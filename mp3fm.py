#!/usr/bin/env python3
"""
MP3FM - Sony Network Walkman (NW-E4xx/NW-HD) MP3 File Manager
Reverse-engineered replacement for Sony's MP3FileManager.exe

Transfers MP3/FLAC/audio files to Sony OMGAUDIO-based players.
Handles FLAC→MP3 conversion, OMA container creation, XOR encryption,
and full OMGAUDIO database generation.

Based on RE of: FrankPACAPI.dll, waider.ie FILE_FORMAT_v2, rustystage,
FU-NW-HD5, JSymphonic, FFmpeg OMA implementation.
"""

import argparse
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import mutagen
    from mutagen.flac import FLAC
    from mutagen.mp3 import MP3
    from mutagen.id3 import ID3, TIT2, TPE1, TALB, TCON, TRCK
except ImportError:
    print("Error: mutagen is required. Install with: pip install mutagen")
    sys.exit(1)


# =============================================================================
# Constants
# =============================================================================

OMGAUDIO_DIR = "OMGAUDIO"
OMA_DIR_FMT = "10F{:02X}"
OMA_FILE_FMT = "1000{:04X}.OMA"

# EA3 tag header: "ea3" + version 0x03 + revision 0x00 + flags 0x00
EA3_TAG_MAGIC = b"ea3\x03\x00\x00"
EA3_TAG_TOTAL_SIZE = 0x0C00  # 3072 bytes for tag section

# EA3 audio header (96 bytes)
EA3_AUDIO_MAGIC = b"EA3"
EA3_AUDIO_HEADER_SIZE = 96

# OMA codec IDs (from FFmpeg oma.h)
OMA_CODECID_ATRAC3 = 0
OMA_CODECID_ATRAC3P = 1
OMA_CODECID_AAC = 2
OMA_CODECID_MP3 = 3
OMA_CODECID_LPCM = 4
OMA_CODECID_WMA = 5

# Encryption marker for MP3 (non-DRM XOR scrambling)
ENC_ID_NONE = 0x0000
ENC_ID_MP3_XOR = 0xFFFE

# MP3 bitrate/samplerate tables for EA3 codec_params construction
MP3_BITRATES_L3 = {
    # MPEG1 Layer 3
    32: 0x01, 40: 0x02, 48: 0x03, 56: 0x04, 64: 0x05,
    80: 0x06, 96: 0x07, 112: 0x08, 128: 0x09, 160: 0x0A,
    192: 0x0B, 224: 0x0C, 256: 0x0D, 320: 0x0E,
}

MP3_SAMPLERATES = {
    44100: 0x00, 48000: 0x01, 32000: 0x02,
    22050: 0x00, 24000: 0x01, 16000: 0x02,
    11025: 0x00, 12000: 0x01, 8000: 0x02,
}


# =============================================================================
# DvID and XOR encryption
# =============================================================================

def read_dvid(dvid_path):
    """Read device ID from DvID.dat, return the 4-byte key at offset 10-13."""
    with open(dvid_path, "rb") as f:
        data = f.read(16)
    if len(data) < 14:
        raise ValueError(f"DvID.dat too short: {len(data)} bytes")
    # Bytes 10-13 (0x0A-0x0D) contain the device-specific key
    return struct.unpack(">I", data[10:14])[0]


def compute_xor_key(track_id, dvid_key):
    """
    Compute XOR encryption key for a track.
    Formula: key = (0x2465 + track_id * 0x5296E435) ^ dvid_key
    Result is a 4-byte big-endian value, applied in 8-byte repeating blocks.
    """
    key = ((0x2465 + track_id * 0x5296E435) & 0xFFFFFFFF) ^ dvid_key
    return struct.pack(">I", key)


def xor_encrypt(data, key_bytes):
    """
    XOR encrypt audio data with 4-byte repeating key.
    Applied in 8-byte blocks (key repeated twice).
    Trailing bytes that don't fill an 8-byte block are left unencrypted.
    """
    key8 = key_bytes * 2  # 4-byte key repeated = 8-byte pattern
    result = bytearray(data)
    full_blocks = len(result) // 8
    for i in range(full_blocks * 8):
        result[i] ^= key8[i % 8]
    return bytes(result)


# =============================================================================
# MP3 parsing helpers
# =============================================================================

def get_mp3_info(mp3_path):
    """Extract metadata and audio properties from an MP3 file."""
    audio = MP3(mp3_path)
    info = {
        "duration_ms": int(audio.info.length * 1000),
        "bitrate": audio.info.bitrate // 1000,  # kbps
        "sample_rate": audio.info.sample_rate,
        "channels": audio.info.channels,
        "title": "",
        "artist": "",
        "album": "",
        "genre": "",
        "track_num": 0,
    }

    tags = audio.tags
    if tags:
        for key, attr in [("TIT2", "title"), ("TPE1", "artist"),
                          ("TALB", "album"), ("TCON", "genre")]:
            frame = tags.get(key)
            if frame:
                info[attr] = str(frame)
        trck = tags.get("TRCK")
        if trck:
            try:
                info["track_num"] = int(str(trck).split("/")[0])
            except ValueError:
                pass

    # Fallback: use filename as title
    if not info["title"]:
        info["title"] = Path(mp3_path).stem

    return info


def get_mp3_raw_audio(mp3_path):
    """Read raw MP3 audio data (everything after ID3 tags)."""
    with open(mp3_path, "rb") as f:
        data = f.read()

    # Skip ID3v2 tag if present
    if data[:3] == b"ID3":
        # ID3v2 header: 10 bytes, size is syncsafe integer at bytes 6-9
        size = (
            (data[6] & 0x7F) << 21 |
            (data[7] & 0x7F) << 14 |
            (data[8] & 0x7F) << 7 |
            (data[9] & 0x7F)
        )
        offset = 10 + size
        # Check for footer flag (bit 4 of flags byte 5)
        if data[5] & 0x10:
            offset += 10
        return data[offset:]

    return data


# =============================================================================
# EA3/OMA file creation
# =============================================================================

def encode_id3_text_frame(frame_id, text, encoding=3):
    """
    Encode an ID3v2.3 text frame.
    encoding: 0=latin1, 1=utf16, 2=utf16be, 3=utf8
    """
    frame_id_bytes = frame_id.encode("ascii")
    if encoding == 3:
        text_bytes = b"\x03" + text.encode("utf-8")
    elif encoding == 1:
        text_bytes = b"\x01\xff\xfe" + text.encode("utf-16-le")
    elif encoding == 0:
        text_bytes = b"\x00" + text.encode("latin-1", errors="replace")
    else:
        text_bytes = b"\x02" + text.encode("utf-16-be")

    size = len(text_bytes)
    # ID3v2.3 frame: 4-byte ID + 4-byte size (big-endian, NOT syncsafe) + 2-byte flags
    return frame_id_bytes + struct.pack(">I", size) + b"\x00\x00" + text_bytes


def encode_txxx_frame(description, value, encoding=3):
    """Encode a TXXX (user-defined text) ID3v2 frame."""
    if encoding == 3:
        payload = b"\x03" + description.encode("utf-8") + b"\x00" + value.encode("utf-8")
    else:
        payload = b"\x01\xff\xfe" + description.encode("utf-16-le") + b"\x00\x00" + value.encode("utf-16-le")
    size = len(payload)
    return b"TXXX" + struct.pack(">I", size) + b"\x00\x00" + payload


def build_ea3_tag(info, track_id):
    """
    Build the EA3 tag section (ID3v2-compatible, 3072 bytes).
    Starts with "ea3\x03\x00" instead of "ID3\x03\x00".
    """
    # Build frames
    frames = b""
    if info["title"]:
        frames += encode_id3_text_frame("TIT2", info["title"])
    if info["artist"]:
        frames += encode_id3_text_frame("TPE1", info["artist"])
    if info["album"]:
        frames += encode_id3_text_frame("TALB", info["album"])
    if info["genre"]:
        frames += encode_id3_text_frame("TCON", info["genre"])
    if info["track_num"]:
        frames += encode_id3_text_frame("TRCK", str(info["track_num"]))

    # Sony-specific TXXX frames
    frames += encode_txxx_frame("OMG_TRACK", f"{track_id}")
    frames += encode_txxx_frame("OMG_TRLDA", "2005/01/01 00:00:00")

    # EA3 tag header (10 bytes): magic + syncsafe size
    # The size field covers everything after the 10-byte header
    content_size = EA3_TAG_TOTAL_SIZE - 10
    # Encode as syncsafe integer
    ss = (
        ((content_size & 0x0FE00000) << 3) |
        ((content_size & 0x001FC000) << 2) |
        ((content_size & 0x00003F80) << 1) |
        (content_size & 0x0000007F)
    )
    header = EA3_TAG_MAGIC + struct.pack(">I", ss)  # 6 + 4 = 10 bytes

    tag = header + frames
    # Pad to exactly EA3_TAG_TOTAL_SIZE
    tag = tag.ljust(EA3_TAG_TOTAL_SIZE, b"\x00")
    return tag[:EA3_TAG_TOTAL_SIZE]


def build_ea3_audio_header(info, track_id):
    """
    Build the 96-byte EA3 audio header that follows the tag section.
    """
    header = bytearray(EA3_AUDIO_HEADER_SIZE)

    # Bytes 0-2: "EA3"
    header[0:3] = EA3_AUDIO_MAGIC
    # Byte 3: version (0x02)
    header[3] = 0x02
    # Byte 4: 0x00
    header[4] = 0x00
    # Byte 5: header size indicator (0x60 = 96)
    header[5] = 0x60

    # Bytes 6-7: Encryption ID (0xFFFE = XOR scrambled MP3)
    struct.pack_into(">H", header, 6, ENC_ID_MP3_XOR)

    # Bytes 8-31: padding/reserved (zeros)

    # Byte 32: Codec ID (3 = MP3)
    header[32] = OMA_CODECID_MP3

    # Bytes 33-35: Codec parameters (24-bit)
    # For MP3: encode bitrate, samplerate, channels
    # Based on FU-NW-HD5: 0x90DE10 for 128kbps/44100Hz
    # Format: bitrate_index(8) | samplerate_flags(8) | channel_flags(8)
    bitrate = info.get("bitrate", 128)
    sample_rate = info.get("sample_rate", 44100)

    # Compute codec params: CBR/VBR(1B) + version|layer|bitrateIdx(1B) + channels(1B)
    # MPEG versions: 1=MPEG1(3), layer: III=1, bitrate index from table
    br_idx = MP3_BITRATES_L3.get(bitrate, 0x09)  # default 128kbps index
    # byte2: (mpeg_version << 6) | (layer << 4) | bitrate_index
    codec_byte2 = (3 << 6) | (1 << 4) | br_idx  # MPEG1, Layer III
    channels = info.get("channels", 2)
    codec_byte3 = 0x10 if channels >= 2 else 0x30  # stereo vs mono
    header[33:36] = bytes([0x80, codec_byte2, codec_byte3])  # 0x80 = CBR

    return bytes(header)


def create_oma_file(mp3_path, oma_path, track_id, dvid_key, info=None):
    """
    Create an OMA file from an MP3 file.
    Structure: EA3 tag (3072B) + EA3 audio header (96B) + XOR-encrypted MP3 data
    """
    if info is None:
        info = get_mp3_info(mp3_path)

    # Build headers
    ea3_tag = build_ea3_tag(info, track_id)
    ea3_audio = build_ea3_audio_header(info, track_id)

    # Read raw MP3 audio data
    mp3_data = get_mp3_raw_audio(mp3_path)

    # XOR encrypt
    key = compute_xor_key(track_id, dvid_key)
    encrypted = xor_encrypt(mp3_data, key)

    # Write OMA file
    os.makedirs(os.path.dirname(oma_path), exist_ok=True)
    with open(oma_path, "wb") as f:
        f.write(ea3_tag)
        f.write(ea3_audio)
        f.write(encrypted)

    return len(mp3_data)


# =============================================================================
# OMGAUDIO Database Writers (Big-Endian throughout)
# =============================================================================

def write_table_header(f, magic, class_count):
    """Write 16-byte table header: magic(4) + 0x01010000(4) + count(1) + pad(7)"""
    f.write(magic)
    f.write(b"\x01\x01\x00\x00")
    f.write(struct.pack("B", class_count))
    f.write(b"\x00" * 7)


def write_class_desc(f, magic, offset, length):
    """Write 16-byte class descriptor: magic(4) + offset(4) + length(4) + pad(4)"""
    f.write(magic)
    f.write(struct.pack(">I", offset))
    f.write(struct.pack(">I", length))
    f.write(b"\x00" * 4)


def write_class_header(f, magic, element_count, element_size,
                       complement1=0, complement2=0):
    """Write 16-byte class header: magic(4) + count(2) + size(2) + comp1(4) + comp2(4)"""
    f.write(magic)
    f.write(struct.pack(">H", element_count))
    f.write(struct.pack(">H", element_size))
    f.write(struct.pack(">I", complement1))
    f.write(struct.pack(">I", complement2))


def write_tag_field(buf, offset, tag_name, encoding, text, field_size=0x80):
    """
    Write a tag field into a buffer at given offset.
    Format: tag(4B) + 0x00(1B) + encoding(1B) + UTF-16BE text + zero padding
    Total: field_size bytes
    """
    tag_bytes = tag_name.encode("ascii")
    buf[offset:offset + 4] = tag_bytes

    # Encoding: {0x00, 0x02} for UTF-16BE (confirmed by JSymphonic + device dumps)
    buf[offset + 4] = 0x00
    buf[offset + 5] = encoding

    if text and encoding == 0x02:
        text_encoded = text.encode("utf-16-be")
        max_text = field_size - 6
        text_encoded = text_encoded[:max_text]
        buf[offset + 6:offset + 6 + len(text_encoded)] = text_encoded


def write_04cntinf(filepath, tracks):
    """
    Write 04CNTINF.DAT - Content Information.
    Each track gets a CNFB element of 0x290 (656) bytes.
    Element structure:
      [0x00-0x01] 0x0000
      [0x02-0x03] protection: 0xFFFE (XOR encrypted MP3)
      [0x04-0x07] file_properties (codec info)
      [0x08-0x0B] title_key (duration_ms as checksum)
      [0x0C-0x0D] tag_count (number of tag fields)
      [0x0E-0x0F] tag_field_size (0x0080 = 128 bytes)
      [0x10-0x28F] tag data (5 x 128-byte tag fields: TIT2, TPE1, TALB, TCON, TSOP)
    """
    n = len(tracks)
    elem_size = 0x290

    # Calculate layout (class header is 16 bytes: magic+count+size+comp1+comp2)
    header_size = 16  # table header
    desc_size = 16    # 1 class descriptor
    class_header_size = 16
    data_size = class_header_size + n * elem_size
    class_offset = header_size + desc_size
    class_length = data_size

    with open(filepath, "wb") as f:
        write_table_header(f, b"CNIF", 1)
        write_class_desc(f, b"CNFB", class_offset, class_length)
        write_class_header(f, b"CNFB", n, elem_size)

        for track in tracks:
            elem = bytearray(elem_size)

            # Bytes 0-1: zeros
            # Bytes 2-3: protection (0xFFFE = MP3 XOR)
            struct.pack_into(">H", elem, 2, 0xFFFE)

            # Bytes 4-7: file properties / codec info
            # Format: codec(1B) + CBR/VBR(1B) + ver|layer|brIdx(1B) + channels(1B)
            bitrate_kbps = track.get("bitrate", 128)
            br_idx = MP3_BITRATES_L3.get(bitrate_kbps, 0x09)
            codec_byte2 = (3 << 6) | (1 << 4) | br_idx  # MPEG1, Layer III
            ch = track.get("channels", 2)
            codec_byte3 = 0x10 if ch >= 2 else 0x30
            elem[4] = OMA_CODECID_MP3
            elem[5:8] = bytes([0x80, codec_byte2, codec_byte3])

            # Bytes 8-11: duration in ms (used as title_key / checksum)
            struct.pack_into(">I", elem, 8, track["duration_ms"])

            # Bytes 12-13: number of tag fields
            struct.pack_into(">H", elem, 12, 5)

            # Bytes 14-15: tag field size (0x80 = 128)
            struct.pack_into(">H", elem, 14, 0x80)

            # Tag fields starting at offset 0x10, each 0x80 (128) bytes
            tag_offset = 0x10
            write_tag_field(elem, tag_offset + 0 * 0x80, "TIT2", 0x02, track.get("title", ""))
            write_tag_field(elem, tag_offset + 1 * 0x80, "TPE1", 0x02, track.get("artist", ""))
            write_tag_field(elem, tag_offset + 2 * 0x80, "TALB", 0x02, track.get("album", ""))
            write_tag_field(elem, tag_offset + 3 * 0x80, "TCON", 0x02, track.get("genre", ""))
            write_tag_field(elem, tag_offset + 4 * 0x80, "TSOP", 0x02, track.get("artist", ""))

            f.write(elem)


def write_03ginf01(filepath, tracks):
    """
    Write 03GINF01.DAT - Group Information (upload order view).
    One group per album. Element size 0x310 (784 bytes).
    Header: magic_key(8B) + album_key(4B) + tag_count_and_size(4B)
    Then 6 x 128-byte tag fields: TIT2, TPE1, TCON, TSOP, PICP, PIC0
    """
    # Group tracks by album
    albums = {}
    for t in tracks:
        album = t.get("album", "Unknown Album")
        if album not in albums:
            albums[album] = {
                "artist": t.get("artist", ""),
                "genre": t.get("genre", ""),
                "total_duration": 0,
                "track_ids": [],
            }
        albums[album]["total_duration"] += t["duration_ms"]
        albums[album]["track_ids"].append(t["track_id"])

    album_list = list(albums.items())
    n = len(album_list)
    elem_size = 0x310

    header_size = 16
    desc_size = 16
    class_header_size = 16
    class_offset = header_size + desc_size
    class_length = class_header_size + n * elem_size

    with open(filepath, "wb") as f:
        write_table_header(f, b"GPIF", 1)
        write_class_desc(f, b"GPFB", class_offset, class_length)
        write_class_header(f, b"GPFB", n, elem_size)

        for album_name, album_info in album_list:
            elem = bytearray(elem_size)

            # Bytes 0-7: magic key (zeros for now)
            # Bytes 8-11: album_key (sum of durations)
            struct.pack_into(">I", elem, 8, album_info["total_duration"])

            # Bytes 12-15: tag count (6) + tag size (0x80)
            struct.pack_into(">H", elem, 12, 6)
            struct.pack_into(">H", elem, 14, 0x80)

            # 6 tag fields at offset 0x10
            tag_offset = 0x10
            write_tag_field(elem, tag_offset + 0 * 0x80, "TIT2", 0x02, album_name)
            write_tag_field(elem, tag_offset + 1 * 0x80, "TPE1", 0x02, album_info["artist"])
            write_tag_field(elem, tag_offset + 2 * 0x80, "TCON", 0x02, album_info["genre"])
            write_tag_field(elem, tag_offset + 3 * 0x80, "TSOP", 0x02, album_info["artist"])
            write_tag_field(elem, tag_offset + 4 * 0x80, "PICP", 0x02, "")
            write_tag_field(elem, tag_offset + 5 * 0x80, "PIC0", 0x02, "")

            f.write(elem)

    return album_list


def write_03ginf_simple(filepath, items, elem_size=0x90):
    """
    Write 03GINF02/03/04.DAT - Simple group info (artists/albums/genres).
    Each element has 1 TIT2 tag field of 128 bytes.
    """
    n = len(items)

    header_size = 16
    desc_size = 16
    class_header_size = 16
    class_offset = header_size + desc_size
    class_length = class_header_size + n * elem_size

    with open(filepath, "wb") as f:
        write_table_header(f, b"GPIF", 1)
        write_class_desc(f, b"GPFB", class_offset, class_length)
        write_class_header(f, b"GPFB", n, elem_size)

        for item_name in items:
            elem = bytearray(elem_size)
            # Simple element: just tag count(2B) + tag size(2B) + TIT2 field
            struct.pack_into(">H", elem, 12, 1)
            struct.pack_into(">H", elem, 14, 0x80)
            write_tag_field(elem, 0x10, "TIT2", 0x02, item_name)
            f.write(elem)


def write_01tree(filepath, groups, tracks_per_group):
    """
    Write 01TREExx.DAT - Tree structure.
    GPLB: group entries (8 bytes each): item_id(2B) + flag(2B) + title_id(2B) + 0x0000(2B)
    TPLB: track ID entries (2 bytes each)
    """
    gplb_elem_size = 8
    tplb_elem_size = 2

    # Build GPLB entries
    gplb_entries = []
    tplb_entries = []
    tplb_offset = 0

    for group_idx, track_ids in enumerate(tracks_per_group):
        # GPLB entry: group_id, flag 0x0100 (has children), first_tplb_index, 0x0000
        gplb_entries.append(struct.pack(">HHHH",
            group_idx + 1,  # group ID (1-based)
            0x0100,         # flag: has children
            tplb_offset + 1,  # pointer into TPLB (1-based)
            0x0000
        ))
        for tid in track_ids:
            tplb_entries.append(struct.pack(">H", tid))
        tplb_offset += len(track_ids)

    n_gplb = len(gplb_entries)
    n_tplb = len(tplb_entries)

    # Class headers are 16 bytes (with complement fields)
    gplb_data_size = 16 + n_gplb * gplb_elem_size  # 16B header + data
    tplb_data_size = 16 + n_tplb * tplb_elem_size

    header_size = 16
    desc_size = 16 * 2  # 2 class descriptors
    gplb_offset = header_size + desc_size
    tplb_offset_file = gplb_offset + gplb_data_size

    with open(filepath, "wb") as f:
        write_table_header(f, b"TREE", 2)
        write_class_desc(f, b"GPLB", gplb_offset, gplb_data_size)
        write_class_desc(f, b"TPLB", tplb_offset_file, tplb_data_size)

        # GPLB class (complement1 = numberOfGroups per JSymphonic)
        write_class_header(f, b"GPLB", n_gplb, gplb_elem_size,
                           complement1=n_gplb)
        for entry in gplb_entries:
            f.write(entry)

        # TPLB class (complement1 = totalTitleCount per JSymphonic)
        write_class_header(f, b"TPLB", n_tplb, tplb_elem_size,
                           complement1=n_tplb)
        for entry in tplb_entries:
            f.write(entry)


def write_01tree_flat(filepath, track_ids):
    """Write a flat tree (all tracks in one implicit group) for sorted views."""
    n = len(track_ids)
    gplb_elem_size = 8
    tplb_elem_size = 2

    gplb_data_size = 16 + 1 * gplb_elem_size  # 16B header + 1 group
    tplb_data_size = 16 + n * tplb_elem_size

    header_size = 16
    desc_size = 32
    gplb_offset = header_size + desc_size
    tplb_offset = gplb_offset + gplb_data_size

    with open(filepath, "wb") as f:
        write_table_header(f, b"TREE", 2)
        write_class_desc(f, b"GPLB", gplb_offset, gplb_data_size)
        write_class_desc(f, b"TPLB", tplb_offset, tplb_data_size)

        # Single group pointing to all tracks
        write_class_header(f, b"GPLB", 1, gplb_elem_size, complement1=1)
        f.write(struct.pack(">HHHH", 1, 0x0100, 1, 0x0000))

        # All track IDs
        write_class_header(f, b"TPLB", n, tplb_elem_size, complement1=n)
        for tid in track_ids:
            f.write(struct.pack(">H", tid))


def write_01tree_empty(filepath):
    """Write an empty tree file."""
    with open(filepath, "wb") as f:
        write_table_header(f, b"TREE", 2)
        write_class_desc(f, b"GPLB", 0x30, 0x10)
        write_class_desc(f, b"TPLB", 0x40, 0x10)
        # 16-byte headers with 0 elements = exactly 0x10 bytes each
        write_class_header(f, b"GPLB", 0, 8)
        write_class_header(f, b"TPLB", 0, 2)


def write_02treinf(filepath, tracks):
    """
    Write 02TREINF.DAT - Tree Information.
    GTFB class with element size 0x90 (144 bytes).
    Pre-allocated for 0x2D (45) elements as per device template.
    """
    n_prealloc = max(1, len(tracks))
    elem_size = 0x90

    header_size = 16
    desc_size = 16
    class_header_size = 16
    # Match device: GTFB at 0x20, length 0x2410
    data_length = 0x2410
    class_offset = header_size + desc_size

    with open(filepath, "wb") as f:
        write_table_header(f, b"GTIF", 1)
        write_class_desc(f, b"GTFB", class_offset, data_length)
        write_class_header(f, b"GTFB", n_prealloc, elem_size)

        # Global key element: sum of all title_keys (durations)
        global_key = sum(t["duration_ms"] for t in tracks)
        elem = bytearray(elem_size)
        # Bytes 12-15: tag info (0x0001 0080 = 1 tag of 128 bytes)
        struct.pack_into(">H", elem, 12, 1)
        struct.pack_into(">H", elem, 14, 0x80)
        # TIT2 tag at offset 0x10
        write_tag_field(elem, 0x10, "TIT2", 0x02, "")
        f.write(elem)

        # Pad remaining to match expected length
        remaining = data_length - class_header_size - elem_size
        if remaining > 0:
            f.write(b"\x00" * remaining)


def write_00gtrlst(filepath, tracks):
    """
    Write 00GTRLST.DAT - Group Tree List (master index).
    SYSB: 1 element of 0x50 (80) bytes - system info
    GTLB: 1 element of 0x50 (80) bytes - tree list references
    """
    elem_size = 0x50

    sysb_offset = 0x30
    sysb_length = 0x70  # header(16) + 1*0x50 + padding(16)
    gtlb_offset = 0xA0
    gtlb_length = 0xB0

    with open(filepath, "wb") as f:
        write_table_header(f, b"GTLT", 2)
        write_class_desc(f, b"SYSB", sysb_offset, sysb_length)
        write_class_desc(f, b"GTLB", gtlb_offset, gtlb_length)

        # SYSB class (complement1=0xC0000000 from device dump)
        write_class_header(f, b"SYSB", 1, elem_size,
                           complement1=0xC0000000)
        sysb_elem = bytearray(elem_size)  # all zeros
        f.write(sysb_elem)
        # Pad to gtlb_offset
        pad = gtlb_offset - (sysb_offset + 16 + elem_size)
        if pad > 0:
            f.write(b"\x00" * pad)

        # GTLB class (complement1=1 = number of tree/ginf pairs)
        write_class_header(f, b"GTLB", 1, elem_size,
                           complement1=1)
        gtlb_elem = bytearray(elem_size)
        # GTLB element: fileRef=1, unknown1=1 at offset 0, rest zeros
        struct.pack_into(">HH", gtlb_elem, 0, 1, 1)  # fileRef=1, unknown1=1
        f.write(gtlb_elem)
        # Pad to match original file size (336 bytes)
        current = gtlb_offset + 16 + elem_size
        target = 336
        if current < target:
            f.write(b"\x00" * (target - current))


def write_05cidlst(filepath, tracks):
    """
    Write 05CIDLST.DAT - Content ID List.
    CILB elements of 0x30 (48) bytes each.
    """
    n = len(tracks)
    elem_size = 0x30

    header_size = 16
    desc_size = 16
    class_header_size = 16
    class_offset = header_size + desc_size
    class_length = class_header_size + n * elem_size

    with open(filepath, "wb") as f:
        write_table_header(f, b"CIDL", 1)
        write_class_desc(f, b"CILB", class_offset, class_length)
        write_class_header(f, b"CILB", n, elem_size)

        for i, track in enumerate(tracks):
            elem = bytearray(elem_size)
            # Minimal CID entry - mostly zeros for non-DRM content
            struct.pack_into(">H", elem, 0, track["track_id"])
            f.write(elem)


# =============================================================================
# FLAC to MP3 conversion
# =============================================================================

def convert_to_mp3(input_path, output_path, bitrate=128):
    """Convert any audio file to MP3 using ffmpeg."""
    cmd = [
        "ffmpeg", "-y", "-i", str(input_path),
        "-codec:a", "libmp3lame",
        "-b:a", f"{bitrate}k",
        "-ar", "44100",
        "-ac", "2",
        "-map_metadata", "0",
        "-id3v2_version", "3",
        str(output_path)
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ffmpeg failed: {result.stderr[:500]}")
    return output_path


# =============================================================================
# Main transfer logic
# =============================================================================

def find_next_track_id(omgaudio_path):
    """Find the next available track ID by scanning existing OMA files."""
    max_id = 0
    for d in range(256):
        dir_path = os.path.join(omgaudio_path, OMA_DIR_FMT.format(d))
        if not os.path.isdir(dir_path):
            continue
        for fname in os.listdir(dir_path):
            if fname.upper().endswith(".OMA") and fname.upper().startswith("1000"):
                try:
                    file_id = int(fname[4:8], 16)
                    max_id = max(max_id, file_id)
                except ValueError:
                    pass
    return max_id + 1


def transfer_files(device_path, input_paths, bitrate=128):
    """
    Transfer audio files to the Sony Walkman.

    Args:
        device_path: Mount point of the Walkman (e.g. /mnt/walkman)
        input_paths: List of audio file paths (MP3, FLAC, etc.)
        bitrate: MP3 encoding bitrate in kbps
    """
    omgaudio = os.path.join(device_path, OMGAUDIO_DIR)
    dvid_path = os.path.join(device_path, "MP3FM", "DvID.dat")
    backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "device_backup", "OMGAUDIO")

    if not os.path.isdir(omgaudio):
        print(f"Error: OMGAUDIO directory not found at {omgaudio}")
        sys.exit(1)

    if not os.path.isfile(dvid_path):
        print(f"Error: DvID.dat not found at {dvid_path}")
        sys.exit(1)

    # Read device key
    dvid_key = read_dvid(dvid_path)
    print(f"Device key: 0x{dvid_key:08X}")

    # Clean existing OMA files for fresh transfer
    cleaned = 0
    for d in range(256):
        dir_path = os.path.join(omgaudio, OMA_DIR_FMT.format(d))
        if not os.path.isdir(dir_path):
            continue
        for fname in os.listdir(dir_path):
            if fname.upper().endswith(".OMA"):
                os.remove(os.path.join(dir_path, fname))
                cleaned += 1
    if cleaned:
        print(f"Cleaned {cleaned} existing OMA files.")

    # Start track IDs from 1 (clean transfer)
    next_id = 1
    print(f"Starting track ID: {next_id}")

    # Collect and process files
    audio_files = []
    for p in input_paths:
        p = Path(p)
        if p.is_dir():
            # Collect all audio files from directory, sorted
            for ext in ["*.flac", "*.mp3", "*.wav", "*.ogg", "*.m4a", "*.aac"]:
                audio_files.extend(sorted(p.glob(ext)))
        elif p.is_file():
            audio_files.append(p)

    if not audio_files:
        print("No audio files found.")
        sys.exit(1)

    print(f"\nFound {len(audio_files)} audio files to transfer.\n")

    tracks = []
    tmp_dir = tempfile.mkdtemp(prefix="mp3fm_")

    try:
        for idx, audio_file in enumerate(audio_files):
            track_id = next_id + idx
            folder_num = track_id // 256
            oma_dir = os.path.join(omgaudio, OMA_DIR_FMT.format(folder_num))
            oma_path = os.path.join(oma_dir, OMA_FILE_FMT.format(track_id))

            print(f"[{idx + 1}/{len(audio_files)}] {audio_file.name}")

            # Convert to MP3 if needed
            suffix = audio_file.suffix.lower()
            if suffix == ".mp3":
                mp3_path = str(audio_file)
            else:
                print(f"  Converting {suffix} → MP3 ({bitrate}kbps)...")
                mp3_path = os.path.join(tmp_dir, f"track_{track_id:04x}.mp3")
                convert_to_mp3(audio_file, mp3_path, bitrate)

            # Read MP3 metadata
            info = get_mp3_info(mp3_path)
            info["track_id"] = track_id
            info["track_num"] = info["track_num"] or (idx + 1)

            print(f"  → {info['title']} | {info['artist']} | {info['album']}")
            print(f"  Duration: {info['duration_ms'] // 1000}s | "
                  f"Bitrate: {info['bitrate']}kbps | "
                  f"OMA: {OMA_DIR_FMT.format(folder_num)}/{OMA_FILE_FMT.format(track_id)}")

            # Create OMA file
            audio_size = create_oma_file(mp3_path, oma_path, track_id, dvid_key, info)
            print(f"  Written: {os.path.getsize(oma_path)} bytes "
                  f"(audio: {audio_size} bytes, encrypted)")

            tracks.append(info)

        # Write database files
        print(f"\nWriting OMGAUDIO database ({len(tracks)} tracks)...")

        # Step 1: Restore non-critical DATs from backup (exact binary match)
        import shutil as _shutil
        restore_from_backup = [
            "02TREINF.DAT",
            "01TREE02.DAT", "01TREE03.DAT", "01TREE04.DAT",
            "03GINF02.DAT", "03GINF03.DAT", "03GINF04.DAT",
        ]
        if os.path.isdir(backup_dir):
            for fname in restore_from_backup:
                src = os.path.join(backup_dir, fname)
                dst = os.path.join(omgaudio, fname)
                if os.path.isfile(src):
                    _shutil.copy2(src, dst)
        else:
            # Write empty files from scratch if no backup
            for i in range(2, 5):
                write_01tree_empty(os.path.join(omgaudio, f"01TREE0{i}.DAT"))
            for i in range(2, 5):
                write_03ginf_simple(os.path.join(omgaudio, f"03GINF0{i}.DAT"), [])
            write_02treinf(os.path.join(omgaudio, "02TREINF.DAT"), tracks)

        # Step 2: Group tracks by album for tree structure
        albums_ordered = {}
        for t in tracks:
            album = t.get("album", "Unknown Album")
            if album not in albums_ordered:
                albums_ordered[album] = []
            albums_ordered[album].append(t["track_id"])
        tracks_per_group = list(albums_ordered.values())

        # Step 3: Write critical database files
        write_00gtrlst(os.path.join(omgaudio, "00GTRLST.DAT"), tracks)
        print("  00GTRLST.DAT ✓")

        write_01tree(os.path.join(omgaudio, "01TREE01.DAT"),
                     tracks_per_group, tracks_per_group)
        print(f"  01TREE01.DAT ✓ ({len(tracks_per_group)} groups, "
              f"{sum(len(g) for g in tracks_per_group)} tracks)")

        write_03ginf01(os.path.join(omgaudio, "03GINF01.DAT"), tracks)
        print("  03GINF01.DAT ✓")

        write_04cntinf(os.path.join(omgaudio, "04CNTINF.DAT"), tracks)
        print("  04CNTINF.DAT ✓")

        write_05cidlst(os.path.join(omgaudio, "05CIDLST.DAT"), tracks)
        print("  05CIDLST.DAT ✓")

        # Sync filesystem
        print("\nSyncing filesystem...")
        subprocess.run(["sync"], check=True)

        print(f"\nDone! Transferred {len(tracks)} tracks to {device_path}")
        print("You can now safely eject the device.")

    finally:
        # Cleanup temp files
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="MP3FM - Transfer music to Sony Network Walkman (NW-E4xx/NW-HD)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /mnt/walkman ~/Music/album/
  %(prog)s /mnt/walkman track1.mp3 track2.flac
  %(prog)s -b 192 /mnt/walkman ~/Music/

Supports: MP3, FLAC, WAV, OGG, M4A, AAC (non-MP3 converted via ffmpeg)
        """
    )
    parser.add_argument("device", help="Walkman mount point (e.g. /mnt/walkman)")
    parser.add_argument("files", nargs="+", help="Audio files or directories to transfer")
    parser.add_argument("-b", "--bitrate", type=int, default=128,
                        help="MP3 encoding bitrate in kbps (default: 128)")

    args = parser.parse_args()
    transfer_files(args.device, args.files, args.bitrate)


if __name__ == "__main__":
    main()
