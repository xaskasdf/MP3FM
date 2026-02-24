# OMGAUDIO Format Specification

Reverse-engineered documentation of the OMGAUDIO database format and OMA
audio container used by Sony Network Walkman players (NW-E4xx, NW-HD series).

This is **clean-room documentation** based on binary analysis of device dumps
and informed by open-source references: JSymphonic, FU-NW-HD5, rustystage,
and the FFmpeg OMA decoder (`libavformat/oma.c`).  No Sony copyrighted
material is reproduced here.

---

## Table of Contents

1. [OMA Audio Container](#1-oma-audio-container)
   - [EA3 Tag Header](#11-ea3-tag-header-3072-bytes)
   - [EA3 Audio Header](#12-ea3-audio-header-96-bytes)
   - [XOR Encryption](#13-xor-encryption)
   - [File Naming Convention](#14-file-naming-convention)
2. [OMGAUDIO Database Structure](#2-omgaudio-database-structure)
   - [Universal File Layout](#21-universal-file-layout)
   - [Table Header](#22-table-header-16-bytes)
   - [Class Descriptor](#23-class-descriptor-16-bytes)
   - [Class Header](#24-class-header-16-bytes)
   - [Tag Field Format](#25-tag-field-format)
3. [Database Files](#3-database-files)
   - [00GTRLST.DAT -- Master Index](#31-00gtrlstdat----master-index)
   - [01TREExx.DAT -- Tree Structure](#32-01treexxdat----tree-structure)
   - [02TREINF.DAT -- Tree Information](#33-02treinfdat----tree-information)
   - [03GINFxx.DAT -- Group Information](#34-03ginfxxdat----group-information)
   - [04CNTINF.DAT -- Track Content Info](#35-04cntinfdat----track-content-info)
   - [05CIDLST.DAT -- Content ID List](#36-05cidlstdat----content-id-list)
4. [DvID.dat -- Device Identity](#4-dviddat----device-identity)
5. [Cross-Reference Chain](#5-cross-reference-chain)
6. [MP3 Codec Parameters Encoding](#6-mp3-codec-parameters-encoding)

---

## 1. OMA Audio Container

Each audio track is stored as a `.OMA` file consisting of three consecutive
sections:

```
+---------------------------+  offset 0x0000
|  EA3 Tag Header (3072 B)  |
+---------------------------+  offset 0x0C00
|  EA3 Audio Header (96 B)  |
+---------------------------+  offset 0x0C60
|  XOR-Encrypted Audio Data  |
|  (variable length)         |
+---------------------------+
```

Total header overhead: **3168 bytes** (0x0C60) before audio data begins.


### 1.1 EA3 Tag Header (3072 bytes)

The EA3 tag is an ID3v2-compatible structure.  It uses `ea3` as its magic
instead of `ID3`, but the framing is otherwise identical to ID3v2.3.

#### Header (10 bytes)

```
Offset  Size  Description
------  ----  -----------
0x00    3     Magic: "ea3" (0x65 0x61 0x33)
0x03    1     Version: 0x03 (maps to ID3v2.3)
0x04    1     Revision: 0x00
0x05    1     Flags: 0x00
0x06    4     Size: syncsafe integer (total size minus 10-byte header)
```

The **syncsafe integer** encoding uses 7 bits per byte (bit 7 always 0):

```
value = (byte[0] & 0x7F) << 21
      | (byte[1] & 0x7F) << 14
      | (byte[2] & 0x7F) << 7
      | (byte[3] & 0x7F)
```

For the standard 3072-byte EA3 tag, the content size is 3062 (0x0BF6).
Encoded as syncsafe: `0x00 0x17 0x76` at bytes 0x07-0x09 (with leading
zero at 0x06).

Observed on device:

```
00000000: 65 61 33 03 00 00 00 00 17 76   ea3......v
```

#### Frames

After the 10-byte header, standard ID3v2.3 text frames follow:

| Frame ID | Purpose           | Encoding |
|----------|-------------------|----------|
| `TIT2`   | Track title       | UTF-8 (0x03) |
| `TPE1`   | Artist            | UTF-8 (0x03) |
| `TALB`   | Album             | UTF-8 (0x03) |
| `TCON`   | Genre             | UTF-8 (0x03) |
| `TRCK`   | Track number      | UTF-8 (0x03) |
| `TXXX`   | `OMG_TRACK` -- track ID string | UTF-8 (0x03) |
| `TXXX`   | `OMG_TRLDA` -- transfer date/time | UTF-8 (0x03) |

Each text frame has the standard ID3v2.3 layout:

```
Offset  Size  Description
------  ----  -----------
0x00    4     Frame ID (ASCII, e.g. "TIT2")
0x04    4     Frame data size (big-endian, NOT syncsafe in ID3v2.3)
0x08    2     Frame flags (0x0000)
0x0A    1     Text encoding byte (0x03 = UTF-8)
0x0B    var   Text content (null-terminated)
```

The remaining bytes up to offset 0x0C00 are zero-padded.


### 1.2 EA3 Audio Header (96 bytes)

Immediately follows the EA3 tag at file offset **0x0C00**.

```
Offset  Size  Description
------  ----  -----------
0x00    3     Magic: "EA3" (0x45 0x41 0x33)
0x03    1     Version: 0x02
0x04    1     Reserved: 0x00
0x05    1     Header size indicator: 0x60 (= 96 decimal)
0x06    2     Encryption ID (big-endian)
0x08    24    Reserved (zeros)
0x20    1     Codec ID
0x21    3     Codec parameters (24-bit, big-endian)
0x24    60    Reserved (zeros)
```

**Encryption ID values:**

| Value    | Meaning |
|----------|---------|
| `0x0000` | No encryption |
| `0xFFFE` | XOR-scrambled (used for MP3 on NW-E4xx) |
| `0xFFFF` | OpenMG DRM (not used by MP3FM) |

**Codec ID values** (from FFmpeg `oma.h`):

| Value | Codec |
|-------|-------|
| 0     | ATRAC3 |
| 1     | ATRAC3plus |
| 2     | AAC |
| 3     | MP3 |
| 4     | LPCM |
| 5     | WMA |

Observed on device for a 128 kbps MPEG1 Layer III stereo file:

```
00000C00: 45 41 33 02 00 60 FF FE  00 00 00 00 00 00 00 00
00000C10: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00000C20: 03 80 D9 10 00 00 00 00  00 00 00 00 00 00 00 00
          ^  ^^^^^^^
          |  codec params (see Section 6)
          codec ID = 3 (MP3)
```


### 1.3 XOR Encryption

The NW-E4xx players require audio data to be XOR-encrypted.  This is a
lightweight scrambling scheme (not DRM) tied to the device identity.

#### Key Derivation

```
dvid_key   = big-endian uint32 from DvID.dat bytes [0x0A:0x0E]
track_key  = ((0x2465 + track_id * 0x5296E435) & 0xFFFFFFFF) ^ dvid_key
```

Where `track_id` is the 1-based track index (matching the OMA filename).

The result is a **4-byte big-endian value**.

#### Application

The 4-byte key is repeated to form an **8-byte block key** (key concatenated
with itself).  The audio data is XOR'd in 8-byte blocks:

```
for i in range(0, len(audio_data) - 7, 8):
    audio_data[i:i+8] ^= key_8bytes

# Trailing bytes (< 8) are left unencrypted
```

The encryption marker `0xFFFE` at EA3 audio header offset 0x06 signals the
player to decrypt before playback.


### 1.4 File Naming Convention

OMA files are stored under `OMGAUDIO/` in numbered subdirectories:

```
OMGAUDIO/
  10F00/
    10000001.OMA    <-- track_id = 0x0001 (1)
    10000002.OMA    <-- track_id = 0x0002 (2)
    ...
    100000FF.OMA    <-- track_id = 0x00FF (255)
  10F01/
    10000100.OMA    <-- track_id = 0x0100 (256)
    ...
```

**Directory name**: `10F` + 2-digit uppercase hex of `track_id // 256`
(format: `10F%02X`)

**File name**: `1000` + 4-digit uppercase hex of `track_id`
(format: `1000%04X.OMA`)

The first directory is always `10F00`.  A new directory is created every 256
tracks.

---

## 2. OMGAUDIO Database Structure

The OMGAUDIO database consists of **six DAT file types** stored in
`OMGAUDIO/` alongside the audio directories.  All files share a common
hierarchical structure.

**All multi-byte integer values are big-endian throughout the database.**


### 2.1 Universal File Layout

Every DAT file follows this layout:

```
+----------------------------------+  offset 0x00
|  Table Header (16 bytes)         |
+----------------------------------+  offset 0x10
|  Class Descriptor 1 (16 bytes)   |
+----------------------------------+  offset 0x20
|  Class Descriptor 2 (16 bytes)   |  (if class_count > 1)
+----------------------------------+
|  ...                             |
+----------------------------------+
|  Class Section 1                 |
|    Class Header (16 bytes)       |
|    Element 1 (elem_size bytes)   |
|    Element 2 (elem_size bytes)   |
|    ...                           |
+----------------------------------+
|  Class Section 2                 |
|    Class Header (16 bytes)       |
|    Elements...                   |
+----------------------------------+
```


### 2.2 Table Header (16 bytes)

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    4     char[]  Table magic (identifies the file type)
0x04    4     bytes   Version: always 0x01 0x01 0x00 0x00
0x08    1     uint8   Number of class sections in this file
0x09    7     bytes   Reserved (zeros)
```

**Table magic values by file:**

| File | Magic (ASCII) | Magic (hex) |
|------|---------------|-------------|
| 00GTRLST.DAT | `GTLT` | `47 54 4C 54` |
| 01TREExx.DAT | `TREE` | `54 52 45 45` |
| 02TREINF.DAT | `GTIF` | `47 54 49 46` |
| 03GINFxx.DAT | `GPIF` | `47 50 49 46` |
| 04CNTINF.DAT | `CNIF` | `43 4E 49 46` |
| 05CIDLST.DAT | `CIDL` | `43 49 44 4C` |


### 2.3 Class Descriptor (16 bytes)

One descriptor per class section, immediately following the table header.

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    4     char[]  Class magic (matches the class header magic)
0x04    4     uint32  Absolute file offset to the class section
0x08    4     uint32  Length of the class section in bytes (header + all elements)
0x0C    4     bytes   Reserved (zeros)
```


### 2.4 Class Header (16 bytes)

Each class section starts with this header, at the offset specified by its
descriptor.

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    4     char[]  Class magic
0x04    2     uint16  Element count (number of elements in this class)
0x08    2     uint16  Element size (fixed size of each element in bytes)
0x08    4     uint32  Complement 1 (usage varies by class)
0x0C    4     uint32  Complement 2 (usage varies by class; usually 0)
```

**Class magic values:**

| Class  | Magic (hex) | Found in |
|--------|-------------|----------|
| `SYSB` | `53 59 53 42` | 00GTRLST.DAT |
| `GTLB` | `47 54 4C 42` | 00GTRLST.DAT |
| `GPLB` | `47 50 4C 42` | 01TREExx.DAT |
| `TPLB` | `54 50 4C 42` | 01TREExx.DAT |
| `GTFB` | `47 54 46 42` | 02TREINF.DAT |
| `GPFB` | `47 50 46 42` | 03GINFxx.DAT |
| `CNFB` | `43 4E 46 42` | 04CNTINF.DAT |
| `CILB` | `43 49 4C 42` | 05CIDLST.DAT |


### 2.5 Tag Field Format

Several element types contain embedded metadata tag fields.  Each tag field
has a fixed size (typically **128 bytes** / 0x80):

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    4     char[]  Tag name (ASCII, e.g. "TIT2", "TPE1")
0x04    1     uint8   Always 0x00
0x05    1     uint8   Text encoding (0x02 = UTF-16BE)
0x06    var   bytes   Text data (UTF-16BE encoded, zero-padded to fill)
```

The number of tag fields and their size are specified in the element header
(see individual element types below).

Common tag names:

| Tag    | Meaning |
|--------|---------|
| `TIT2` | Title (track title or group name) |
| `TPE1` | Artist / performer |
| `TALB` | Album name |
| `TCON` | Genre / content type |
| `TSOP` | Sort order (performer) |
| `PICP` | Picture path (unused on NW-E4xx) |
| `PIC0` | Picture data (unused on NW-E4xx) |

---

## 3. Database Files


### 3.1 00GTRLST.DAT -- Master Index

The master index file.  Contains system information and references to
tree/group information pairs.

**Table magic**: `GTLT`
**Class count**: 2

**Classes**: `SYSB` + `GTLB`

#### File layout observed on device (336 bytes):

```
Offset  Content
------  -------
0x0000  Table header: "GTLT" 01 01 00 00 02 00 00 00 00 00 00 00
0x0010  SYSB descriptor: offset=0x0030 length=0x0070
0x0020  GTLB descriptor: offset=0x00A0 length=0x00B0
0x0030  SYSB class header + 1 element
0x00A0  GTLB class header + 1 element
```

#### SYSB Element (0x50 = 80 bytes)

System information block.  Mostly zeros on the NW-E4xx.

```
Offset  Size  Description
------  ----  -----------
0x00    80    Reserved / system data (all zeros on observed devices)
```

Class header complement1 = `0xC0000000` (observed constant).

#### GTLB Element (0x50 = 80 bytes)

Each GTLB element references a tree/group info file pair.

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    2     uint16  File reference index (01TREExx / 03GINFxx pair number)
0x02    2     uint16  Unknown flag (observed: 0x0001)
0x04    76    bytes   Reserved (zeros)
```

A `fileRef` of 1 means the player should read `01TREE01.DAT` and
`03GINF01.DAT` as a pair.  Multiple GTLB elements reference additional
tree/ginf pairs (02, 03, 04) for artist, album, and genre views.

Class header complement1 = number of valid tree/group pairs.

Hex dump from device:

```
000000A0: 47 54 4C 42  00 01  00 50  00 00 00 01  00 00 00 00
           GTLB     count=1  sz=80  complement1=1
000000B0: 00 01 00 01  00 00 ...
           ref=1 flag=1
```


### 3.2 01TREExx.DAT -- Tree Structure

Defines the hierarchical grouping of tracks.  The `xx` suffix matches the
GTLB file reference (01 = upload order, 02-04 = artist/album/genre views).

**Table magic**: `TREE`
**Class count**: 2

**Classes**: `GPLB` + `TPLB`

#### GPLB Element (8 bytes) -- Group Entry

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    2     uint16  Group ID (1-based, references 03GINFxx element index)
0x02    2     uint16  Flags (0x0100 = group has child tracks)
0x04    2     uint16  First TPLB index (1-based pointer into the TPLB array)
0x06    2     uint16  Reserved (0x0000)
```

Class header complement1 = total number of groups.

#### TPLB Element (2 bytes) -- Track Reference

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    2     uint16  Track ID (1-based, references 04CNTINF element index)
```

Class header complement1 = total number of track references.

TPLB entries are sequential.  A GPLB entry with `first_tplb_index=5` means
that group's tracks start at the 5th TPLB element.  The group contains all
TPLB entries from that index up to (but not including) the next group's
`first_tplb_index`.

#### Example: 01TREE01.DAT with 1 group, 18 tracks

```
00000000: 54 52 45 45 01 01 00 00  02 00 00 00 00 00 00 00  TREE............
00000010: 47 50 4C 42 00 00 00 30  00 00 00 18 00 00 00 00  GPLB...0........
00000020: 54 50 4C 42 00 00 00 48  00 00 00 34 00 00 00 00  TPLB...H...4....
00000030: 47 50 4C 42 00 01 00 08  00 00 00 01 00 00 00 00  GPLB............
           magic    cnt=1  sz=8  comp1=1
00000040: 00 01  01 00  00 01  00 00                          group1: id=1, flags=0x0100, tplb_start=1
00000048: 54 50 4C 42 00 12 00 02  00 00 00 12 00 00 00 00  TPLB............
           magic    cnt=18 sz=2  comp1=18
00000058: 00 01 00 02 00 03 00 04  00 05 00 06 00 07 00 08  tracks 1-8
00000068: 00 09 00 0A 00 0B 00 0C  00 0D 00 0E 00 0F 00 10  tracks 9-16
00000078: 00 11 00 12                                        tracks 17-18
```


### 3.3 02TREINF.DAT -- Tree Information

Contains tree-level summary information.

**Table magic**: `GTIF`
**Class count**: 1

**Classes**: `GTFB`

#### GTFB Element (0x90 = 144 bytes)

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    12    bytes   Reserved (zeros)
0x0C    2     uint16  Tag field count (observed: 1)
0x0E    2     uint16  Tag field size (observed: 0x0080 = 128)
0x10    128   tag     TIT2 tag field (tree display name, typically empty)
```

The device pre-allocates space for multiple GTFB elements.  Observed
`GTFB` section size on a factory-formatted NW-E407: 0x2410 bytes (9232),
accommodating up to 64 elements of 0x90 bytes each (plus 16-byte header).

Hex dump:

```
00000020: 47 54 46 42 00 01 00 90  00 00 00 00 00 00 00 00  GTFB............
           magic    cnt=1  sz=144 comp1=0       comp2=0
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 01 00 80  ................
                                                  tags=1 sz=128
00000040: 54 49 54 32 00 02 00 00  00 00 00 00 ...          TIT2 (empty)
```


### 3.4 03GINFxx.DAT -- Group Information

Stores metadata for groups (albums, artists, or genres depending on the
`xx` suffix).

**Table magic**: `GPIF`
**Class count**: 1

**Classes**: `GPFB`

#### 03GINF01.DAT: GPFB Element (0x310 = 784 bytes) -- Album Groups

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    8     bytes   Reserved / magic key (zeros)
0x08    4     uint32  Album key (sum of track durations in ms)
0x0C    2     uint16  Tag field count (6)
0x0E    2     uint16  Tag field size (0x0080 = 128)
0x10    128   tag     TIT2 -- album title
0x90    128   tag     TPE1 -- album artist
0x110   128   tag     TCON -- genre
0x190   128   tag     TSOP -- sort order (performer)
0x210   128   tag     PICP -- picture path (empty on NW-E4xx)
0x290   128   tag     PIC0 -- picture data (empty on NW-E4xx)
```

Hex dump from device (first element):

```
00000030: 00 00 00 00 00 00 00 00  00 3F C0 C8 00 06 00 80
                                   album_key    tags=6 sz=128
00000040: 54 49 54 32 00 02 00 54  00 68 00 65 00 20 ...    TIT2 "The ..."
```

#### 03GINF02-04.DAT: GPFB Element (0x90 = 144 bytes) -- Simple Groups

Used for artist, album, and genre views (one tag field per element).

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    12    bytes   Reserved (zeros)
0x0C    2     uint16  Tag field count (1)
0x0E    2     uint16  Tag field size (0x0080 = 128)
0x10    128   tag     TIT2 -- group name (artist, album, or genre)
```

These files are empty (element count = 0) when using only the primary
upload-order tree.


### 3.5 04CNTINF.DAT -- Track Content Info

Per-track metadata.  This is the primary track information database.

**Table magic**: `CNIF`
**Class count**: 1

**Classes**: `CNFB`

#### CNFB Element (0x290 = 656 bytes)

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    2     uint16  Reserved (0x0000)
0x02    2     uint16  Protection type
0x04    4     bytes   File properties (codec info, see Section 6)
0x08    4     uint32  Title key (track duration in milliseconds)
0x0C    2     uint16  Tag field count (5)
0x0E    2     uint16  Tag field size (0x0080 = 128)
0x10    128   tag     TIT2 -- track title
0x90    128   tag     TPE1 -- artist
0x110   128   tag     TALB -- album
0x190   128   tag     TCON -- genre
0x210   128   tag     TSOP -- sort order (performer)
```

**Protection type values:**

| Value    | Meaning |
|----------|---------|
| `0x0000` | No protection |
| `0xFFFE` | XOR-encrypted MP3 |
| `0xFFFF` | OpenMG DRM |

Hex dump from device (first track):

```
00000030: 00 00  FF FE  03 80 D9 10  00 03 2F 1A  00 05 00 80
           res   prot   file_props   title_key   tags=5 sz=128
00000040: 54 49 54 32 00 02 00 49  00 6E 00 20 ...          TIT2 "In ..."
000000C0: 54 50 45 31 00 02 00 56  00 65 00 6E ...          TPE1 "Ven..."
00000140: 54 41 4C 42 00 02 00 54  00 68 00 65 ...          TALB "The..."
000001C0: 54 43 4F 4E 00 02 00 00  ...                      TCON (empty)
00000240: 54 53 4F 50 00 02 00 56  00 65 00 6E ...          TSOP "Ven..."
```

Note: Tag text in CNFB elements is encoded as **UTF-16BE** (encoding byte
`0x02`), unlike the EA3 tag header which uses UTF-8.


### 3.6 05CIDLST.DAT -- Content ID List

Maps track IDs to content identifiers.  For non-DRM (XOR-encrypted) content,
most fields are zero.

**Table magic**: `CIDL`
**Class count**: 1

**Classes**: `CILB`

#### CILB Element (0x30 = 48 bytes)

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    2     uint16  Track ID (1-based, matches OMA filename)
0x02    46    bytes   Reserved (zeros for non-DRM content)
```

Hex dump (first 4 entries):

```
00000030: 00 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  track 1
00000040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00000050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00000060: 00 02 00 00 00 00 00 00  00 00 00 00 00 00 00 00  track 2
00000070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00000080: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00000090: 00 03 00 00 00 00 00 00  00 00 00 00 00 00 00 00  track 3
```

---

## 4. DvID.dat -- Device Identity

Located at `MP3FM/DvID.dat` on the device (relative to the mount point).
Exactly **16 bytes**.

```
Offset  Size  Type    Description
------  ----  ------  -----------
0x00    2     bytes   Unknown (observed: 0x03 0x01)
0x02    2     bytes   Unknown (observed: 0x01 0x00)
0x04    2     bytes   Unknown (observed: 0x00 0x00)
0x06    4     bytes   Unknown (observed: varies)
0x0A    4     uint32  Device encryption key (big-endian)
0x0E    2     bytes   Unknown (observed: 0x00 0x00)
```

The **4 bytes at offset 0x0A-0x0D** are the device-specific key used in XOR
key derivation (see Section 1.3).

Example hex dump:

```
00000000: 03 01 01 00 00 00 01 28  00 00 08 DA 6D 03 00 00
                                         ^^^^^^^^^^^
                                         device key = 0x08DA6D03
```

This key is unique per device and does not change.  It is written to the
device during factory initialization.

---

## 5. Cross-Reference Chain

The database files reference each other through index values.  The complete
chain for looking up a track:

```
00GTRLST.DAT
  GTLB element.fileRef = N
    --> 01TREE0N.DAT
    --> 03GINF0N.DAT

01TREE0N.DAT
  GPLB element.group_id = G
    --> 03GINF0N.DAT element[G] (group metadata)
  GPLB element.first_tplb_index = T
    --> TPLB[T], TPLB[T+1], ... (track IDs for this group)
  TPLB element.track_id = K
    --> 04CNTINF.DAT element[K] (track metadata)
    --> 05CIDLST.DAT element[K] (content ID)
    --> OMGAUDIO/10F{K//256:02X}/1000{K:04X}.OMA (audio file)
```

**Lookup example** -- finding track 5's metadata:

1. `00GTRLST.DAT` GTLB element 1 has `fileRef=1` --> use `01TREE01.DAT`
2. `01TREE01.DAT` TPLB contains `... 00 05 ...` at some index
3. `04CNTINF.DAT` element 5 (5th CNFB block, at file offset
   `0x20 + 0x10 + (5-1) * 0x290`) contains the track's title, artist, etc.
4. `05CIDLST.DAT` element 5 has `track_id=0x0005`
5. Audio file: `OMGAUDIO/10F00/10000005.OMA`

---

## 6. MP3 Codec Parameters Encoding

The **file_properties** field in CNFB elements (04CNTINF.DAT offset 0x04)
and the **codec_params** field in the EA3 audio header (offset 0x21) encode
MP3 stream parameters in 3 bytes (24 bits).

```
Byte 0 (offset +0): CBR/VBR flag
Byte 1 (offset +1): MPEG version, layer, and bitrate index
Byte 2 (offset +2): Channel mode
```

### Byte 0: CBR/VBR

| Value  | Meaning |
|--------|---------|
| `0x80` | CBR (Constant Bit Rate) |
| `0xC0` | VBR (Variable Bit Rate) |

### Byte 1: Version, Layer, Bitrate Index

Packed as: `(mpeg_version << 6) | (layer << 4) | bitrate_index`

**MPEG version codes:**

| Value | MPEG Version |
|-------|-------------|
| 0     | MPEG 2.5 |
| 2     | MPEG 2 |
| 3     | MPEG 1 |

**Layer codes:**

| Value | Layer |
|-------|-------|
| 1     | Layer III |
| 2     | Layer II |
| 3     | Layer I |

**Bitrate index (MPEG1 Layer III):**

| Index | Bitrate (kbps) |
|-------|----------------|
| 0x01  | 32 |
| 0x02  | 40 |
| 0x03  | 48 |
| 0x04  | 56 |
| 0x05  | 64 |
| 0x06  | 80 |
| 0x07  | 96 |
| 0x08  | 112 |
| 0x09  | 128 |
| 0x0A  | 160 |
| 0x0B  | 192 |
| 0x0C  | 224 |
| 0x0D  | 256 |
| 0x0E  | 320 |

### Byte 2: Channel Mode

| Value  | Meaning |
|--------|---------|
| `0x10` | Stereo (or joint stereo) |
| `0x30` | Mono |

### Decoding Example

Observed value: `0x80 0xD9 0x10`

```
Byte 0: 0x80 = CBR
Byte 1: 0xD9 = 1101 1001
         ^^    mpeg_version = 3 (MPEG 1)
           ^   layer = 1 (Layer III)
            ^^^^ bitrate_index = 0x09 (128 kbps)
Byte 2: 0x10 = Stereo

Result: MPEG1 Layer III, 128 kbps CBR, Stereo
```

### In the EA3 Audio Header

The codec_params appear at offset 0x21-0x23 (bytes 33-35), immediately
after the codec ID byte at offset 0x20:

```
Offset 0x20: 03        Codec ID = MP3
Offset 0x21: 80        CBR
Offset 0x22: D9        MPEG1 / Layer III / 128 kbps
Offset 0x23: 10        Stereo
```

---

## References

- JSymphonic (Java, GPL) -- Sony Walkman manager with OMGAUDIO support
- FU-NW-HD5 -- NW-HD5 reverse engineering notes
- rustystage (Rust) -- SonicStage protocol reimplementation
- FFmpeg `libavformat/oma.c` and `libavformat/oma.h` (LGPL) -- OMA demuxer
- waider.ie FILE_FORMAT_v2 -- community format documentation

---

## Disclaimer

Sony, Network Walkman, SonicStage, OpenMG, ATRAC, and all associated logos and
trademarks are the property of Sony Corporation. This document is not affiliated
with, endorsed by, or sponsored by Sony Corporation. All product names are used
for identification purposes only.

This is clean-room documentation produced through independent reverse
engineering for interoperability purposes.
