/*
 * MP3FM - Sony Network Walkman (NW-E4xx/NW-HD) MP3 File Manager
 * C++17 implementation - no external libraries (std + POSIX + ffmpeg subprocess)
 *
 * Reverse-engineered replacement for Sony's MP3FileManager.exe
 * Transfers MP3/FLAC/audio files to Sony OMGAUDIO-based players.
 * Handles FLAC->MP3 conversion, OMA container creation, XOR encryption,
 * and full OMGAUDIO database generation.
 *
 * Based on RE of: FrankPACAPI.dll, waider.ie FILE_FORMAT_v2, rustystage,
 * FU-NW-HD5, JSymphonic, FFmpeg OMA implementation.
 *
 * Build (Linux/macOS): g++ -std=c++17 -O2 -o mp3fm mp3fm.cpp
 * Build (Windows):     x86_64-w64-mingw32-g++ -std=c++17 -O2 -o mp3fm.exe mp3fm.cpp
 * Usage: ./mp3fm <device_path> <files_or_dirs...> [-b bitrate]
 */

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <io.h>
#  include <direct.h>
#  include <process.h>
#else
#  include <dirent.h>
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace fs = std::filesystem;

// =============================================================================
// Constants
// =============================================================================

static constexpr const char* OMGAUDIO_DIR = "OMGAUDIO";

static constexpr uint32_t EA3_TAG_TOTAL_SIZE = 0x0C00;  // 3072 bytes
static constexpr uint32_t EA3_AUDIO_HEADER_SIZE = 96;

static constexpr uint8_t OMA_CODECID_MP3 = 3;
static constexpr uint16_t ENC_ID_MP3_XOR = 0xFFFE;

// MP3 bitrate index table (MPEG1 Layer III)
static const std::map<int, uint8_t> MP3_BITRATES_L3 = {
    {32, 0x01}, {40, 0x02}, {48, 0x03}, {56, 0x04}, {64, 0x05},
    {80, 0x06}, {96, 0x07}, {112, 0x08}, {128, 0x09}, {160, 0x0A},
    {192, 0x0B}, {224, 0x0C}, {256, 0x0D}, {320, 0x0E},
};

// =============================================================================
// Track metadata structure
// =============================================================================

struct TrackInfo {
    int track_id = 0;
    int track_num = 0;
    int duration_ms = 0;
    int bitrate = 128;       // kbps
    int sample_rate = 44100;
    int channels = 2;
    std::string title;
    std::string artist;
    std::string album;
    std::string genre;
};

// =============================================================================
// Big-endian binary I/O helpers
// =============================================================================

static void put_be16(uint8_t* dst, uint16_t val) {
    dst[0] = static_cast<uint8_t>((val >> 8) & 0xFF);
    dst[1] = static_cast<uint8_t>(val & 0xFF);
}

static void put_be32(uint8_t* dst, uint32_t val) {
    dst[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    dst[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    dst[2] = static_cast<uint8_t>((val >> 8) & 0xFF);
    dst[3] = static_cast<uint8_t>(val & 0xFF);
}

static uint16_t get_be16(const uint8_t* src) {
    return static_cast<uint16_t>((src[0] << 8) | src[1]);
}

static uint32_t get_be32(const uint8_t* src) {
    return (static_cast<uint32_t>(src[0]) << 24) |
           (static_cast<uint32_t>(src[1]) << 16) |
           (static_cast<uint32_t>(src[2]) << 8) |
           static_cast<uint32_t>(src[3]);
}

// Write 2-byte big-endian to file stream
static void fwrite_be16(std::ofstream& f, uint16_t val) {
    uint8_t buf[2];
    put_be16(buf, val);
    f.write(reinterpret_cast<const char*>(buf), 2);
}

// Write 4-byte big-endian to file stream
static void fwrite_be32(std::ofstream& f, uint32_t val) {
    uint8_t buf[4];
    put_be32(buf, val);
    f.write(reinterpret_cast<const char*>(buf), 4);
}

// Write raw bytes to stream
static void fwrite_raw(std::ofstream& f, const void* data, size_t len) {
    f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
}

// Write zero padding
static void fwrite_zeros(std::ofstream& f, size_t count) {
    std::vector<uint8_t> z(count, 0);
    fwrite_raw(f, z.data(), count);
}

// Read entire file into vector
static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        std::cerr << "Error: cannot open file: " << path << "\n";
        std::exit(1);
    }
    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

// =============================================================================
// UTF-8 to UTF-16BE conversion (manual, no ICU/iconv needed)
// =============================================================================

static std::vector<uint8_t> utf8_to_utf16be(const std::string& utf8) {
    std::vector<uint8_t> out;
    size_t i = 0;
    while (i < utf8.size()) {
        uint32_t cp = 0;
        uint8_t c = static_cast<uint8_t>(utf8[i]);

        if (c < 0x80) {
            cp = c;
            i += 1;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= utf8.size()) break;
            cp = (static_cast<uint32_t>(c & 0x1F) << 6) |
                 (static_cast<uint32_t>(utf8[i + 1]) & 0x3F);
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= utf8.size()) break;
            cp = (static_cast<uint32_t>(c & 0x0F) << 12) |
                 ((static_cast<uint32_t>(utf8[i + 1]) & 0x3F) << 6) |
                 (static_cast<uint32_t>(utf8[i + 2]) & 0x3F);
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= utf8.size()) break;
            cp = (static_cast<uint32_t>(c & 0x07) << 18) |
                 ((static_cast<uint32_t>(utf8[i + 1]) & 0x3F) << 12) |
                 ((static_cast<uint32_t>(utf8[i + 2]) & 0x3F) << 6) |
                 (static_cast<uint32_t>(utf8[i + 3]) & 0x3F);
            i += 4;
        } else {
            // Invalid byte, skip
            i += 1;
            continue;
        }

        // Encode as UTF-16BE
        if (cp <= 0xFFFF) {
            out.push_back(static_cast<uint8_t>((cp >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(cp & 0xFF));
        } else if (cp <= 0x10FFFF) {
            // Surrogate pair
            cp -= 0x10000;
            uint16_t hi = 0xD800 | static_cast<uint16_t>((cp >> 10) & 0x3FF);
            uint16_t lo = 0xDC00 | static_cast<uint16_t>(cp & 0x3FF);
            out.push_back(static_cast<uint8_t>((hi >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(hi & 0xFF));
            out.push_back(static_cast<uint8_t>((lo >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(lo & 0xFF));
        }
    }
    return out;
}

// =============================================================================
// String formatting helpers
// =============================================================================

static std::string format_oma_dir(int folder_num) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "10F%02X", folder_num);
    return buf;
}

static std::string format_oma_file(int track_id) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "1000%04X.OMA", track_id);
    return buf;
}

static std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// =============================================================================
// DvID and XOR encryption
// =============================================================================

static uint32_t read_dvid(const std::string& dvid_path) {
    auto data = read_file(dvid_path);
    if (data.size() < 14) {
        std::cerr << "Error: DvID.dat too short: " << data.size() << " bytes\n";
        std::exit(1);
    }
    // Bytes 10-13 contain the device-specific key (big-endian)
    return get_be32(&data[10]);
}

static std::array<uint8_t, 4> compute_xor_key(int track_id, uint32_t dvid_key) {
    // key = (0x2465 + track_id * 0x5296E435) ^ dvid_key
    uint32_t key = ((0x2465u + static_cast<uint32_t>(track_id) * 0x5296E435u) & 0xFFFFFFFFu) ^ dvid_key;
    std::array<uint8_t, 4> kb;
    put_be32(kb.data(), key);
    return kb;
}

static void xor_encrypt(std::vector<uint8_t>& data, const std::array<uint8_t, 4>& key_bytes) {
    // 4-byte key repeated as 8-byte pattern
    uint8_t key8[8];
    std::memcpy(key8, key_bytes.data(), 4);
    std::memcpy(key8 + 4, key_bytes.data(), 4);

    size_t full_blocks = data.size() / 8;
    size_t enc_len = full_blocks * 8;
    for (size_t i = 0; i < enc_len; ++i) {
        data[i] ^= key8[i % 8];
    }
    // Trailing bytes that don't fill an 8-byte block are left unencrypted
}

// =============================================================================
// Manual ID3v2 tag parsing (ID3v2.3)
// =============================================================================

// Parse a syncsafe integer (ID3v2 uses 7 bits per byte)
static uint32_t parse_syncsafe(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0] & 0x7F) << 21) |
           (static_cast<uint32_t>(p[1] & 0x7F) << 14) |
           (static_cast<uint32_t>(p[2] & 0x7F) << 7) |
           static_cast<uint32_t>(p[3] & 0x7F);
}

// Decode ID3v2 text frame content to UTF-8 string
static std::string decode_id3_text(const uint8_t* data, size_t len) {
    if (len < 1) return "";

    uint8_t encoding = data[0];
    const uint8_t* text_start = data + 1;
    size_t text_len = len - 1;

    if (encoding == 0) {
        // ISO-8859-1 (Latin-1) -> just treat as ASCII for basic cases
        return std::string(reinterpret_cast<const char*>(text_start), text_len);
    } else if (encoding == 1) {
        // UTF-16 with BOM
        if (text_len < 2) return "";
        bool le = (text_start[0] == 0xFF && text_start[1] == 0xFE);
        // bool be = (text_start[0] == 0xFE && text_start[1] == 0xFF);
        const uint8_t* p = text_start + 2;
        size_t remaining = text_len - 2;
        std::string result;
        for (size_t i = 0; i + 1 < remaining; i += 2) {
            uint16_t ch;
            if (le)
                ch = static_cast<uint16_t>(p[i]) | (static_cast<uint16_t>(p[i + 1]) << 8);
            else
                ch = (static_cast<uint16_t>(p[i]) << 8) | static_cast<uint16_t>(p[i + 1]);
            if (ch == 0) break;
            // Simple UTF-16 to UTF-8 (BMP only for metadata)
            if (ch < 0x80) {
                result += static_cast<char>(ch);
            } else if (ch < 0x800) {
                result += static_cast<char>(0xC0 | (ch >> 6));
                result += static_cast<char>(0x80 | (ch & 0x3F));
            } else {
                result += static_cast<char>(0xE0 | (ch >> 12));
                result += static_cast<char>(0x80 | ((ch >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (ch & 0x3F));
            }
        }
        return result;
    } else if (encoding == 2) {
        // UTF-16BE (no BOM)
        std::string result;
        for (size_t i = 0; i + 1 < text_len; i += 2) {
            uint16_t ch = (static_cast<uint16_t>(text_start[i]) << 8) |
                          static_cast<uint16_t>(text_start[i + 1]);
            if (ch == 0) break;
            if (ch < 0x80) {
                result += static_cast<char>(ch);
            } else if (ch < 0x800) {
                result += static_cast<char>(0xC0 | (ch >> 6));
                result += static_cast<char>(0x80 | (ch & 0x3F));
            } else {
                result += static_cast<char>(0xE0 | (ch >> 12));
                result += static_cast<char>(0x80 | ((ch >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (ch & 0x3F));
            }
        }
        return result;
    } else if (encoding == 3) {
        // UTF-8
        // Trim trailing NULs
        while (text_len > 0 && text_start[text_len - 1] == 0) --text_len;
        return std::string(reinterpret_cast<const char*>(text_start), text_len);
    }

    return "";
}

// Parse ID3v2 tags from MP3 data, returning metadata
static TrackInfo parse_id3v2(const std::vector<uint8_t>& data) {
    TrackInfo info;
    info.bitrate = 128;
    info.sample_rate = 44100;
    info.channels = 2;
    info.duration_ms = 0;

    if (data.size() < 10) return info;
    if (data[0] != 'I' || data[1] != 'D' || data[2] != '3') return info;

    // uint8_t version_major = data[3];  // e.g. 3 for ID3v2.3
    // uint8_t version_minor = data[4];
    // uint8_t flags = data[5];
    uint32_t tag_size = parse_syncsafe(&data[6]);
    size_t header_end = 10 + tag_size;
    if (header_end > data.size()) header_end = data.size();

    // Parse frames starting at offset 10
    size_t pos = 10;
    while (pos + 10 <= header_end) {
        // Frame header: 4-byte ID + 4-byte size (big-endian, NOT syncsafe in v2.3) + 2-byte flags
        char frame_id[5] = {};
        std::memcpy(frame_id, &data[pos], 4);

        // Check for padding (all zeros)
        if (frame_id[0] == 0) break;

        uint32_t frame_size = get_be32(&data[pos + 4]);
        // uint16_t frame_flags = get_be16(&data[pos + 8]);

        if (frame_size == 0 || pos + 10 + frame_size > header_end) break;

        const uint8_t* frame_data = &data[pos + 10];

        std::string fid(frame_id, 4);
        if (fid == "TIT2") {
            info.title = decode_id3_text(frame_data, frame_size);
        } else if (fid == "TPE1") {
            info.artist = decode_id3_text(frame_data, frame_size);
        } else if (fid == "TALB") {
            info.album = decode_id3_text(frame_data, frame_size);
        } else if (fid == "TCON") {
            info.genre = decode_id3_text(frame_data, frame_size);
        } else if (fid == "TRCK") {
            std::string trck_str = decode_id3_text(frame_data, frame_size);
            // May be "5" or "5/12"
            try {
                auto slash = trck_str.find('/');
                if (slash != std::string::npos)
                    info.track_num = std::stoi(trck_str.substr(0, slash));
                else
                    info.track_num = std::stoi(trck_str);
            } catch (...) {
                info.track_num = 0;
            }
        }

        pos += 10 + frame_size;
    }

    return info;
}

// =============================================================================
// MP3 audio parsing - duration, bitrate, sample rate
// =============================================================================

// MPEG1 Layer III bitrate table (kbps), index 0 = free, 15 = bad
static const int MPEG1_L3_BITRATES[16] = {
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0
};

// MPEG2/2.5 Layer III bitrate table
static const int MPEG2_L3_BITRATES[16] = {
    0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0
};

// MPEG1 sample rates
static const int MPEG1_SAMPLERATES[4] = {44100, 48000, 32000, 0};
static const int MPEG2_SAMPLERATES[4] = {22050, 24000, 16000, 0};
static const int MPEG25_SAMPLERATES[4] = {11025, 12000, 8000, 0};

// Find the offset of the first MP3 sync frame (after ID3v2 tags)
static size_t find_mp3_audio_start(const std::vector<uint8_t>& data) {
    if (data.size() >= 10 && data[0] == 'I' && data[1] == 'D' && data[2] == '3') {
        uint32_t tag_size = parse_syncsafe(&data[6]);
        size_t offset = 10 + tag_size;
        // Check for footer flag (bit 4 of flags byte 5)
        if (data[5] & 0x10) offset += 10;
        return offset;
    }
    return 0;
}

// Parse MP3 frame header at given offset, return frame size (0 if invalid)
struct Mp3FrameInfo {
    int bitrate;      // kbps
    int sample_rate;
    int channels;
    int frame_size;   // bytes
    int samples;      // samples per frame
    bool valid;
};

static Mp3FrameInfo parse_mp3_frame(const std::vector<uint8_t>& data, size_t offset) {
    Mp3FrameInfo fi = {};
    fi.valid = false;

    if (offset + 4 > data.size()) return fi;

    uint32_t hdr = (static_cast<uint32_t>(data[offset]) << 24) |
                   (static_cast<uint32_t>(data[offset + 1]) << 16) |
                   (static_cast<uint32_t>(data[offset + 2]) << 8) |
                   static_cast<uint32_t>(data[offset + 3]);

    // Check sync word (11 bits)
    if ((hdr & 0xFFE00000) != 0xFFE00000) return fi;

    int mpeg_version = (hdr >> 19) & 0x03;  // 0=2.5, 1=reserved, 2=2, 3=1
    int layer = (hdr >> 17) & 0x03;          // 0=reserved, 1=III, 2=II, 3=I
    // int protection = (hdr >> 16) & 0x01;
    int bitrate_idx = (hdr >> 12) & 0x0F;
    int samplerate_idx = (hdr >> 10) & 0x03;
    int padding = (hdr >> 9) & 0x01;
    int channel_mode = (hdr >> 6) & 0x03;

    if (mpeg_version == 1 || layer == 0 || bitrate_idx == 0 || bitrate_idx == 15 || samplerate_idx == 3)
        return fi;

    // Get bitrate
    int bitrate_kbps = 0;
    if (mpeg_version == 3 && layer == 1)  // MPEG1, Layer III
        bitrate_kbps = MPEG1_L3_BITRATES[bitrate_idx];
    else if (layer == 1)  // MPEG2/2.5, Layer III
        bitrate_kbps = MPEG2_L3_BITRATES[bitrate_idx];
    else
        return fi;  // We only handle Layer III

    if (bitrate_kbps == 0) return fi;

    // Get sample rate
    int sr = 0;
    if (mpeg_version == 3) sr = MPEG1_SAMPLERATES[samplerate_idx];
    else if (mpeg_version == 2) sr = MPEG2_SAMPLERATES[samplerate_idx];
    else if (mpeg_version == 0) sr = MPEG25_SAMPLERATES[samplerate_idx];
    if (sr == 0) return fi;

    // Samples per frame: Layer III = 1152 for MPEG1, 576 for MPEG2/2.5
    int samples_per_frame = (mpeg_version == 3) ? 1152 : 576;

    // Frame size for Layer III: (samples_per_frame / 8 * bitrate * 1000) / sample_rate + padding
    int frame_size = (samples_per_frame * bitrate_kbps * 1000 / 8) / sr + padding;

    fi.bitrate = bitrate_kbps;
    fi.sample_rate = sr;
    fi.channels = (channel_mode == 3) ? 1 : 2;  // 3 = mono
    fi.frame_size = frame_size;
    fi.samples = samples_per_frame;
    fi.valid = true;
    return fi;
}

// Compute MP3 duration by scanning frames (accurate for both CBR and VBR)
static void compute_mp3_info(const std::vector<uint8_t>& data, TrackInfo& info) {
    size_t audio_start = find_mp3_audio_start(data);
    size_t pos = audio_start;

    int64_t total_samples = 0;
    int first_bitrate = 0;
    int first_sr = 0;
    int first_ch = 0;
    int frame_count = 0;

    while (pos + 4 <= data.size()) {
        auto fi = parse_mp3_frame(data, pos);
        if (!fi.valid) {
            // Try to find next sync
            ++pos;
            continue;
        }

        if (frame_count == 0) {
            first_bitrate = fi.bitrate;
            first_sr = fi.sample_rate;
            first_ch = fi.channels;
        }

        total_samples += fi.samples;
        ++frame_count;

        if (fi.frame_size <= 0) break;
        pos += static_cast<size_t>(fi.frame_size);
    }

    if (frame_count > 0 && first_sr > 0) {
        info.duration_ms = static_cast<int>((total_samples * 1000) / first_sr);
        info.bitrate = first_bitrate;
        info.sample_rate = first_sr;
        info.channels = first_ch;
    }
}

// Read MP3 file and extract all metadata + audio properties
static TrackInfo get_mp3_info(const std::string& mp3_path) {
    auto data = read_file(mp3_path);

    // Parse ID3 tags
    TrackInfo info = parse_id3v2(data);

    // Compute audio properties from frames
    compute_mp3_info(data, info);

    // Fallback: use filename stem as title
    if (info.title.empty()) {
        info.title = fs::path(mp3_path).stem().string();
    }

    return info;
}

// Get raw MP3 audio data (strip ID3v2 header)
static std::vector<uint8_t> get_mp3_raw_audio(const std::string& mp3_path) {
    auto data = read_file(mp3_path);
    size_t offset = find_mp3_audio_start(data);
    if (offset >= data.size()) return {};
    return std::vector<uint8_t>(data.begin() + static_cast<ptrdiff_t>(offset), data.end());
}

// =============================================================================
// EA3/OMA file creation
// =============================================================================

// Encode an ID3v2.3 text frame for the EA3 tag section
static std::vector<uint8_t> encode_id3_text_frame(const std::string& frame_id,
                                                   const std::string& text,
                                                   int encoding = 3) {
    std::vector<uint8_t> result;

    // Frame ID (4 bytes)
    for (int i = 0; i < 4; ++i)
        result.push_back(static_cast<uint8_t>(frame_id[i]));

    // Build payload
    std::vector<uint8_t> payload;
    if (encoding == 3) {
        // UTF-8
        payload.push_back(0x03);
        for (char c : text) payload.push_back(static_cast<uint8_t>(c));
    } else if (encoding == 0) {
        // Latin-1
        payload.push_back(0x00);
        for (char c : text) payload.push_back(static_cast<uint8_t>(c));
    }

    // Size (4 bytes, big-endian, NOT syncsafe for ID3v2.3)
    uint32_t sz = static_cast<uint32_t>(payload.size());
    result.push_back(static_cast<uint8_t>((sz >> 24) & 0xFF));
    result.push_back(static_cast<uint8_t>((sz >> 16) & 0xFF));
    result.push_back(static_cast<uint8_t>((sz >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(sz & 0xFF));

    // Flags (2 bytes, zeros)
    result.push_back(0x00);
    result.push_back(0x00);

    // Payload
    result.insert(result.end(), payload.begin(), payload.end());

    return result;
}

// Encode a TXXX (user-defined text) ID3v2 frame
static std::vector<uint8_t> encode_txxx_frame(const std::string& description,
                                               const std::string& value,
                                               int encoding = 3) {
    std::vector<uint8_t> result;

    // "TXXX"
    result.push_back('T'); result.push_back('X');
    result.push_back('X'); result.push_back('X');

    // Build payload
    std::vector<uint8_t> payload;
    if (encoding == 3) {
        payload.push_back(0x03);
        for (char c : description) payload.push_back(static_cast<uint8_t>(c));
        payload.push_back(0x00);  // NUL separator
        for (char c : value) payload.push_back(static_cast<uint8_t>(c));
    }

    // Size
    uint32_t sz = static_cast<uint32_t>(payload.size());
    result.push_back(static_cast<uint8_t>((sz >> 24) & 0xFF));
    result.push_back(static_cast<uint8_t>((sz >> 16) & 0xFF));
    result.push_back(static_cast<uint8_t>((sz >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(sz & 0xFF));

    // Flags
    result.push_back(0x00);
    result.push_back(0x00);

    // Payload
    result.insert(result.end(), payload.begin(), payload.end());

    return result;
}

// Build the EA3 tag section (3072 bytes, ID3v2-like with "ea3" magic)
static std::vector<uint8_t> build_ea3_tag(const TrackInfo& info, int track_id) {
    // Build frames
    std::vector<uint8_t> frames;

    auto append = [&](const std::vector<uint8_t>& v) {
        frames.insert(frames.end(), v.begin(), v.end());
    };

    if (!info.title.empty())
        append(encode_id3_text_frame("TIT2", info.title));
    if (!info.artist.empty())
        append(encode_id3_text_frame("TPE1", info.artist));
    if (!info.album.empty())
        append(encode_id3_text_frame("TALB", info.album));
    if (!info.genre.empty())
        append(encode_id3_text_frame("TCON", info.genre));
    if (info.track_num > 0)
        append(encode_id3_text_frame("TRCK", std::to_string(info.track_num)));

    // Sony-specific TXXX frames
    append(encode_txxx_frame("OMG_TRACK", std::to_string(track_id)));
    append(encode_txxx_frame("OMG_TRLDA", "2005/01/01 00:00:00"));

    // EA3 tag header (10 bytes): "ea3\x03\x00\x00" + syncsafe size
    uint32_t content_size = EA3_TAG_TOTAL_SIZE - 10;
    // Encode as syncsafe integer
    uint32_t ss = ((content_size & 0x0FE00000u) << 3) |
                  ((content_size & 0x001FC000u) << 2) |
                  ((content_size & 0x00003F80u) << 1) |
                  (content_size & 0x0000007Fu);

    std::vector<uint8_t> tag;
    tag.reserve(EA3_TAG_TOTAL_SIZE);

    // Magic: "ea3" + 0x03 + 0x00 + 0x00
    tag.push_back('e'); tag.push_back('a'); tag.push_back('3');
    tag.push_back(0x03); tag.push_back(0x00); tag.push_back(0x00);

    // Syncsafe size (4 bytes)
    tag.push_back(static_cast<uint8_t>((ss >> 24) & 0xFF));
    tag.push_back(static_cast<uint8_t>((ss >> 16) & 0xFF));
    tag.push_back(static_cast<uint8_t>((ss >> 8) & 0xFF));
    tag.push_back(static_cast<uint8_t>(ss & 0xFF));

    // Append frames
    tag.insert(tag.end(), frames.begin(), frames.end());

    // Pad to EA3_TAG_TOTAL_SIZE
    tag.resize(EA3_TAG_TOTAL_SIZE, 0x00);

    return tag;
}

// Build the 96-byte EA3 audio header
static std::vector<uint8_t> build_ea3_audio_header(const TrackInfo& info) {
    std::vector<uint8_t> header(EA3_AUDIO_HEADER_SIZE, 0x00);

    // Bytes 0-2: "EA3"
    header[0] = 'E'; header[1] = 'A'; header[2] = '3';
    // Byte 3: version 0x02
    header[3] = 0x02;
    // Byte 4: 0x00
    header[4] = 0x00;
    // Byte 5: header size 0x60 (96)
    header[5] = 0x60;

    // Bytes 6-7: Encryption ID (0xFFFE = XOR scrambled MP3)
    put_be16(&header[6], ENC_ID_MP3_XOR);

    // Byte 32: Codec ID (3 = MP3)
    header[32] = OMA_CODECID_MP3;

    // Bytes 33-35: Codec parameters
    // Byte 33: 0x80 = CBR
    header[33] = 0x80;

    // Byte 34: (mpeg_version << 6) | (layer << 4) | bitrate_index
    auto it = MP3_BITRATES_L3.find(info.bitrate);
    uint8_t br_idx = (it != MP3_BITRATES_L3.end()) ? it->second : 0x09;
    header[34] = static_cast<uint8_t>((3 << 6) | (1 << 4) | br_idx);  // MPEG1, Layer III

    // Byte 35: channels (0x10 = stereo, 0x30 = mono)
    header[35] = (info.channels >= 2) ? 0x10 : 0x30;

    return header;
}

// Create an OMA file from an MP3 file
static size_t create_oma_file(const std::string& mp3_path,
                              const std::string& oma_path,
                              int track_id,
                              uint32_t dvid_key,
                              const TrackInfo& info) {
    // Build headers
    auto ea3_tag = build_ea3_tag(info, track_id);
    auto ea3_audio = build_ea3_audio_header(info);

    // Read raw MP3 audio data
    auto mp3_data = get_mp3_raw_audio(mp3_path);
    size_t audio_size = mp3_data.size();

    // XOR encrypt
    auto key = compute_xor_key(track_id, dvid_key);
    xor_encrypt(mp3_data, key);

    // Ensure parent directory exists
    fs::create_directories(fs::path(oma_path).parent_path());

    // Write OMA file
    std::ofstream f(oma_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        std::cerr << "Error: cannot create OMA file: " << oma_path << "\n";
        std::exit(1);
    }
    fwrite_raw(f, ea3_tag.data(), ea3_tag.size());
    fwrite_raw(f, ea3_audio.data(), ea3_audio.size());
    fwrite_raw(f, mp3_data.data(), mp3_data.size());
    f.close();

    return audio_size;
}

// =============================================================================
// OMGAUDIO Database Writers (all big-endian)
// =============================================================================

// Write 16-byte table header: magic(4) + 0x01010000(4) + count(1) + pad(7)
static void write_table_header(std::ofstream& f, const char* magic, uint8_t class_count) {
    fwrite_raw(f, magic, 4);
    uint8_t ver[] = {0x01, 0x01, 0x00, 0x00};
    fwrite_raw(f, ver, 4);
    f.put(static_cast<char>(class_count));
    fwrite_zeros(f, 7);
}

// Write 16-byte class descriptor: magic(4) + offset(4 BE) + length(4 BE) + pad(4)
static void write_class_desc(std::ofstream& f, const char* magic, uint32_t offset, uint32_t length) {
    fwrite_raw(f, magic, 4);
    fwrite_be32(f, offset);
    fwrite_be32(f, length);
    fwrite_zeros(f, 4);
}

// Write 16-byte class header: magic(4) + count(2 BE) + elemSize(2 BE) + comp1(4 BE) + comp2(4 BE)
static void write_class_header(std::ofstream& f, const char* magic,
                               uint16_t element_count, uint16_t element_size,
                               uint32_t complement1 = 0, uint32_t complement2 = 0) {
    fwrite_raw(f, magic, 4);
    fwrite_be16(f, element_count);
    fwrite_be16(f, element_size);
    fwrite_be32(f, complement1);
    fwrite_be32(f, complement2);
}

// Write a tag field into a buffer at given offset.
// Format: tag_name(4B) + 0x00(1B) + encoding(1B) + UTF-16BE text + zero padding
// Total: field_size bytes
static void write_tag_field(std::vector<uint8_t>& buf, size_t offset,
                            const char* tag_name, uint8_t encoding,
                            const std::string& text, size_t field_size = 0x80) {
    // tag name (4 ASCII bytes)
    buf[offset + 0] = static_cast<uint8_t>(tag_name[0]);
    buf[offset + 1] = static_cast<uint8_t>(tag_name[1]);
    buf[offset + 2] = static_cast<uint8_t>(tag_name[2]);
    buf[offset + 3] = static_cast<uint8_t>(tag_name[3]);

    // Encoding bytes
    buf[offset + 4] = 0x00;
    buf[offset + 5] = encoding;

    // UTF-16BE text
    if (!text.empty() && encoding == 0x02) {
        auto encoded = utf8_to_utf16be(text);
        size_t max_text = field_size - 6;
        if (encoded.size() > max_text) encoded.resize(max_text);
        std::memcpy(&buf[offset + 6], encoded.data(), encoded.size());
    }
}

// Write 04CNTINF.DAT - Content Information
static void write_04cntinf(const std::string& filepath, const std::vector<TrackInfo>& tracks) {
    size_t n = tracks.size();
    uint16_t elem_size = 0x0290;

    uint32_t class_offset = 16 + 16;  // table header + 1 class descriptor
    uint32_t class_length = 16 + static_cast<uint32_t>(n) * elem_size;

    std::ofstream f(filepath, std::ios::binary | std::ios::trunc);
    write_table_header(f, "CNIF", 1);
    write_class_desc(f, "CNFB", class_offset, class_length);
    write_class_header(f, "CNFB", static_cast<uint16_t>(n), elem_size);

    for (const auto& track : tracks) {
        std::vector<uint8_t> elem(elem_size, 0x00);

        // Bytes 2-3: protection (0xFFFE = MP3 XOR)
        put_be16(&elem[2], 0xFFFE);

        // Bytes 4-7: file properties / codec info
        auto it = MP3_BITRATES_L3.find(track.bitrate);
        uint8_t br_idx = (it != MP3_BITRATES_L3.end()) ? it->second : 0x09;
        uint8_t codec_byte2 = static_cast<uint8_t>((3 << 6) | (1 << 4) | br_idx);
        uint8_t codec_byte3 = (track.channels >= 2) ? 0x10 : 0x30;
        elem[4] = OMA_CODECID_MP3;
        elem[5] = 0x80;
        elem[6] = codec_byte2;
        elem[7] = codec_byte3;

        // Bytes 8-11: duration in ms
        put_be32(&elem[8], static_cast<uint32_t>(track.duration_ms));

        // Bytes 12-13: number of tag fields (5)
        put_be16(&elem[12], 5);

        // Bytes 14-15: tag field size (0x80 = 128)
        put_be16(&elem[14], 0x0080);

        // Tag fields at offset 0x10, each 0x80 bytes
        size_t tag_off = 0x10;
        write_tag_field(elem, tag_off + 0 * 0x80, "TIT2", 0x02, track.title);
        write_tag_field(elem, tag_off + 1 * 0x80, "TPE1", 0x02, track.artist);
        write_tag_field(elem, tag_off + 2 * 0x80, "TALB", 0x02, track.album);
        write_tag_field(elem, tag_off + 3 * 0x80, "TCON", 0x02, track.genre);
        write_tag_field(elem, tag_off + 4 * 0x80, "TSOP", 0x02, track.artist);

        fwrite_raw(f, elem.data(), elem.size());
    }
}

// Album group info for tree building
struct AlbumGroup {
    std::string name;
    std::string artist;
    std::string genre;
    uint32_t total_duration;
    std::vector<int> track_ids;
};

// Write 03GINF01.DAT - Group Information (album view)
static std::vector<AlbumGroup> write_03ginf01(const std::string& filepath,
                                               const std::vector<TrackInfo>& tracks) {
    // Group tracks by album, preserving order
    std::vector<AlbumGroup> albums;
    std::map<std::string, size_t> album_index;

    for (const auto& t : tracks) {
        std::string album = t.album.empty() ? "Unknown Album" : t.album;
        auto it = album_index.find(album);
        if (it == album_index.end()) {
            album_index[album] = albums.size();
            AlbumGroup ag;
            ag.name = album;
            ag.artist = t.artist;
            ag.genre = t.genre;
            ag.total_duration = 0;
            albums.push_back(ag);
        }
        size_t idx = album_index[album];
        albums[idx].total_duration += static_cast<uint32_t>(t.duration_ms);
        albums[idx].track_ids.push_back(t.track_id);
    }

    size_t n = albums.size();
    uint16_t elem_size = 0x0310;

    uint32_t class_offset = 16 + 16;
    uint32_t class_length = 16 + static_cast<uint32_t>(n) * elem_size;

    std::ofstream f(filepath, std::ios::binary | std::ios::trunc);
    write_table_header(f, "GPIF", 1);
    write_class_desc(f, "GPFB", class_offset, class_length);
    write_class_header(f, "GPFB", static_cast<uint16_t>(n), elem_size);

    for (const auto& ag : albums) {
        std::vector<uint8_t> elem(elem_size, 0x00);

        // Bytes 8-11: total duration
        put_be32(&elem[8], ag.total_duration);

        // Bytes 12-15: tag count (6) + tag size (0x80)
        put_be16(&elem[12], 6);
        put_be16(&elem[14], 0x0080);

        // 6 tag fields at offset 0x10
        size_t tag_off = 0x10;
        write_tag_field(elem, tag_off + 0 * 0x80, "TIT2", 0x02, ag.name);
        write_tag_field(elem, tag_off + 1 * 0x80, "TPE1", 0x02, ag.artist);
        write_tag_field(elem, tag_off + 2 * 0x80, "TCON", 0x02, ag.genre);
        write_tag_field(elem, tag_off + 3 * 0x80, "TSOP", 0x02, ag.artist);
        write_tag_field(elem, tag_off + 4 * 0x80, "PICP", 0x02, "");
        write_tag_field(elem, tag_off + 5 * 0x80, "PIC0", 0x02, "");

        fwrite_raw(f, elem.data(), elem.size());
    }

    return albums;
}

// Write 03GINF02/03/04.DAT - Simple group info (artists/albums/genres)
static void write_03ginf_simple(const std::string& filepath,
                                const std::vector<std::string>& items,
                                uint16_t elem_size = 0x0090) {
    size_t n = items.size();

    uint32_t class_offset = 16 + 16;
    uint32_t class_length = 16 + static_cast<uint32_t>(n) * elem_size;

    std::ofstream f(filepath, std::ios::binary | std::ios::trunc);
    write_table_header(f, "GPIF", 1);
    write_class_desc(f, "GPFB", class_offset, class_length);
    write_class_header(f, "GPFB", static_cast<uint16_t>(n), elem_size);

    for (const auto& item_name : items) {
        std::vector<uint8_t> elem(elem_size, 0x00);
        put_be16(&elem[12], 1);
        put_be16(&elem[14], 0x0080);
        write_tag_field(elem, 0x10, "TIT2", 0x02, item_name);
        fwrite_raw(f, elem.data(), elem.size());
    }
}

// Write 01TREExx.DAT - Tree structure with groups
static void write_01tree(const std::string& filepath,
                         const std::vector<std::vector<int>>& tracks_per_group) {
    uint16_t gplb_elem_size = 8;
    uint16_t tplb_elem_size = 2;

    // Build GPLB entries
    std::vector<std::vector<uint8_t>> gplb_entries;
    std::vector<uint16_t> tplb_entries;
    uint16_t tplb_offset = 0;

    for (size_t gi = 0; gi < tracks_per_group.size(); ++gi) {
        const auto& track_ids = tracks_per_group[gi];
        std::vector<uint8_t> entry(8, 0);
        put_be16(&entry[0], static_cast<uint16_t>(gi + 1));  // group ID (1-based)
        put_be16(&entry[2], 0x0100);                          // flag: has children
        put_be16(&entry[4], tplb_offset + 1);                 // pointer into TPLB (1-based)
        put_be16(&entry[6], 0x0000);
        gplb_entries.push_back(entry);

        for (int tid : track_ids) {
            tplb_entries.push_back(static_cast<uint16_t>(tid));
        }
        tplb_offset += static_cast<uint16_t>(track_ids.size());
    }

    auto n_gplb = static_cast<uint16_t>(gplb_entries.size());
    auto n_tplb = static_cast<uint16_t>(tplb_entries.size());

    // Class headers are 16 bytes each
    uint32_t gplb_data_size = 16 + static_cast<uint32_t>(n_gplb) * gplb_elem_size;
    uint32_t tplb_data_size = 16 + static_cast<uint32_t>(n_tplb) * tplb_elem_size;

    uint32_t gplb_offset_file = 16 + 16 * 2;  // table header + 2 class descriptors
    uint32_t tplb_offset_file = gplb_offset_file + gplb_data_size;

    std::ofstream f(filepath, std::ios::binary | std::ios::trunc);
    write_table_header(f, "TREE", 2);
    write_class_desc(f, "GPLB", gplb_offset_file, gplb_data_size);
    write_class_desc(f, "TPLB", tplb_offset_file, tplb_data_size);

    // GPLB class
    write_class_header(f, "GPLB", n_gplb, gplb_elem_size, n_gplb);
    for (const auto& entry : gplb_entries)
        fwrite_raw(f, entry.data(), entry.size());

    // TPLB class
    write_class_header(f, "TPLB", n_tplb, tplb_elem_size, n_tplb);
    for (uint16_t tid : tplb_entries)
        fwrite_be16(f, tid);
}

// Write a flat tree (all tracks in one implicit group)
static void write_01tree_flat(const std::string& filepath, const std::vector<int>& track_ids) {
    auto n = static_cast<uint16_t>(track_ids.size());
    uint16_t gplb_elem_size = 8;
    uint16_t tplb_elem_size = 2;

    uint32_t gplb_data_size = 16 + 1 * gplb_elem_size;
    uint32_t tplb_data_size = 16 + static_cast<uint32_t>(n) * tplb_elem_size;

    uint32_t gplb_offset = 16 + 32;
    uint32_t tplb_offset = gplb_offset + gplb_data_size;

    std::ofstream f(filepath, std::ios::binary | std::ios::trunc);
    write_table_header(f, "TREE", 2);
    write_class_desc(f, "GPLB", gplb_offset, gplb_data_size);
    write_class_desc(f, "TPLB", tplb_offset, tplb_data_size);

    // Single group pointing to all tracks
    write_class_header(f, "GPLB", 1, gplb_elem_size, 1);
    uint8_t gentry[8] = {};
    put_be16(&gentry[0], 1);
    put_be16(&gentry[2], 0x0100);
    put_be16(&gentry[4], 1);
    put_be16(&gentry[6], 0x0000);
    fwrite_raw(f, gentry, 8);

    // All track IDs
    write_class_header(f, "TPLB", n, tplb_elem_size, n);
    for (int tid : track_ids)
        fwrite_be16(f, static_cast<uint16_t>(tid));
}

// Write an empty tree file
static void write_01tree_empty(const std::string& filepath) {
    std::ofstream f(filepath, std::ios::binary | std::ios::trunc);
    write_table_header(f, "TREE", 2);
    write_class_desc(f, "GPLB", 0x30, 0x10);
    write_class_desc(f, "TPLB", 0x40, 0x10);
    write_class_header(f, "GPLB", 0, 8);
    write_class_header(f, "TPLB", 0, 2);
}

// Write 02TREINF.DAT - Tree Information
static void write_02treinf(const std::string& filepath, const std::vector<TrackInfo>& tracks) {
    uint16_t elem_size = 0x0090;
    uint32_t data_length = 0x2410;
    uint32_t class_offset = 16 + 16;

    std::ofstream f(filepath, std::ios::binary | std::ios::trunc);
    write_table_header(f, "GTIF", 1);
    write_class_desc(f, "GTFB", class_offset, data_length);

    uint16_t n_prealloc = static_cast<uint16_t>(std::max(size_t{1}, tracks.size()));
    write_class_header(f, "GTFB", n_prealloc, elem_size);

    // Global key element
    std::vector<uint8_t> elem(elem_size, 0x00);
    put_be16(&elem[12], 1);
    put_be16(&elem[14], 0x0080);
    write_tag_field(elem, 0x10, "TIT2", 0x02, "");
    fwrite_raw(f, elem.data(), elem.size());

    // Pad remaining to match expected length
    size_t written = 16 + elem_size;  // class header + 1 element
    if (written < data_length) {
        fwrite_zeros(f, data_length - written);
    }
}

// Write 00GTRLST.DAT - Group Tree List (master index)
static void write_00gtrlst(const std::string& filepath) {
    uint16_t elem_size = 0x0050;

    uint32_t sysb_offset = 0x30;
    uint32_t sysb_length = 0x70;
    uint32_t gtlb_offset = 0xA0;
    uint32_t gtlb_length = 0xB0;

    std::ofstream f(filepath, std::ios::binary | std::ios::trunc);
    write_table_header(f, "GTLT", 2);
    write_class_desc(f, "SYSB", sysb_offset, sysb_length);
    write_class_desc(f, "GTLB", gtlb_offset, gtlb_length);

    // SYSB class (complement1 = 0xC0000000)
    write_class_header(f, "SYSB", 1, elem_size, 0xC0000000);
    std::vector<uint8_t> sysb_elem(elem_size, 0x00);
    fwrite_raw(f, sysb_elem.data(), sysb_elem.size());

    // Pad to gtlb_offset
    uint32_t pad = gtlb_offset - (sysb_offset + 16 + elem_size);
    if (pad > 0) fwrite_zeros(f, pad);

    // GTLB class (complement1 = 1)
    write_class_header(f, "GTLB", 1, elem_size, 1);
    std::vector<uint8_t> gtlb_elem(elem_size, 0x00);
    // GTLB element: fileRef=1, unknown1=1
    put_be16(&gtlb_elem[0], 1);
    put_be16(&gtlb_elem[2], 1);
    fwrite_raw(f, gtlb_elem.data(), gtlb_elem.size());

    // Pad to 336 bytes total
    uint32_t current = gtlb_offset + 16 + elem_size;
    uint32_t target = 336;
    if (current < target) fwrite_zeros(f, target - current);
}

// Write 05CIDLST.DAT - Content ID List
static void write_05cidlst(const std::string& filepath, const std::vector<TrackInfo>& tracks) {
    size_t n = tracks.size();
    uint16_t elem_size = 0x0030;

    uint32_t class_offset = 16 + 16;
    uint32_t class_length = 16 + static_cast<uint32_t>(n) * elem_size;

    std::ofstream f(filepath, std::ios::binary | std::ios::trunc);
    write_table_header(f, "CIDL", 1);
    write_class_desc(f, "CILB", class_offset, class_length);
    write_class_header(f, "CILB", static_cast<uint16_t>(n), elem_size);

    for (const auto& track : tracks) {
        std::vector<uint8_t> elem(elem_size, 0x00);
        put_be16(&elem[0], static_cast<uint16_t>(track.track_id));
        fwrite_raw(f, elem.data(), elem.size());
    }
}

// =============================================================================
// FLAC to MP3 conversion (via ffmpeg subprocess)
// =============================================================================

static std::string convert_to_mp3(const std::string& input_path,
                                   const std::string& output_path,
                                   int bitrate) {
    std::string br_str = std::to_string(bitrate) + "k";

#ifdef _WIN32
    // Windows: use CreateProcess with stdout/stderr redirected to NUL
    std::string cmd = "ffmpeg.exe -y -i \"" + input_path + "\" -codec:a libmp3lame"
                      " -b:a " + br_str + " -ar 44100 -ac 2"
                      " -map_metadata 0 -id3v2_version 3 \"" + output_path + "\"";

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hNull = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_WRITE,
                               &sa, OPEN_EXISTING, 0, nullptr);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = hNull;
    si.hStdError = hNull;

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()),
                             nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi);
    if (!ok) {
        if (hNull != INVALID_HANDLE_VALUE) CloseHandle(hNull);
        std::cerr << "Error: failed to launch ffmpeg for " << input_path << "\n";
        std::exit(1);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (hNull != INVALID_HANDLE_VALUE) CloseHandle(hNull);

    if (exit_code != 0) {
        std::cerr << "Error: ffmpeg conversion failed for " << input_path << "\n";
        std::exit(1);
    }
#else
    // POSIX: fork + exec
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Error: fork() failed\n";
        std::exit(1);
    }

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("ffmpeg", "ffmpeg",
               "-y", "-i", input_path.c_str(),
               "-codec:a", "libmp3lame",
               "-b:a", br_str.c_str(),
               "-ar", "44100",
               "-ac", "2",
               "-map_metadata", "0",
               "-id3v2_version", "3",
               output_path.c_str(),
               nullptr);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::cerr << "Error: ffmpeg conversion failed for " << input_path << "\n";
        std::exit(1);
    }
#endif

    return output_path;
}

// =============================================================================
// File and directory utilities
// =============================================================================

// Collect audio files from paths (files or directories)
static std::vector<std::string> collect_audio_files(const std::vector<std::string>& input_paths) {
    static const std::vector<std::string> AUDIO_EXTENSIONS = {
        ".flac", ".mp3", ".wav", ".ogg", ".m4a", ".aac"
    };

    auto is_audio = [&](const std::string& path) -> bool {
        std::string ext = to_lower(fs::path(path).extension().string());
        for (const auto& ae : AUDIO_EXTENSIONS) {
            if (ext == ae) return true;
        }
        return false;
    };

    std::vector<std::string> result;

    for (const auto& p : input_paths) {
        fs::path path(p);
        if (fs::is_directory(path)) {
            // Collect all audio files from directory, sorted
            std::vector<std::string> dir_files;
            for (const auto& entry : fs::directory_iterator(path)) {
                if (entry.is_regular_file() && is_audio(entry.path().string())) {
                    dir_files.push_back(entry.path().string());
                }
            }
            std::sort(dir_files.begin(), dir_files.end());
            result.insert(result.end(), dir_files.begin(), dir_files.end());
        } else if (fs::is_regular_file(path)) {
            result.push_back(path.string());
        }
    }

    return result;
}

// Copy file (for backup restore)
static bool copy_file_binary(const std::string& src, const std::string& dst) {
    std::ifstream in(src, std::ios::binary);
    if (!in.is_open()) return false;
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;
    out << in.rdbuf();
    return true;
}

// Remove all OMA files from OMGAUDIO subdirectories
static int clean_oma_files(const std::string& omgaudio) {
    int cleaned = 0;
    for (int d = 0; d < 256; ++d) {
        std::string dir_path = (fs::path(omgaudio) / format_oma_dir(d)).string();
        if (!fs::is_directory(dir_path)) continue;
        for (const auto& entry : fs::directory_iterator(dir_path)) {
            std::string fname = to_upper(entry.path().filename().string());
            if (fname.size() > 4 && fname.substr(fname.size() - 4) == ".OMA") {
                fs::remove(entry.path());
                ++cleaned;
            }
        }
    }
    return cleaned;
}

// =============================================================================
// Temporary directory helper
// =============================================================================

class TempDir {
public:
    TempDir() {
#ifdef _WIN32
        char tmp[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp);
        char dir[MAX_PATH];
        // GetTempFileName creates a unique file; we delete it and mkdir instead
        if (GetTempFileNameA(tmp, "m3f", 0, dir) == 0) {
            std::cerr << "Error: GetTempFileName failed\n";
            std::exit(1);
        }
        DeleteFileA(dir);
        CreateDirectoryA(dir, nullptr);
        path_ = dir;
#else
        char tmpl[] = "/tmp/mp3fm_XXXXXX";
        char* result = mkdtemp(tmpl);
        if (!result) {
            std::cerr << "Error: mkdtemp failed\n";
            std::exit(1);
        }
        path_ = result;
#endif
    }

    ~TempDir() {
        try {
            fs::remove_all(path_);
        } catch (...) {}
    }

    const std::string& path() const { return path_; }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

private:
    std::string path_;
};

// =============================================================================
// Main transfer logic
// =============================================================================

static void transfer_files(const std::string& device_path,
                           const std::vector<std::string>& input_paths,
                           int bitrate) {
    std::string omgaudio = (fs::path(device_path) / OMGAUDIO_DIR).string();
    std::string dvid_path = (fs::path(device_path) / "MP3FM" / "DvID.dat").string();

    // Determine backup directory (relative to executable/CWD)
    std::string self_dir = fs::current_path().string();
    std::string backup_dir = (fs::path(self_dir) / "device_backup" / "OMGAUDIO").string();

    if (!fs::is_directory(omgaudio)) {
        std::cerr << "Error: OMGAUDIO directory not found at " << omgaudio << "\n";
        std::exit(1);
    }

    if (!fs::is_regular_file(dvid_path)) {
        std::cerr << "Error: DvID.dat not found at " << dvid_path << "\n";
        std::exit(1);
    }

    // Read device key
    uint32_t dvid_key = read_dvid(dvid_path);
    char keybuf[32];
    std::snprintf(keybuf, sizeof(keybuf), "0x%08X", dvid_key);
    std::cout << "Device key: " << keybuf << "\n";

    // Clean existing OMA files
    int cleaned = clean_oma_files(omgaudio);
    if (cleaned > 0) {
        std::cout << "Cleaned " << cleaned << " existing OMA files.\n";
    }

    // Start track IDs from 1 (clean transfer)
    int next_id = 1;
    std::cout << "Starting track ID: " << next_id << "\n";

    // Collect audio files
    auto audio_files = collect_audio_files(input_paths);
    if (audio_files.empty()) {
        std::cerr << "No audio files found.\n";
        std::exit(1);
    }

    std::cout << "\nFound " << audio_files.size() << " audio files to transfer.\n\n";

    std::vector<TrackInfo> tracks;
    TempDir tmp_dir;

    for (size_t idx = 0; idx < audio_files.size(); ++idx) {
        const auto& audio_file = audio_files[idx];
        int track_id = next_id + static_cast<int>(idx);
        int folder_num = track_id / 256;
        std::string oma_dir_name = format_oma_dir(folder_num);
        std::string oma_file_name = format_oma_file(track_id);
        std::string oma_dir_path = (fs::path(omgaudio) / oma_dir_name).string();
        std::string oma_path = (fs::path(oma_dir_path) / oma_file_name).string();

        std::string basename = fs::path(audio_file).filename().string();
        std::cout << "[" << (idx + 1) << "/" << audio_files.size() << "] " << basename << "\n";

        // Convert to MP3 if needed
        std::string ext = to_lower(fs::path(audio_file).extension().string());
        std::string mp3_path;
        if (ext == ".mp3") {
            mp3_path = audio_file;
        } else {
            std::cout << "  Converting " << ext << " -> MP3 (" << bitrate << "kbps)...\n";
            char hex_id[16];
            std::snprintf(hex_id, sizeof(hex_id), "%04x", track_id);
            mp3_path = (fs::path(tmp_dir.path()) / (std::string("track_") + hex_id + ".mp3")).string();
            convert_to_mp3(audio_file, mp3_path, bitrate);
        }

        // Read MP3 metadata
        TrackInfo info = get_mp3_info(mp3_path);
        info.track_id = track_id;
        if (info.track_num == 0) info.track_num = static_cast<int>(idx + 1);

        std::cout << "  -> " << info.title << " | " << info.artist << " | " << info.album << "\n";
        std::cout << "  Duration: " << (info.duration_ms / 1000) << "s | "
                  << "Bitrate: " << info.bitrate << "kbps | "
                  << "OMA: " << oma_dir_name << "/" << oma_file_name << "\n";

        // Create OMA file
        size_t audio_size = create_oma_file(mp3_path, oma_path, track_id, dvid_key, info);

        size_t file_size = fs::file_size(oma_path);
        std::cout << "  Written: " << file_size << " bytes "
                  << "(audio: " << audio_size << " bytes, encrypted)\n";

        tracks.push_back(info);
    }

    // Write database files
    std::cout << "\nWriting OMGAUDIO database (" << tracks.size() << " tracks)...\n";

    // Step 1: Restore non-critical DATs from backup
    std::vector<std::string> restore_from_backup = {
        "02TREINF.DAT",
        "01TREE02.DAT", "01TREE03.DAT", "01TREE04.DAT",
        "03GINF02.DAT", "03GINF03.DAT", "03GINF04.DAT",
    };

    if (fs::is_directory(backup_dir)) {
        for (const auto& fname : restore_from_backup) {
            std::string src = (fs::path(backup_dir) / fname).string();
            std::string dst = (fs::path(omgaudio) / fname).string();
            if (fs::is_regular_file(src)) {
                copy_file_binary(src, dst);
            }
        }
    } else {
        // Write empty files from scratch if no backup
        for (int i = 2; i <= 4; ++i) {
            write_01tree_empty((fs::path(omgaudio) / ("01TREE0" + std::to_string(i) + ".DAT")).string());
        }
        std::vector<std::string> empty_items;
        for (int i = 2; i <= 4; ++i) {
            write_03ginf_simple((fs::path(omgaudio) / ("03GINF0" + std::to_string(i) + ".DAT")).string(), empty_items);
        }
        write_02treinf((fs::path(omgaudio) / "02TREINF.DAT").string(), tracks);
    }

    // Step 2: Group tracks by album for tree structure
    auto albums = write_03ginf01((fs::path(omgaudio) / "03GINF01.DAT").string(), tracks);
    std::cout << "  03GINF01.DAT (ok)\n";

    std::vector<std::vector<int>> tracks_per_group;
    for (const auto& ag : albums) {
        tracks_per_group.push_back(ag.track_ids);
    }

    // Step 3: Write critical database files
    write_00gtrlst((fs::path(omgaudio) / "00GTRLST.DAT").string());
    std::cout << "  00GTRLST.DAT (ok)\n";

    write_01tree((fs::path(omgaudio) / "01TREE01.DAT").string(), tracks_per_group);
    size_t total_tree_tracks = 0;
    for (const auto& g : tracks_per_group) total_tree_tracks += g.size();
    std::cout << "  01TREE01.DAT (ok) (" << tracks_per_group.size() << " groups, "
              << total_tree_tracks << " tracks)\n";

    write_04cntinf((fs::path(omgaudio) / "04CNTINF.DAT").string(), tracks);
    std::cout << "  04CNTINF.DAT (ok)\n";

    write_05cidlst((fs::path(omgaudio) / "05CIDLST.DAT").string(), tracks);
    std::cout << "  05CIDLST.DAT (ok)\n";

    // Sync filesystem
    std::cout << "\nSyncing filesystem...\n";
#ifdef _WIN32
    // Flush the device volume
    std::string vol = "\\\\.\\";
    // Extract drive letter from device_path (e.g. "E:" or "E:\")
    if (device_path.size() >= 2 && device_path[1] == ':')
        vol += device_path.substr(0, 2);
    else
        vol += device_path;
    HANDLE hVol = CreateFileA(vol.c_str(), GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, 0, nullptr);
    if (hVol != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(hVol);
        CloseHandle(hVol);
    }
#else
    sync();
#endif

    std::cout << "\nDone! Transferred " << tracks.size() << " tracks to " << device_path << "\n";
    std::cout << "You can now safely eject the device.\n";
}

// =============================================================================
// CLI argument parsing
// =============================================================================

static void print_usage(const char* argv0) {
    std::cerr << "MP3FM - Transfer music to Sony Network Walkman (NW-E4xx/NW-HD)\n\n"
              << "Usage: " << argv0 << " <device_path> <files_or_dirs...> [-b bitrate]\n\n"
              << "Arguments:\n"
              << "  device_path    Walkman mount point (e.g. /mnt/walkman)\n"
              << "  files_or_dirs  Audio files or directories to transfer\n\n"
              << "Options:\n"
              << "  -b, --bitrate  MP3 encoding bitrate in kbps (default: 128)\n\n"
              << "Supports: MP3, FLAC, WAV, OGG, M4A, AAC (non-MP3 converted via ffmpeg)\n\n"
              << "Examples:\n"
#ifdef _WIN32
              << "  " << argv0 << " E:\\ C:\\Music\\album\\\n"
              << "  " << argv0 << " E:\\ track1.mp3 track2.flac\n"
              << "  " << argv0 << " E:\\ C:\\Music\\ -b 192\n";
#else
              << "  " << argv0 << " /mnt/walkman ~/Music/album/\n"
              << "  " << argv0 << " /mnt/walkman track1.mp3 track2.flac\n"
              << "  " << argv0 << " /mnt/walkman ~/Music/ -b 192\n";
#endif
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string device_path;
    std::vector<std::string> files;
    int bitrate = 128;

    // Parse arguments
    int i = 1;
    // First positional argument is always the device path
    device_path = argv[i++];

    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "-b" || arg == "--bitrate") {
            if (i + 1 >= argc) {
                std::cerr << "Error: -b requires a bitrate value\n";
                return 1;
            }
            try {
                bitrate = std::stoi(argv[i + 1]);
            } catch (...) {
                std::cerr << "Error: invalid bitrate: " << argv[i + 1] << "\n";
                return 1;
            }
            i += 2;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            files.push_back(arg);
            ++i;
        }
    }

    if (files.empty()) {
        std::cerr << "Error: no input files specified\n";
        print_usage(argv[0]);
        return 1;
    }

    transfer_files(device_path, files, bitrate);
    return 0;
}
