#include "scanner/FileHasher.h"

#include <fstream>
#include <cstring>

namespace ThreatOne::Scanner {

#ifdef HAS_OPENSSL

// ============================================================================
// OpenSSL EVP-based SHA256 implementation
// ============================================================================

SHA256::SHA256() : ctx_(EVP_MD_CTX_new()) {
    EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr);
}

SHA256::~SHA256() {
    EVP_MD_CTX_free(ctx_);
}

void SHA256::update(const uint8_t* data, size_t length) {
    EVP_DigestUpdate(ctx_, data, length);
}

void SHA256::update(const std::string& data) {
    update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::array<uint8_t, 32> SHA256::finalize() {
    std::array<uint8_t, 32> digest{};
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx_, digest.data(), &len);
    return digest;
}

std::array<uint8_t, 32> SHA256::hash(const uint8_t* data, size_t length) {
    SHA256 hasher;
    hasher.update(data, length);
    return hasher.finalize();
}

std::array<uint8_t, 32> SHA256::hash(const std::string& data) {
    return hash(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

#else

// ============================================================================
// Custom FIPS 180-4 SHA256 implementation (fallback)
// ============================================================================

// SHA256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
static constexpr std::array<uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Bit rotation helpers
static inline uint32_t rotr(uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32u - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static inline uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static inline uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

SHA256::SHA256()
    : state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
    , bitCount_(0)
    , buffer_{}
    , bufferLength_(0) {
}

void SHA256::processBlock(const uint8_t* block) {
    std::array<uint32_t, 64> W{};

    // Prepare the message schedule
    for (int i = 0; i < 16; ++i) {
        W[static_cast<size_t>(i)] =
            (static_cast<uint32_t>(block[static_cast<size_t>(i) * 4]) << 24) |
            (static_cast<uint32_t>(block[static_cast<size_t>(i) * 4 + 1]) << 16) |
            (static_cast<uint32_t>(block[static_cast<size_t>(i) * 4 + 2]) << 8) |
            (static_cast<uint32_t>(block[static_cast<size_t>(i) * 4 + 3]));
    }

    for (int i = 16; i < 64; ++i) {
        auto idx = static_cast<size_t>(i);
        W[idx] = gamma1(W[idx - 2]) + W[idx - 7] + gamma0(W[idx - 15]) + W[idx - 16];
    }

    // Initialize working variables
    uint32_t a = state_[0];
    uint32_t b = state_[1];
    uint32_t c = state_[2];
    uint32_t d = state_[3];
    uint32_t e = state_[4];
    uint32_t f = state_[5];
    uint32_t g = state_[6];
    uint32_t h = state_[7];

    // Compression function main loop
    for (int i = 0; i < 64; ++i) {
        auto idx = static_cast<size_t>(i);
        uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[idx] + W[idx];
        uint32_t t2 = sigma0(a) + maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add the compressed chunk to the current hash value
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void SHA256::update(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        buffer_[bufferLength_] = data[i];
        bufferLength_++;
        if (bufferLength_ == 64) {
            processBlock(buffer_.data());
            bitCount_ += 512;
            bufferLength_ = 0;
        }
    }
}

void SHA256::update(const std::string& data) {
    update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::array<uint8_t, 32> SHA256::finalize() {
    // Add remaining bit count
    bitCount_ += bufferLength_ * 8;

    // Padding
    buffer_[bufferLength_] = 0x80;
    bufferLength_++;

    if (bufferLength_ > 56) {
        // Not enough room for the length, need another block
        while (bufferLength_ < 64) {
            buffer_[bufferLength_] = 0x00;
            bufferLength_++;
        }
        processBlock(buffer_.data());
        bufferLength_ = 0;
    }

    // Pad to 56 bytes
    while (bufferLength_ < 56) {
        buffer_[bufferLength_] = 0x00;
        bufferLength_++;
    }

    // Append the bit count as big-endian 64-bit
    buffer_[56] = static_cast<uint8_t>(bitCount_ >> 56);
    buffer_[57] = static_cast<uint8_t>(bitCount_ >> 48);
    buffer_[58] = static_cast<uint8_t>(bitCount_ >> 40);
    buffer_[59] = static_cast<uint8_t>(bitCount_ >> 32);
    buffer_[60] = static_cast<uint8_t>(bitCount_ >> 24);
    buffer_[61] = static_cast<uint8_t>(bitCount_ >> 16);
    buffer_[62] = static_cast<uint8_t>(bitCount_ >> 8);
    buffer_[63] = static_cast<uint8_t>(bitCount_);

    processBlock(buffer_.data());

    // Produce the final hash value (big-endian)
    std::array<uint8_t, 32> digest{};
    for (int i = 0; i < 8; ++i) {
        auto idx = static_cast<size_t>(i);
        digest[idx * 4]     = static_cast<uint8_t>(state_[idx] >> 24);
        digest[idx * 4 + 1] = static_cast<uint8_t>(state_[idx] >> 16);
        digest[idx * 4 + 2] = static_cast<uint8_t>(state_[idx] >> 8);
        digest[idx * 4 + 3] = static_cast<uint8_t>(state_[idx]);
    }

    return digest;
}

std::array<uint8_t, 32> SHA256::hash(const uint8_t* data, size_t length) {
    SHA256 hasher;
    hasher.update(data, length);
    return hasher.finalize();
}

std::array<uint8_t, 32> SHA256::hash(const std::string& data) {
    return hash(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

#endif // HAS_OPENSSL

// BLAKE3 implementation using 7-round ChaCha-based compression and tree hashing.
// Per the BLAKE3 specification: 1024-byte chunks, 64-byte blocks, tree structure.

namespace {

// BLAKE3 IV (same as SHA-256 initial values)
constexpr std::array<uint32_t, 8> BLAKE3_IV = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// BLAKE3 message schedule permutations
constexpr std::array<std::array<uint8_t, 16>, 7> BLAKE3_MSG_SCHEDULE = {{
    {{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }},
    {{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 }},
    {{ 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 }},
    {{ 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 }},
    {{ 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 }},
    {{ 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 }},
    {{ 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 }}
}};

// Domain flags
constexpr uint32_t BLAKE3_CHUNK_START = 1;
constexpr uint32_t BLAKE3_CHUNK_END = 2;
constexpr uint32_t BLAKE3_ROOT = 8;

inline uint32_t blake3_rotr(uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32u - n));
}

// Quarter round (G function) using ChaCha-style mixing
inline void blake3_g(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d,
                     uint32_t mx, uint32_t my) {
    a = a + b + mx;
    d = blake3_rotr(d ^ a, 16);
    c = c + d;
    b = blake3_rotr(b ^ c, 12);
    a = a + b + my;
    d = blake3_rotr(d ^ a, 8);
    c = c + d;
    b = blake3_rotr(b ^ c, 7);
}

// 7-round compression function
void blake3_compress(const uint32_t cv[8], const uint32_t block[16],
                     uint64_t counter, uint32_t blockLen, uint32_t flags,
                     uint32_t out[16]) {
    uint32_t state[16] = {
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3],
        static_cast<uint32_t>(counter & 0xFFFFFFFF),
        static_cast<uint32_t>((counter >> 32) & 0xFFFFFFFF),
        blockLen,
        flags
    };

    uint32_t msg[16];
    for (int i = 0; i < 16; ++i) msg[i] = block[i];

    for (int round = 0; round < 7; ++round) {
        const auto& schedule = BLAKE3_MSG_SCHEDULE[static_cast<size_t>(round)];
        // Column rounds
        blake3_g(state[0], state[4], state[8],  state[12], msg[schedule[0]],  msg[schedule[1]]);
        blake3_g(state[1], state[5], state[9],  state[13], msg[schedule[2]],  msg[schedule[3]]);
        blake3_g(state[2], state[6], state[10], state[14], msg[schedule[4]],  msg[schedule[5]]);
        blake3_g(state[3], state[7], state[11], state[15], msg[schedule[6]],  msg[schedule[7]]);
        // Diagonal rounds
        blake3_g(state[0], state[5], state[10], state[15], msg[schedule[8]],  msg[schedule[9]]);
        blake3_g(state[1], state[6], state[11], state[12], msg[schedule[10]], msg[schedule[11]]);
        blake3_g(state[2], state[7], state[8],  state[13], msg[schedule[12]], msg[schedule[13]]);
        blake3_g(state[3], state[4], state[9],  state[14], msg[schedule[14]], msg[schedule[15]]);
    }

    for (int i = 0; i < 8; ++i) {
        out[i] = state[i] ^ state[i + 8];
        out[i + 8] = state[i + 8] ^ cv[i];
    }
}

// Compress a single 64-byte block, returning the new chaining value (first 8 words)
void blake3_compress_cv(const uint32_t cv[8], const uint32_t block[16],
                        uint64_t counter, uint32_t blockLen, uint32_t flags,
                        uint32_t newCv[8]) {
    uint32_t full[16];
    blake3_compress(cv, block, counter, blockLen, flags, full);
    for (int i = 0; i < 8; ++i) {
        newCv[i] = full[i];
    }
}

// Load a 32-bit word from bytes (little-endian)
inline uint32_t blake3_load32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

// Process a single chunk (up to 1024 bytes) and return its chaining value
void blake3_chunk_cv(const uint8_t* chunkData, size_t chunkLen,
                     const uint32_t key[8], uint64_t chunkCounter,
                     uint32_t cvOut[8]) {
    uint32_t cv[8];
    for (int i = 0; i < 8; ++i) cv[i] = key[i];

    size_t blocksInChunk = (chunkLen + 63) / 64;
    if (blocksInChunk == 0) blocksInChunk = 1;

    for (size_t bi = 0; bi < blocksInChunk; ++bi) {
        uint32_t block[16] = {};
        size_t blockStart = bi * 64;
        size_t blockBytes = std::min(size_t{64}, chunkLen > blockStart ? chunkLen - blockStart : 0);

        // Load block as little-endian words
        uint8_t blockBuf[64] = {};
        if (blockBytes > 0) {
            std::memcpy(blockBuf, chunkData + blockStart, blockBytes);
        }
        for (int w = 0; w < 16; ++w) {
            block[w] = blake3_load32(blockBuf + w * 4);
        }

        uint32_t flags = 0;
        if (bi == 0) flags |= BLAKE3_CHUNK_START;
        if (bi == blocksInChunk - 1) flags |= BLAKE3_CHUNK_END;

        blake3_compress_cv(cv, block, chunkCounter, static_cast<uint32_t>(blockBytes), flags, cv);
    }

    for (int i = 0; i < 8; ++i) cvOut[i] = cv[i];
}

// Parent compression: merges two child chaining values
void blake3_parent_cv(const uint32_t left[8], const uint32_t right[8],
                      const uint32_t key[8], uint32_t flags,
                      uint32_t cvOut[8]) {
    uint32_t block[16];
    for (int i = 0; i < 8; ++i) block[i] = left[i];
    for (int i = 0; i < 8; ++i) block[i + 8] = right[i];

    // Parent node flag = 4
    blake3_compress_cv(key, block, 0, 64, flags | 4, cvOut);
}

} // anonymous namespace

std::array<uint8_t, 32> FileHasher::blake3Hash(const uint8_t* data, size_t length) {
    constexpr size_t CHUNK_SIZE = 1024;

    uint32_t key[8];
    for (int i = 0; i < 8; ++i) key[i] = BLAKE3_IV[i];

    if (length == 0) {
        // Hash empty input: single empty chunk
        uint32_t cv[8];
        uint32_t block[16] = {};
        uint32_t flags = BLAKE3_CHUNK_START | BLAKE3_CHUNK_END | BLAKE3_ROOT;
        uint32_t full[16];
        blake3_compress(key, block, 0, 0, flags, full);
        std::array<uint8_t, 32> result{};
        for (int i = 0; i < 8; ++i) {
            result[static_cast<size_t>(i) * 4]     = static_cast<uint8_t>(full[i]);
            result[static_cast<size_t>(i) * 4 + 1] = static_cast<uint8_t>(full[i] >> 8);
            result[static_cast<size_t>(i) * 4 + 2] = static_cast<uint8_t>(full[i] >> 16);
            result[static_cast<size_t>(i) * 4 + 3] = static_cast<uint8_t>(full[i] >> 24);
        }
        return result;
    }

    // Compute chaining values for each chunk
    size_t numChunks = (length + CHUNK_SIZE - 1) / CHUNK_SIZE;
    std::vector<std::array<uint32_t, 8>> chunkCvs(numChunks);

    for (size_t ci = 0; ci < numChunks; ++ci) {
        size_t chunkStart = ci * CHUNK_SIZE;
        size_t chunkLen = std::min(CHUNK_SIZE, length - chunkStart);
        blake3_chunk_cv(data + chunkStart, chunkLen, key, ci, chunkCvs[ci].data());
    }

    // Tree hashing: merge pairs until one root remains
    if (numChunks == 1) {
        // Single chunk: re-compress with ROOT flag
        size_t chunkLen = std::min(CHUNK_SIZE, length);
        size_t blocksInChunk = (chunkLen + 63) / 64;
        if (blocksInChunk == 0) blocksInChunk = 1;

        uint32_t cv[8];
        for (int i = 0; i < 8; ++i) cv[i] = key[i];

        for (size_t bi = 0; bi < blocksInChunk; ++bi) {
            uint32_t block[16] = {};
            size_t blockStart = bi * 64;
            size_t blockBytes = std::min(size_t{64}, chunkLen > blockStart ? chunkLen - blockStart : 0);

            uint8_t blockBuf[64] = {};
            if (blockBytes > 0) {
                std::memcpy(blockBuf, data + blockStart, blockBytes);
            }
            for (int w = 0; w < 16; ++w) {
                block[w] = blake3_load32(blockBuf + w * 4);
            }

            uint32_t flags = 0;
            if (bi == 0) flags |= BLAKE3_CHUNK_START;
            if (bi == blocksInChunk - 1) flags |= BLAKE3_CHUNK_END | BLAKE3_ROOT;

            if (bi < blocksInChunk - 1) {
                blake3_compress_cv(cv, block, 0, static_cast<uint32_t>(blockBytes), flags, cv);
            } else {
                // Final block: output full 32 bytes
                uint32_t full[16];
                blake3_compress(cv, block, 0, static_cast<uint32_t>(blockBytes), flags, full);
                std::array<uint8_t, 32> result{};
                for (int i = 0; i < 8; ++i) {
                    result[static_cast<size_t>(i) * 4]     = static_cast<uint8_t>(full[i]);
                    result[static_cast<size_t>(i) * 4 + 1] = static_cast<uint8_t>(full[i] >> 8);
                    result[static_cast<size_t>(i) * 4 + 2] = static_cast<uint8_t>(full[i] >> 16);
                    result[static_cast<size_t>(i) * 4 + 3] = static_cast<uint8_t>(full[i] >> 24);
                }
                return result;
            }
        }
    }

    // Multi-chunk: binary tree merge
    while (chunkCvs.size() > 1) {
        std::vector<std::array<uint32_t, 8>> parentCvs;
        for (size_t i = 0; i < chunkCvs.size(); i += 2) {
            if (i + 1 < chunkCvs.size()) {
                std::array<uint32_t, 8> parentCv{};
                uint32_t flags = (chunkCvs.size() <= 2) ? BLAKE3_ROOT : 0;
                blake3_parent_cv(chunkCvs[i].data(), chunkCvs[i + 1].data(),
                                 key, flags, parentCv.data());
                parentCvs.push_back(parentCv);
            } else {
                parentCvs.push_back(chunkCvs[i]);
            }
        }
        chunkCvs = std::move(parentCvs);
    }

    // Convert final CV to bytes (little-endian)
    std::array<uint8_t, 32> result{};
    for (int i = 0; i < 8; ++i) {
        result[static_cast<size_t>(i) * 4]     = static_cast<uint8_t>(chunkCvs[0][static_cast<size_t>(i)]);
        result[static_cast<size_t>(i) * 4 + 1] = static_cast<uint8_t>(chunkCvs[0][static_cast<size_t>(i)] >> 8);
        result[static_cast<size_t>(i) * 4 + 2] = static_cast<uint8_t>(chunkCvs[0][static_cast<size_t>(i)] >> 16);
        result[static_cast<size_t>(i) * 4 + 3] = static_cast<uint8_t>(chunkCvs[0][static_cast<size_t>(i)] >> 24);
    }
    return result;
}

std::string FileHasher::toHex(const std::array<uint8_t, 32>& bytes) {
    static constexpr char hexChars[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (auto byte : bytes) {
        result.push_back(hexChars[(byte >> 4) & 0x0F]);
        result.push_back(hexChars[byte & 0x0F]);
    }
    return result;
}

Core::Result<std::string, Core::Error> FileHasher::hashFile(
    const std::filesystem::path& filePath,
    HashAlgorithm algorithm) {

    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec)) {
        return Core::Result<std::string, Core::Error>::err(
            Core::Error("File not found: " + filePath.string(), Core::ErrorCategory::IO));
    }

    if (!std::filesystem::is_regular_file(filePath, ec)) {
        return Core::Result<std::string, Core::Error>::err(
            Core::Error("Not a regular file: " + filePath.string(), Core::ErrorCategory::IO));
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return Core::Result<std::string, Core::Error>::err(
            Core::Error("Cannot open file: " + filePath.string(), Core::ErrorCategory::IO));
    }

    constexpr size_t chunkSize = 8192;
    std::array<char, chunkSize> buffer{};

    if (algorithm == HashAlgorithm::SHA256) {
        SHA256 hasher;
        while (file.read(buffer.data(), static_cast<std::streamsize>(chunkSize)) || file.gcount() > 0) {
            hasher.update(reinterpret_cast<const uint8_t*>(buffer.data()),
                         static_cast<size_t>(file.gcount()));
            if (file.eof()) break;
        }
        return Core::Result<std::string, Core::Error>::ok(toHex(hasher.finalize()));
    } else {
        // BLAKE3: read entire file then hash with tree structure
        std::vector<uint8_t> fileData;
        file.seekg(0, std::ios::end);
        auto fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        if (fileSize > 0) {
            fileData.resize(static_cast<size_t>(fileSize));
            file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
        }
        return Core::Result<std::string, Core::Error>::ok(
            toHex(blake3Hash(fileData.data(), fileData.size())));
    }
}

Core::Result<std::string, Core::Error> FileHasher::hashBuffer(
    const std::vector<uint8_t>& data,
    HashAlgorithm algorithm) {

    if (algorithm == HashAlgorithm::SHA256) {
        auto digest = SHA256::hash(data.data(), data.size());
        return Core::Result<std::string, Core::Error>::ok(toHex(digest));
    } else {
        return Core::Result<std::string, Core::Error>::ok(
            toHex(blake3Hash(data.data(), data.size())));
    }
}

Core::Result<std::string, Core::Error> FileHasher::hashString(
    const std::string& data,
    HashAlgorithm algorithm) {

    if (algorithm == HashAlgorithm::SHA256) {
        auto digest = SHA256::hash(data);
        return Core::Result<std::string, Core::Error>::ok(toHex(digest));
    } else {
        return Core::Result<std::string, Core::Error>::ok(
            toHex(blake3Hash(reinterpret_cast<const uint8_t*>(data.data()), data.size())));
    }
}

} // namespace ThreatOne::Scanner
