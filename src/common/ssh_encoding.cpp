#include "common/ssh_encoding.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <cstdint>

namespace {
constexpr std::size_t bits_per_byte = 8;
}

namespace ssh_encoding {

std::array<uint8_t, uint32_bytes> encode_uint32(uint32_t value) {
    std::array<uint8_t, uint32_bytes> encoded{};
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        encoded[i] = static_cast<uint8_t>(value >> ((encoded.size() - 1 - i) * bits_per_byte));
    }
    return encoded;
}

uint32_t decode_uint32(const std::array<uint8_t, uint32_bytes>& bytes) {
    uint32_t value = 0;
    for (uint8_t byte : bytes) {
        value = (value << bits_per_byte) | static_cast<uint32_t>(byte);
    }
    return value;
}

void append_string(std::vector<uint8_t>& destination, const std::vector<uint8_t>& value) {
    if (value.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("SSH string is too long");
    }
    const auto length = encode_uint32(static_cast<uint32_t>(value.size()));
    destination.insert(destination.end(), length.begin(), length.end());
    destination.insert(destination.end(), value.begin(), value.end());
}

void append_string(std::vector<uint8_t>& destination, const std::string& value) {
    if (value.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("SSH string is too long");
    }
    const auto length = encode_uint32(static_cast<uint32_t>(value.size()));
    destination.insert(destination.end(), length.begin(), length.end());
    destination.insert(destination.end(), value.begin(), value.end());
}

std::vector<uint8_t> read_string(const std::vector<uint8_t>& payload, std::size_t& position) {
    if (position > payload.size() || payload.size() - position < uint32_bytes) {
        throw std::runtime_error("Expected SSH string length");
    }
    std::array<uint8_t, uint32_bytes> length_bytes{};
    std::copy_n(payload.begin() + position, length_bytes.size(), length_bytes.begin());
    const uint32_t length = decode_uint32(length_bytes);
    position += uint32_bytes;

    if (position > payload.size() || payload.size() - position < length) {
        throw std::runtime_error("Expected SSH string bytes");
    }
    std::vector<uint8_t> result(payload.begin() + position, payload.begin() + position + length);
    position += length;
    return result;
}

}
