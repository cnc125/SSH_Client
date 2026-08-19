#include "kex.hpp"
#include <stdexcept>
#include <cstddef>
#include <array>
#include <algorithm>
#include <string>
#include <iostream>

namespace {
    constexpr std::size_t cookie_bytes = 16;
    constexpr std::size_t bits_per_byte = 8;
}

void Kex::parse_kexinit(const std::vector<uint8_t>& payload) {
    if (payload.size() < 1) {
        throw std::runtime_error("Payload should not be empty");
    }
    if (payload[0] != 20) {
        throw std::runtime_error("SSH KEXINIT packet was expected");
    }

    size_t position = 1;

    if (payload.size() - position < cookie_bytes) {
        throw std::runtime_error("Payload should contain a cookie");
    }

    //obtain cookie bytes
    std::array<uint8_t, cookie_bytes> cookie{};
    std::copy_n(payload.begin() + position, cookie.size(), cookie.begin());
    position += cookie_bytes;

    //get lists
    if (payload.size() - position < uint32_bytes) {
        throw std::runtime_error("Expected list length");
    }
    std::array<uint8_t, uint32_bytes> length{};
    std::copy_n(payload.begin() + position, length.size(), length.begin());
    uint32_t list_length = read_uint32(length);
    position += uint32_bytes;
    
    if (payload.size() - position < list_length) {
        throw std::runtime_error("Expected list");
    }
    std::string list_text(payload.begin() + position, payload.begin() + position + list_length);
    position += list_length;
    std::cout << "KEXINIT\n";
    std::cout << "List Length: " << list_length << "\n";
    std::cout << "List contents: " << list_text;
}

uint32_t Kex::read_uint32(const std::array<uint8_t, uint32_bytes>& length_bytes) const {
    uint32_t acc = 0;
    for (uint8_t byte : length_bytes) {
        acc = (acc << bits_per_byte) | uint32_t(byte);
    }
    return acc;
}