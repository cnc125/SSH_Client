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
    std::string kex_algorithms = read_name_list(payload, position);
    std::string host_key_algorithms = read_name_list(payload, position);
    std::string encryption_cs_algorithms = read_name_list(payload, position);
    std::string encryption_sc_algorithms = read_name_list(payload, position);
    std::string mac_cs_algorithms = read_name_list(payload, position);
    std::string mac_sc_algorithms = read_name_list(payload, position);
    std::string compression_cs_algorithms = read_name_list(payload, position);
    std::string compression_sc_algorithms = read_name_list(payload, position);
    std::string languages_cs = read_name_list(payload, position);
    std::string languages_sc = read_name_list(payload, position);

    std::cout << "KEXINIT\n";
    std::cout << "Kex Algorithms: " << kex_algorithms << "\n";
    std::cout << "Host Key Algorithms: " << host_key_algorithms << "\n";
    std::cout << "Encryption Algorithms, client → server: " << encryption_cs_algorithms << "\n";
    std::cout << "Encryption Algorithms, server → client: " << encryption_sc_algorithms << "\n";
    std::cout << "MAC client → server: " << mac_cs_algorithms << "\n";
    std::cout << "MAC server → client: " << mac_sc_algorithms << "\n";
    std::cout << "Compression client → server: " << compression_cs_algorithms << "\n";
    std::cout << "Compression server → client: " << compression_sc_algorithms << "\n";
    std::cout << "Languages client → server: " << languages_cs << "\n";
    std::cout << "Languages server → client: " << languages_sc << "\n";

    //get first_kex_packet_follows
    bool first_kex_packet_follows = parse_boolean(payload, position);
    std::cout << "First kex packet follows: " << first_kex_packet_follows << "\n";

    //reserved bytes
    if (payload.size() - position < uint32_bytes) {
        throw std::runtime_error("4 reserved bytes expected");
    }
    std::array<uint8_t, uint32_bytes> reserved{};
    std::copy_n(payload.begin() + position, reserved.size(), reserved.begin());
    uint32_t reserved_value = read_uint32(reserved);
    position += uint32_bytes;
    if (reserved_value != 0) {
        throw std::runtime_error("Reserved bytes expected to be equal to 0");
    }

    //final check
    if (payload.size() != position) {
        throw std::runtime_error("Additional bytes not expected");
    }

}

uint32_t Kex::read_uint32(const std::array<uint8_t, uint32_bytes>& length_bytes) const {
    uint32_t acc = 0;
    for (uint8_t byte : length_bytes) {
        acc = (acc << bits_per_byte) | uint32_t(byte);
    }
    return acc;
}

std::string Kex::read_name_list(const std::vector<uint8_t>& payload, std::size_t& position) const {
    if (position > payload.size()) {
        throw std::runtime_error("SSH Payload missing expected bytes");
    }
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
    return list_text;
}

bool Kex::parse_boolean(const std::vector<uint8_t>& payload, std::size_t& position) const {
    if (position > payload.size()) {
        throw std::runtime_error("SSH Payload missing expected bytes");
    }
    if (payload.size() - position < 1) {
        throw std::runtime_error("Expected 1 byte");
    }

    bool result = payload[position] != 0;
    position++;
    return result;
}