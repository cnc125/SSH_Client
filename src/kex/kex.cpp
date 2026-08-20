#include "kex.hpp"
#include <stdexcept>
#include <cstddef>
#include <array>
#include <algorithm>
#include <string>
#include <iostream>
#include <sodium.h>
#include <limits>
#include <sstream>

namespace {
    constexpr std::size_t bits_per_byte = 8;
    constexpr std::size_t length_of_key = 32;
    constexpr std::size_t SSH_MSG_KEX_ECDH_INIT = 30;
}

KexInit Kex::parse_kexinit(const std::vector<uint8_t>& payload) {
    KexInit result{};
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

    result.raw_payload = payload;

    //obtain cookie bytes
    std::array<uint8_t, cookie_bytes> cookie{};
    std::copy_n(payload.begin() + position, cookie.size(), cookie.begin());
    position += cookie_bytes;
    result.cookie = cookie;

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

    result.kex_algorithms = kex_algorithms;
    result.host_key_algorithms = host_key_algorithms;
    result.encryption_cs_algorithms = encryption_cs_algorithms;
    result.encryption_sc_algorithms = encryption_sc_algorithms;
    result.mac_cs_algorithms = mac_cs_algorithms;
    result.mac_sc_algorithms = mac_sc_algorithms;
    result.compression_cs_algorithms = compression_cs_algorithms;
    result.compression_sc_algorithms = compression_sc_algorithms;
    result.languages_cs = languages_cs;
    result.languages_sc = languages_sc;
    result.first_kex_packet_follows = first_kex_packet_follows;

    return result;

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

KexInit Kex::create_client_kexinit() {
    KexInit result{};
    std::array<uint8_t, cookie_bytes> cookie{};
    randombytes_buf(cookie.data(), cookie.size());
    result.cookie = cookie;
    result.kex_algorithms = "curve25519-sha256";
    result.host_key_algorithms = "ssh-ed25519";
    result.encryption_cs_algorithms = "aes256-ctr";
    result.encryption_sc_algorithms = "aes256-ctr";
    result.mac_cs_algorithms = "hmac-sha2-256";
    result.mac_sc_algorithms = "hmac-sha2-256";
    result.compression_cs_algorithms = "none";
    result.compression_sc_algorithms = "none";
    result.languages_cs = "";
    result.languages_sc = "";
    result.first_kex_packet_follows = false;

    std::vector<uint8_t>& raw_payload = result.raw_payload;
    raw_payload.push_back(20);
    raw_payload.insert(raw_payload.end(), cookie.begin(), cookie.end());
    append_name_list(raw_payload, result.kex_algorithms);
    append_name_list(raw_payload, result.host_key_algorithms);
    append_name_list(raw_payload, result.encryption_cs_algorithms);
    append_name_list(raw_payload, result.encryption_sc_algorithms);
    append_name_list(raw_payload, result.mac_cs_algorithms);
    append_name_list(raw_payload, result.mac_sc_algorithms);
    append_name_list(raw_payload, result.compression_cs_algorithms);
    append_name_list(raw_payload, result.compression_sc_algorithms);
    append_name_list(raw_payload, result.languages_cs);
    append_name_list(raw_payload, result.languages_sc);
    raw_payload.push_back(result.first_kex_packet_follows);
    auto reserved = encode_uint32(0);
    raw_payload.insert(raw_payload.end(), reserved.begin(), reserved.end());
    return result;
}

std::array<uint8_t, Kex::uint32_bytes> Kex::encode_uint32(uint32_t length) const {
    std::array<uint8_t, uint32_bytes> encoded;
    for (size_t i = 0; i<uint32_bytes; i++) {
        encoded[i] = uint8_t(length >> ((uint32_bytes - 1 - i) * bits_per_byte));
    }
    return encoded;
}

void Kex::append_name_list(std::vector<uint8_t>& payload, const std::string& list) const {
    if (list.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("Length doesn't bit into 32 bits");
    }
    uint32_t length = uint32_t(list.size());
    std::array<uint8_t, Kex::uint32_bytes> length_array = encode_uint32(length);

    //add the length
    payload.insert(payload.end(), length_array.begin(), length_array.end());
    //add the algorithms
    payload.insert(payload.end(), list.begin(), list.end());
}

std::string Kex::choose_algorithm(const std::string& client_list, const std::string& server_list) const{
    //first split by commas
    std::stringstream cs(client_list);
    std::string item;
    std::vector<std::string> client;

    while (std::getline(cs, item, ',')) {
        client.push_back(item);
    }

    std::stringstream ss(server_list);
    std::vector<std::string> server;

    while (std::getline(ss, item, ',')) {
        server.push_back(item);
    }

    for (const auto& c : client) {
        for (const auto& s : server) {
            if (c == s) {
                return c;
            }
        }
    }
    throw std::runtime_error("No mutually supported SSH algorithm");
}

NegotiatedAlgorithms Kex::negotiate(const KexInit& client, const KexInit& server) const {
    NegotiatedAlgorithms algorithms;
    algorithms.kex_algorithm = choose_algorithm(client.kex_algorithms, server.kex_algorithms);
    algorithms.host_key_algorithm = choose_algorithm(client.host_key_algorithms, server.host_key_algorithms);
    algorithms.encryption_cs_algorithm = choose_algorithm(client.encryption_cs_algorithms, server.encryption_cs_algorithms);
    algorithms.encryption_sc_algorithm = choose_algorithm(client.encryption_sc_algorithms, server.encryption_sc_algorithms);
    algorithms.mac_cs_algorithm = choose_algorithm(client.mac_cs_algorithms, server.mac_cs_algorithms);
    algorithms.mac_sc_algorithm = choose_algorithm(client.mac_sc_algorithms, server.mac_sc_algorithms);
    algorithms.compression_cs_algorithm = choose_algorithm(client.compression_cs_algorithms, server.compression_cs_algorithms);
    algorithms.compression_sc_algorithm = choose_algorithm(client.compression_sc_algorithms, server.compression_sc_algorithms);
    return algorithms;
}

Curve25519State Kex::create_curve25519_keypair() const {
    Curve25519State state{};

    randombytes_buf(state.client_private_key.data(), state.client_private_key.size());

    const auto result = crypto_scalarmult_curve25519_base(state.client_public_key.data(), state.client_private_key.data());
    if (result != 0) {
        throw std::runtime_error("Curve25519 algorithm failed to generate keys");
    }

    return state;
}

std::vector<uint8_t> Kex::create_ecdh_init_payload(const Curve25519State& state) const {
    std::vector<uint8_t> payload{};
    payload.push_back(SSH_MSG_KEX_ECDH_INIT); 
    const auto length = encode_uint32(uint32_t(length_of_key));
    payload.insert(payload.end(), length.begin(), length.end());
    payload.insert(payload.end(), state.client_public_key.begin(), state.client_public_key.end());
    return payload;
}

std::vector<uint8_t> Kex::read_binary_string(const std::vector<uint8_t>& payload, std::size_t& position) const {
    if (position > payload.size()) {
        throw std::runtime_error("Position is outside SSH payload");
    }
    if (payload.size() - position < uint32_bytes) {
        throw std::runtime_error("Expected string length");
    }
    std::array<uint8_t, uint32_bytes> length{};
    std::copy_n(payload.begin() + position, length.size(), length.begin());
    uint32_t string_length = read_uint32(length);
    position += uint32_bytes;
    
    if (position > payload.size()) {
        throw std::runtime_error("Position is outside SSH payload");
    }
    if (payload.size() - position < string_length) {
        throw std::runtime_error("Expected string");
    }
    std::vector<uint8_t> result(payload.begin() + position, payload.begin() + position + string_length);
    position += string_length;
    return result;
}

EcdhReply Kex::parse_ecdh_reply(const std::vector<uint8_t>& payload) const {
    EcdhReply result{};
    if (payload.size() < 1) {
        throw std::runtime_error("Payload should not be empty");
    }
    if (payload[0] != 31) {
        throw std::runtime_error("SSH_MSG_KEX_ECDH_REPLY packet was expected");
    }

    size_t position = 1;

    result.server_host_key = read_binary_string(payload, position);
    std::vector<uint8_t> server_public_key = read_binary_string(payload, position);
    if (server_public_key.size() != result.server_public_key.size()) {
        throw std::runtime_error("Curve25519 server public key must be 32 bytes");
    }
    std::copy(server_public_key.begin(), server_public_key.end(), result.server_public_key.begin());
    result.signature = read_binary_string(payload, position);

    if (position != payload.size()) {
        throw std::runtime_error("No more bytes expected");
    }

    return result;
}

void Kex::calculate_shared_secret(Curve25519State& state, const std::array<uint8_t, 32>& server_public_key) const {
    auto result = crypto_scalarmult_curve25519(state.shared_secret.data(), state.client_private_key.data(), server_public_key.data());
    if (result == -1) {
        throw std::runtime_error("Invalid server public key");
    }
}