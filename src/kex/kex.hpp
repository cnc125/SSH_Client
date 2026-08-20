#pragma once

#include <vector>
#include <cstdint>
#include <array>
#include <string>
#include <cstddef>

struct KexInit {
    std::vector<uint8_t> raw_payload;
    std::array<uint8_t, 16> cookie;
    std::string kex_algorithms;
    std::string host_key_algorithms;
    std::string encryption_cs_algorithms;
    std::string encryption_sc_algorithms;
    std::string mac_cs_algorithms;
    std::string mac_sc_algorithms;
    std::string compression_cs_algorithms;
    std::string compression_sc_algorithms;
    std::string languages_cs;
    std::string languages_sc;
    bool first_kex_packet_follows;
};

struct NegotiatedAlgorithms {
    std::string kex_algorithm;
    std::string host_key_algorithm;
    std::string encryption_cs_algorithm;
    std::string encryption_sc_algorithm;
    std::string mac_cs_algorithm;
    std::string mac_sc_algorithm;
    std::string compression_cs_algorithm;
    std::string compression_sc_algorithm;
};

struct Curve25519State {
    std::array<uint8_t, 32> client_private_key;
    std::array<uint8_t, 32> client_public_key;
};

class Kex {
public:
    KexInit parse_kexinit(const std::vector<uint8_t>& payload);
    KexInit create_client_kexinit();
    NegotiatedAlgorithms negotiate(const KexInit& client, const KexInit& server) const;
    Curve25519State create_curve25519_keypair() const;
    std::vector<uint8_t> create_ecdh_init_payload(const Curve25519State& state) const;

private:
    static constexpr std::size_t uint32_bytes = 4;
    static constexpr std::size_t cookie_bytes = 16;

    uint32_t read_uint32(const std::array<uint8_t, uint32_bytes>& length_bytes) const;
    std::string read_name_list(const std::vector<uint8_t>& payload, std::size_t& position) const;
    bool parse_boolean(const std::vector<uint8_t>& payload, std::size_t& position) const;
    std::array<uint8_t, uint32_bytes> encode_uint32(uint32_t length) const;

    void append_name_list(std::vector<uint8_t>& payload, const std::string& list) const;

    std::string choose_algorithm(const std::string& client_list, const std::string& server_list) const;
};

