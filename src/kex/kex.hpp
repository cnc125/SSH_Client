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
    std::array<uint8_t, 32> shared_secret;
};

struct EcdhReply {
    std::vector<uint8_t> server_host_key;
    std::array<uint8_t, 32> server_public_key;
    std::vector<uint8_t> signature;
};

struct Ed25519VerificationData {
    std::array<uint8_t, 32> public_key;
    std::array<uint8_t, 64> signature;
};

struct TransportKeyMaterial {
    std::array<uint8_t, 16> iv_cs;
    std::array<uint8_t, 16> iv_sc;
    
    std::array<uint8_t, 32> encryption_key_cs;
    std::array<uint8_t, 32> encryption_key_sc;

    std::array<uint8_t, 32> mac_key_cs;
    std::array<uint8_t, 32> mac_key_sc;
};

class Kex {
public:
    KexInit parse_kexinit(const std::vector<uint8_t>& payload);
    KexInit create_client_kexinit();
    NegotiatedAlgorithms negotiate(const KexInit& client, const KexInit& server) const;
    Curve25519State create_curve25519_keypair() const;
    std::vector<uint8_t> create_ecdh_init_payload(const Curve25519State& state) const;
    EcdhReply parse_ecdh_reply(const std::vector<uint8_t>& payload) const;
    void calculate_shared_secret(Curve25519State& state, const std::array<uint8_t, 32>& server_public_key) const;

    std::array<uint8_t, 32> calculate_exchange_hash(const std::string& client_identification, const std::string& server_identification,
    const KexInit& client_kexinit, const KexInit& server_kexinit, const Curve25519State& curve_state,
    const EcdhReply& ecdh_reply) const;

    Ed25519VerificationData parse_ed25519_verification_data(const EcdhReply& reply, const std::string& negotiated_host_key_algorithm) const;
    void verify_ed25519_signature(const Ed25519VerificationData& data, const std::array<uint8_t, 32>& exchange_hash) const;

    std::array<uint8_t, 32> calculate_host_key_fingerprint(const std::vector<uint8_t>& server_host_key) const;
    TransportKeyMaterial derive_transport_keys(const std::array<uint8_t, 32>& shared_secret, const std::array<uint8_t, 32>& exchange_hash, const std::array<uint8_t, 32>& session_id) const;
private:
    static constexpr std::size_t uint32_bytes = 4;
    static constexpr std::size_t cookie_bytes = 16;

    uint32_t read_uint32(const std::array<uint8_t, uint32_bytes>& length_bytes) const;
    std::string read_name_list(const std::vector<uint8_t>& payload, std::size_t& position) const;
    bool parse_boolean(const std::vector<uint8_t>& payload, std::size_t& position) const;
    std::array<uint8_t, uint32_bytes> encode_uint32(uint32_t length) const;

    void append_name_list(std::vector<uint8_t>& payload, const std::string& list) const;

    std::string choose_algorithm(const std::string& client_list, const std::string& server_list) const;
    std::vector<uint8_t> read_binary_string(const std::vector<uint8_t>& payload, std::size_t& position) const;

    void append_binary_string(std::vector<uint8_t>& destination, const std::vector<uint8_t>& value) const;
    void append_binary_string(std::vector<uint8_t>& destination, const std::string& value) const;
    void append_positive_mpint(std::vector<uint8_t>& destination, const std::array<uint8_t, 32>& value) const;

    std::array<uint8_t, 32> derive_key_material(const std::array<uint8_t, 32>& shared_secret, const std::array<uint8_t, 32>& exchange_hash, uint8_t letter, const std::array<uint8_t, 32>& session_id) const;

};

