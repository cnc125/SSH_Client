#pragma once

#include <vector>
#include <cstdint>
#include <array>
#include <string>
#include <cstddef>

// Parsed and encoded fields of an SSH_MSG_KEXINIT payload
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

// Algorithms selected from the client and server KEXINIT lists
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

// Ephemeral Curve25519 key pair and its derived shared secret
struct Curve25519State {
    std::array<uint8_t, 32> client_private_key;
    std::array<uint8_t, 32> client_public_key;
    std::array<uint8_t, 32> shared_secret;
};

// Parsed fields of SSH_MSG_KEX_ECDH_REPLY
struct EcdhReply {
    std::vector<uint8_t> server_host_key;
    std::array<uint8_t, 32> server_public_key;
    std::vector<uint8_t> signature;
};

// Ed25519 public key and signature extracted from the KEX reply
struct Ed25519VerificationData {
    std::array<uint8_t, 32> public_key;
    std::array<uint8_t, 64> signature;
};

// Direction-specific IVs, encryption keys, and MAC keys for transport
struct TransportKeyMaterial {
    std::array<uint8_t, 16> iv_cs;
    std::array<uint8_t, 16> iv_sc;
    
    std::array<uint8_t, 32> encryption_key_cs;
    std::array<uint8_t, 32> encryption_key_sc;

    std::array<uint8_t, 32> mac_key_cs;
    std::array<uint8_t, 32> mac_key_sc;
};

// Performs SSH algorithm negotiation, key exchange, and key derivation
class Kex {
public:
    // Parses and validates an SSH_MSG_KEXINIT payload
    KexInit parse_kexinit(const std::vector<uint8_t>& payload);
    // Creates this client's SSH_MSG_KEXINIT payload and algorithm lists
    KexInit create_client_kexinit();
    // Selects the first mutually supported algorithm in each category
    NegotiatedAlgorithms negotiate(const KexInit& client, const KexInit& server) const;
    // Generates an ephemeral Curve25519 key pair
    Curve25519State create_curve25519_keypair() const;
    // Creates SSH_MSG_KEX_ECDH_INIT containing the client public key
    std::vector<uint8_t> create_ecdh_init_payload(const Curve25519State& state) const;
    // Parses the server host key, ephemeral public key, and signature
    EcdhReply parse_ecdh_reply(const std::vector<uint8_t>& payload) const;
    // Derives and stores the Curve25519 shared secret
    void calculate_shared_secret(Curve25519State& state, const std::array<uint8_t, 32>& server_public_key) const;

    // Calculates the SSH exchange hash over both parties' handshake data
    std::array<uint8_t, 32> calculate_exchange_hash(const std::string& client_identification, const std::string& server_identification,
    const KexInit& client_kexinit, const KexInit& server_kexinit, const Curve25519State& curve_state,
    const EcdhReply& ecdh_reply) const;

    // Extracts Ed25519 verification material from the server reply
    Ed25519VerificationData parse_ed25519_verification_data(const EcdhReply& reply, const std::string& negotiated_host_key_algorithm) const;
    // Verifies that the server host key signed the exchange hash
    void verify_ed25519_signature(const Ed25519VerificationData& data, const std::array<uint8_t, 32>& exchange_hash) const;

    // Calculates the SHA-256 fingerprint of the encoded server host key
    std::array<uint8_t, 32> calculate_host_key_fingerprint(const std::vector<uint8_t>& server_host_key) const;
    // Derives all direction-specific transport keys from K, H, and session ID
    TransportKeyMaterial derive_transport_keys(const std::array<uint8_t, 32>& shared_secret, const std::array<uint8_t, 32>& exchange_hash, const std::array<uint8_t, 32>& session_id) const;
private:
    // Helpers for SSH KEX field parsing and encoding
    static constexpr std::size_t uint32_bytes = 4;
    static constexpr std::size_t cookie_bytes = 16;

    std::string read_name_list(const std::vector<uint8_t>& payload, std::size_t& position) const;
    bool parse_boolean(const std::vector<uint8_t>& payload, std::size_t& position) const;

    void append_name_list(std::vector<uint8_t>& payload, const std::string& list) const;

    // Chooses the first client-preferred algorithm also offered by the server
    std::string choose_algorithm(const std::string& client_list, const std::string& server_list) const;

    // Appends a positive SSH mpint representation of a 32-byte value
    void append_positive_mpint(std::vector<uint8_t>& destination, const std::array<uint8_t, 32>& value) const;

    // Derives one RFC 4253 key stream identified by its direction letter
    std::array<uint8_t, 32> derive_key_material(const std::array<uint8_t, 32>& shared_secret, const std::array<uint8_t, 32>& exchange_hash, uint8_t letter, const std::array<uint8_t, 32>& session_id) const;

};

