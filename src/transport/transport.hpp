#pragma once

#include <vector>
#include <array>
#include <cstdint>
#include <openssl/evp.h>

#include "socket/socket.hpp"

class Transport {

public:
    Transport(Socket& sock);
    ~Transport();

    //prevent accidental copying - due to OpenSSL pointers
    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;

    void send_packet(const std::vector<uint8_t>& payload);

    std::vector<uint8_t> receive_packet();

    void enable_outgoing_encryption(const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 32>& encryption_key, const std::array<uint8_t, 32>& mac_key);
    void enable_incoming_encryption(const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 32>& encryption_key, const std::array<uint8_t, 32>& mac_key);

private:

    static constexpr std::size_t packet_length_bytes = 4;

    uint32_t decode_packet_length(const std::array<uint8_t, packet_length_bytes>& length_bytes) const;
    void validate_packet_length(uint32_t packet_length) const;
    void validate_packet_padding(uint32_t packet_length, uint8_t padding_length) const;

    std::size_t calculate_padding_length(std::size_t payload_size) const;
    std::array<uint8_t, packet_length_bytes> encode_packet_length(uint32_t packet_length) const;
    void validate_payload_size(std::size_t payload_size) const;
    std::vector<uint8_t> generate_padding(std::size_t padding_length) const;

    Socket& sock_;
    uint32_t incoming_sequence_;
    uint32_t outgoing_sequence_;

    bool outgoing_encryption_active_;
    bool incoming_encryption_active_;

    EVP_CIPHER_CTX* outgoing_cipher_;
    EVP_CIPHER_CTX* incoming_cipher_;

    std::array<uint8_t, 32> outgoing_mac_key_;
    std::array<uint8_t, 32> incoming_mac_key_;  

};