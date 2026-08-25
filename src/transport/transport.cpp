#include "transport.hpp"
#include "common/ssh_encoding.hpp"
#include <stdexcept>
#include <cstddef>
#include <limits>
#include <cstdint>
#include <sodium.h>
#include <algorithm>

namespace {

    constexpr std::size_t bits_per_byte = 8;
    constexpr std::size_t min_packet_size = 16;
    constexpr std::size_t max_packet_size = 35000;
    constexpr std::size_t block_size = 8;
    constexpr std::size_t aes_block_size = 16;
    constexpr std::size_t min_padding_length = 4;
    constexpr std::size_t min_payload_bytes = 1;
    constexpr std::size_t padding_length_bytes = 1;
}

Transport::Transport(Socket& sock) : sock_(sock), incoming_sequence_(0), outgoing_sequence_(0), outgoing_encryption_active_(false), incoming_encryption_active_(false), outgoing_cipher_(nullptr), incoming_cipher_(nullptr) {
}

Transport::~Transport() {
    EVP_CIPHER_CTX_free(outgoing_cipher_);
    EVP_CIPHER_CTX_free(incoming_cipher_);
}

//this method converts the length from big-endian order to a numerical value
uint32_t Transport::decode_packet_length(const std::array<uint8_t, packet_length_bytes>& length_bytes) const {
    uint32_t acc = 0;
    for (uint8_t byte : length_bytes) {
        acc = (acc << bits_per_byte) | uint32_t(byte);
    }
    return acc;
}

//checks that the packet length is valid and that the packet is aligned
void Transport::validate_packet_length(uint32_t packet_length) const {
    //packet length minimum size
    if (packet_length < min_packet_size - packet_length_bytes) {
        throw std::runtime_error("SSH packet length is below minimum");
    }

    //packet length maximum size
    if (packet_length + packet_length_bytes > max_packet_size) {
        throw std::runtime_error("SSH packet length is above maximum");
    }

    //packet alignment
    if ((packet_length + packet_length_bytes) % (incoming_encryption_active_ ? aes_block_size : block_size) != 0) {
        throw std::runtime_error("SSH packet is not aligned");
    }
}

//check validity of packet padding
void Transport::validate_packet_padding(uint32_t packet_length, uint8_t padding_length) const {
    if (padding_length < min_padding_length) {
        throw std::runtime_error("SSH packet does not have the minimum amount of padding required");
    }

    if (padding_length + padding_length_bytes + min_payload_bytes > packet_length) {
        throw std::runtime_error("SSH packet does not contain the correct amount of padding");
    }
}

//handles receiving packets
std::vector<uint8_t> Transport::receive_packet() {

    if (!incoming_encryption_active_) {
        //get the length bytes
        std::array<uint8_t, packet_length_bytes> length_bytes;
        sock_.read_exact(length_bytes.data(), length_bytes.size());

        //decode and verify length
        uint32_t packet_length = decode_packet_length(length_bytes);
        validate_packet_length(packet_length);

        //obtain the packet's body
        std::vector<uint8_t> pbody(packet_length);
        sock_.read_exact(pbody.data(), pbody.size());

        //obtain padding length and check validity
        uint8_t padding_length = pbody[0];
        validate_packet_padding(packet_length, padding_length);

        std::size_t payload_length = packet_length - padding_length_bytes - padding_length;
        std::vector<uint8_t> payload(pbody.begin() + 1, pbody.begin() + 1 + payload_length);
    
        incoming_sequence_++;
        return payload;
    } else {
        std::vector<uint8_t> ciphertext(aes_block_size);
        sock_.read_exact(ciphertext.data(), ciphertext.size());

        std::vector<uint8_t> plaintext_bytes = decrypt_incoming_bytes(ciphertext);

        std::array<uint8_t, packet_length_bytes> length_bytes;
        std::copy_n(plaintext_bytes.begin(), 4, length_bytes.begin());
        uint32_t packet_length = decode_packet_length(length_bytes);
        validate_packet_length(packet_length);

        uint32_t total_encrypted_bytes = packet_length_bytes + packet_length;
        uint32_t remaining_bytes = total_encrypted_bytes - aes_block_size;

        std::vector<uint8_t> remaining_ciphertext(remaining_bytes);
        sock_.read_exact(remaining_ciphertext.data(), remaining_ciphertext.size());
        std::vector<uint8_t> remaining_plaintext_bytes = decrypt_incoming_bytes(remaining_ciphertext);

        std::vector<uint8_t> plaintext_packet;
        plaintext_packet.reserve(total_encrypted_bytes);
        plaintext_packet.insert(plaintext_packet.end(), plaintext_bytes.begin(), plaintext_bytes.end());
        plaintext_packet.insert(plaintext_packet.end(), remaining_plaintext_bytes.begin(), remaining_plaintext_bytes.end());

        if (plaintext_packet.size() != total_encrypted_bytes) {
            throw std::runtime_error("Packet size is incorrect");
        }

        std::array<uint8_t, 32> server_mac;
        sock_.read_exact(server_mac.data(), server_mac.size());
        std::array<uint8_t, 32> calculated_mac = calculate_hmac(incoming_sequence_, plaintext_packet, incoming_mac_key_);

        if (sodium_memcmp(server_mac.data(), calculated_mac.data(), server_mac.size()) != 0) {
            throw std::runtime_error("SSH packet MAC verification failed");
        }
        uint8_t padding_length = plaintext_packet[packet_length_bytes];
        validate_packet_padding(packet_length, padding_length);

        std::size_t payload_length = packet_length - padding_length_bytes - padding_length;
        
        auto payload_start = plaintext_packet.begin() + packet_length_bytes + padding_length_bytes;
        
        std::vector<uint8_t> payload(payload_start, payload_start + payload_length);
        incoming_sequence_++;
        
        return payload;


    }
    
}

//checks the payload is not empty ie contains an SSH Message Number
void Transport::validate_payload_size(std::size_t payload_size) const {
    if (payload_size < 1) {
        throw std::runtime_error("Payload cannot be empty");
    }
}

//calculates the amount of padding required for the packet
std::size_t Transport::calculate_padding_length(std::size_t payload_size) const {

    size_t b_size = outgoing_encryption_active_ ? aes_block_size : block_size;

    size_t base = payload_size + packet_length_bytes + padding_length_bytes;
    size_t total = min_padding_length + base;
    size_t remainder = total % b_size;
    return min_padding_length + (b_size - remainder) % b_size;
}

//encodes packet length from a number to big endian form
std::array<uint8_t, Transport::packet_length_bytes> Transport::encode_packet_length(uint32_t packet_length) const {
    std::array<uint8_t, packet_length_bytes> packet_length_arr;
    for (size_t i = 0; i<packet_length_bytes; i++) {
        packet_length_arr[i] = uint8_t(packet_length >> ((packet_length_bytes - 1 - i) * bits_per_byte));
    }
    return packet_length_arr;
}

//generates random padding for sending packets
std::vector<uint8_t> Transport::generate_padding(std::size_t padding_length) const {
    std::vector<uint8_t> padding(padding_length);
    randombytes_buf(padding.data(), padding.size());
    return padding; 
}

//handles sending packets
void Transport::send_packet(const std::vector<uint8_t>& payload) {
    validate_payload_size(payload.size());
    size_t padding_length = calculate_padding_length(payload.size());
    size_t packet_length = padding_length_bytes + payload.size() + padding_length;

    //validate sizes
    if (packet_length + packet_length_bytes > max_packet_size) {
        throw std::runtime_error("Packet size exceeds maximum");
    }

    if (padding_length > std::numeric_limits<uint8_t>::max()) {
        throw std::runtime_error("Padding size exceeds maximum");
    }

    if (packet_length > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("Packet length exceeds maximum");
    }

    std::array<uint8_t, packet_length_bytes> packet_length_arr = encode_packet_length(packet_length);
    std::vector<uint8_t> padding = generate_padding(padding_length);

    std::vector<uint8_t> packet;
    packet.reserve(packet_length + packet_length_bytes);
    packet.insert(packet.end(), packet_length_arr.begin(), packet_length_arr.end());
    packet.push_back(uint8_t(padding_length));
    packet.insert(packet.end(), payload.begin(), payload.end());
    packet.insert(packet.end(), padding.begin(), padding.end());

    if (packet.size() != packet_length + packet_length_bytes) {
        throw std::runtime_error("Internal: packet constructed incorrectly");
    }

    if (outgoing_encryption_active_) {
        std::array<uint8_t, 32> hmac = calculate_hmac(outgoing_sequence_, packet, outgoing_mac_key_);
        std::vector<uint8_t> encrypted_packet = encrypt_outgoing_packet(packet);
        encrypted_packet.insert(encrypted_packet.end(), hmac.begin(), hmac.end());

        sock_.write_exact(encrypted_packet.data(), encrypted_packet.size());
    } else {
        sock_.write_exact(packet.data(), packet.size());
    }
    
    outgoing_sequence_++;
}

void Transport::enable_outgoing_encryption(const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 32>& encryption_key, const std::array<uint8_t, 32>& mac_key) {
    EVP_CIPHER_CTX* new_context = EVP_CIPHER_CTX_new();
    if (new_context == nullptr) {
        throw std::runtime_error("Failed to create temporary cipher context");
    }
    bool r = EVP_EncryptInit_ex(new_context, EVP_aes_256_ctr(), nullptr, encryption_key.data(), iv.data());
    if (r != 1) {
        EVP_CIPHER_CTX_free(new_context);
        throw std::runtime_error("Failed to initialise encryption");
    }
    EVP_CIPHER_CTX_free(outgoing_cipher_);
    outgoing_cipher_ = new_context;
    outgoing_mac_key_ = mac_key;
    outgoing_encryption_active_ = true;
}

void Transport::enable_incoming_encryption(const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 32>& encryption_key, const std::array<uint8_t, 32>& mac_key) {
    EVP_CIPHER_CTX* new_context = EVP_CIPHER_CTX_new();
    if (new_context == nullptr) {
        throw std::runtime_error("Failed to create temporary cipher context");
    }
    bool r = EVP_DecryptInit_ex(new_context, EVP_aes_256_ctr(), nullptr, encryption_key.data(), iv.data());
    if (r != 1) {
        EVP_CIPHER_CTX_free(new_context);
        throw std::runtime_error("Failed to initialise encryption");
    }
    EVP_CIPHER_CTX_free(incoming_cipher_);
    incoming_cipher_ = new_context;
    incoming_mac_key_ = mac_key;
    incoming_encryption_active_ = true;
}

std::array<uint8_t, 32> Transport::calculate_hmac(uint32_t sequence_number, const std::vector<uint8_t>& plaintext_packet, const std::array<uint8_t, 32>& mac_key) const {
    const auto sequence_number_arr = ssh_encoding::encode_uint32(sequence_number);
    std::vector<uint8_t> input{};
    input.insert(input.end(), sequence_number_arr.begin(), sequence_number_arr.end());
    input.insert(input.end(), plaintext_packet.begin(), plaintext_packet.end());
    std::array<uint8_t, 32> result{};
    if (crypto_auth_hmacsha256(result.data(), input.data(), input.size(), mac_key.data()) != 0) {
        throw std::runtime_error("Failed to calculate hmac value");
    }
    return result;
}

std::vector<uint8_t> Transport::encrypt_outgoing_packet(const std::vector<uint8_t>& plaintext_packet) {
    if (outgoing_encryption_active_ != true) {
        throw std::runtime_error("Encryption not active");
    }

    if (outgoing_cipher_ == nullptr) {
        throw std::runtime_error("Outgoing cipher not set");
    }

    if (plaintext_packet.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("Packet is too large for OpenSSL");
    }
    std::vector<uint8_t> ciphertext(plaintext_packet.size());
    int output_length = 0;

    if (EVP_EncryptUpdate(outgoing_cipher_, ciphertext.data(), &output_length, plaintext_packet.data(), static_cast<int>(plaintext_packet.size())) != 1) {
        throw std::runtime_error("Failed to encrypt the packet");
    }

    if (output_length != static_cast<int>(plaintext_packet.size())) {
        throw std::runtime_error("AES-CTR output length was unexpected");
    }

    return ciphertext;
}

std::vector<uint8_t> Transport::decrypt_incoming_bytes(const std::vector<uint8_t>& ciphertext) {
    if (incoming_encryption_active_ != true) {
        throw std::runtime_error("Encryption not active");
    }

    if (incoming_cipher_ == nullptr) {
        throw std::runtime_error("Incoming cipher not set");
    }

    if (ciphertext.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("Ciphertext is too large for OpenSSL");
    }

    std::vector<uint8_t> bytes(ciphertext.size());
    int length = 0;

    if (EVP_DecryptUpdate(incoming_cipher_, bytes.data(), &length, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("Failed to decrypt the packet");
    }

    if (length != static_cast<int>(ciphertext.size())) {
        throw std::runtime_error("AES-CTR length was unexpected");
    }

    return bytes;
}
