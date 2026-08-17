#include "transport.hpp"
#include <stdexcept>
#include <cstddef>
#include <limits>
#include <cstdint>
#include <sodium.h>

namespace {

    constexpr std::size_t bits_per_byte = 8;
    constexpr std::size_t min_packet_size = 16;
    constexpr std::size_t max_packet_size = 35000;
    constexpr std::size_t block_size = 8;
    constexpr std::size_t min_padding_length = 4;
    constexpr std::size_t min_payload_bytes = 1;
    constexpr std::size_t padding_length_bytes = 1;
}

Transport::Transport(Socket& sock) : sock_(sock), incoming_sequence_(0), outgoing_sequence_(0) {
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
    if ((packet_length + packet_length_bytes) % block_size != 0) {
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
}

//checks the payload is not empty ie contains an SSH Message Number
void Transport::validate_payload_size(std::size_t payload_size) const {
    if (payload_size < 1) {
        throw std::runtime_error("Payload cannot be empty");
    }
}

//calculates the amount of padding required for the packet
std::size_t Transport::calculate_padding_length(std::size_t payload_size) const {
    size_t base = payload_size + packet_length_bytes + padding_length_bytes;
    size_t total = min_padding_length + base;
    size_t remainder = total % block_size;
    return min_padding_length + (block_size - remainder) % block_size;
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

    sock_.write_exact(packet.data(), packet.size());

    outgoing_sequence_++;
}



