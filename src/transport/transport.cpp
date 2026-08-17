#include "transport.hpp"
#include <stdexcept>
#include <cstddef>

namespace {

    constexpr std::size_t bits_per_byte = 8;
    constexpr std::size_t min_packet_size = 16;
    constexpr std::size_t max_packet_size = 35000;
    constexpr std::size_t block_size = 8;
    constexpr std::size_t min_padding_length = 4;
    constexpr std::size_t min_payload_bytes = 1;
    constexpr std::size_t padding_length_bytes = 1;
}

Transport::Transport(Socket& sock) : sock_(sock) {}

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
    return payload;

}



