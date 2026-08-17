#include "transport.hpp"
#include <array>
#include <vector>
#include <stdexcept>

namespace {

    constexpr std::size_t bits_per_byte = 8;
    constexpr std::size_t min_packet_size = 16;
    constexpr std::size_t max_packet_size = 35000;
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
void validate_packet_length(uint32_t packet_length) const {
    //packet length minimum size
    if (packet_length < min_packet_size - packet_length_bytes) {
        throw std::runtime_error("SSH packet length is below minimum");
    }

    //packet length maximum size
    if (packet_length + packet_length_bytes > max_packet_size) {
        throw std::runtime_error("SSH packet length is above maximum");
    }

    //packet alignment
    if ((packet_length + packet_length_bytes) % 8 != 0) {
        throw std::runtime_error("SSH packet is not aligned");
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
}



