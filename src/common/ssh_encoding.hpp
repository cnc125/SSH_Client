#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ssh_encoding {

constexpr std::size_t uint32_bytes = 4;

std::array<uint8_t, uint32_bytes> encode_uint32(uint32_t value);
uint32_t decode_uint32(const std::array<uint8_t, uint32_bytes>& bytes);
void append_string(std::vector<uint8_t>& destination, const std::vector<uint8_t>& value);
void append_string(std::vector<uint8_t>& destination, const std::string& value);
std::vector<uint8_t> read_string(const std::vector<uint8_t>& payload, std::size_t& position);

}
