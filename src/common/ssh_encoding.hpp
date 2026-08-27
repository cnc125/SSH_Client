#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Helpers for encoding and decoding SSH binary protocol values
namespace ssh_encoding {

// Number of bytes in an SSH uint32 value
constexpr std::size_t uint32_bytes = 4;

// Encodes a host integer in SSH network-byte order
std::array<uint8_t, uint32_bytes> encode_uint32(uint32_t value);
// Decodes an SSH network-byte-order integer
uint32_t decode_uint32(const std::array<uint8_t, uint32_bytes>& bytes);
// Appends a length-prefixed binary SSH string
void append_string(std::vector<uint8_t>& destination, const std::vector<uint8_t>& value);
// Appends a length-prefixed text SSH string
void append_string(std::vector<uint8_t>& destination, const std::string& value);
// Reads a length-prefixed SSH string and advances the cursor
std::vector<uint8_t> read_string(const std::vector<uint8_t>& payload, std::size_t& position);
// Reads an SSH uint32 and advances the cursor
uint32_t read_uint32(const std::vector<uint8_t>& payload, std::size_t& position);

}
