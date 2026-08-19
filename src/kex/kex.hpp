#pragma once

#include <vector>
#include <cstdint>
#include <array>

class Kex {
public:
    void parse_kexinit(const std::vector<uint8_t>& payload);

private:
    static constexpr std::size_t uint32_bytes = 4;

    uint32_t read_uint32(const std::array<uint8_t, uint32_bytes>& length_bytes) const;
};