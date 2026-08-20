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

class Kex {
public:
    KexInit parse_kexinit(const std::vector<uint8_t>& payload);

private:
    static constexpr std::size_t uint32_bytes = 4;
    static constexpr std::size_t cookie_bytes = 16;

    uint32_t read_uint32(const std::array<uint8_t, uint32_bytes>& length_bytes) const;

    std::string read_name_list(const std::vector<uint8_t>& payload, std::size_t& position) const;

    bool parse_boolean(const std::vector<uint8_t>& payload, std::size_t& position) const;
};
