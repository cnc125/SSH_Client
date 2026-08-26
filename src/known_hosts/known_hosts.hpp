#pragma once

#include <string>
#include <vector>
#include <cstdint>

enum class HostKeyStatus {
    Unknown,
    Match,
    Changed
};

class KnownHosts {
public:
    explicit KnownHosts(const std::string& file_path);

    HostKeyStatus check(const std::string& hostname, const std::string& algorithm, const std::vector<uint8_t>& host_key) const;
    void add(const std::string& hostname, const std::string& algorithm, const std::vector<uint8_t>& host_key);

private:
    std::string file_path_;
};