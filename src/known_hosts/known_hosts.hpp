#pragma once

#include <string>
#include <vector>
#include <cstdint>

// Result of comparing a presented host key with persistent trust data
enum class HostKeyStatus {
    Unknown,
    Match,
    Changed
};

// Manages the client's project-specific known-hosts file
class KnownHosts {
public:
    // Uses the supplied file as the persistent host-key store
    explicit KnownHosts(const std::string& file_path);

    // Returns whether a host key is unknown, matching, or changed
    HostKeyStatus check(const std::string& hostname, const std::string& algorithm, const std::vector<uint8_t>& host_key) const;
    // Appends a previously unknown trusted host key without replacing entries
    void add(const std::string& hostname, const std::string& algorithm, const std::vector<uint8_t>& host_key);

private:
    std::string file_path_;
};