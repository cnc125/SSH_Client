#include "known_hosts.hpp"
#include <sodium.h>
#include <stdexcept>
#include <cstddef>
#include <fstream>
#include <filesystem>
#include <sstream>

namespace {
    std::string encode_base64(const std::vector<uint8_t>& bytes) {
        if (bytes.empty()) {
            throw std::runtime_error("Cannot encode an empty host key");
        }
        std::size_t encoded_size = sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_ORIGINAL);
        std::vector<char> encoded(encoded_size);

        char* result = sodium_bin2base64(encoded.data(), encoded.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
        if (result == nullptr) {
            throw std::runtime_error("Failed to encode host key");
        }
        return std::string(encoded.data());
    }
}

KnownHosts::KnownHosts(const std::string& file_path) : file_path_(file_path) {
}

HostKeyStatus KnownHosts::check(const std::string& hostname, const std::string& algorithm, const std::vector<uint8_t>& host_key) const {
    std::string encoded_key = encode_base64(host_key);
    if (!std::filesystem::exists(file_path_)) {
        return HostKeyStatus::Unknown;
    }
    std::ifstream file(file_path_);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open known-hosts file");
    }

    std::string line;

    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream fields(line);
        std::string saved_hostname;
        std::string saved_algorithm;
        std::string saved_key;
        if (!(fields >> saved_hostname >> saved_algorithm >> saved_key)) {
            throw std::runtime_error("Malformed known-hosts entry");
        }
        if (saved_hostname != hostname) {
            continue;
        }
        if (saved_algorithm == algorithm && saved_key == encoded_key) {
            return HostKeyStatus::Match;
        }
        return HostKeyStatus::Changed;
    }
    if (file.bad()) {
            throw std::runtime_error("Failed while reading known-hosts file");
    }

    return HostKeyStatus::Unknown;
}

void KnownHosts::add(const std::string& hostname, const std::string& algorithm, const std::vector<uint8_t>& host_key) {
    HostKeyStatus status = check(hostname, algorithm, host_key);
    if (status == HostKeyStatus::Match) {
        return;
    }

    if (status == HostKeyStatus::Changed) {
        throw std::runtime_error("Refusing to replace existing host key");
    }

    std::filesystem::path path(file_path_);
    std::filesystem::path directory = path.parent_path();
    if (!directory.empty()) {
        std::filesystem::create_directories(directory);
    }
    std::ofstream file(file_path_, std::ios::app);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open known-hosts file for writing");
    }
    file << hostname << ' ' << algorithm << ' ' << encode_base64(host_key) << '\n';
    if (!file) {
        throw std::runtime_error("Failed to write known-hosts entry");
    }
}
