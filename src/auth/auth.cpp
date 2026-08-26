#include "auth.hpp"
#include "common/ssh_encoding.hpp"
#include "common/ssh_messages.hpp"
#include <stdexcept>
#include <cstddef>

std::vector<uint8_t> Auth::create_service_request() const {
    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::SERVICE_REQUEST);
    ssh_encoding::append_string(payload, "ssh-userauth");
    return payload;
}

void Auth::validate_service_accept(const std::vector<uint8_t>& payload) const {
    if (payload.size() == 0) {
        throw std::runtime_error("Payload cannot be empty");
    }
    if (payload[0] != ssh_message::SERVICE_ACCEPT) {
        throw std::runtime_error("SSH_MSG_SERVICE_ACCEPT was expected");
    }

    std::size_t position = 1;

    std::vector<uint8_t> service_bytes = ssh_encoding::read_string(payload, position);
    std::string service_name(service_bytes.begin(), service_bytes.end());
    if (service_name != "ssh-userauth") {
        throw std::runtime_error("String doesn't match ssh-userauth");
    }
    if (position != payload.size()) {
        throw std::runtime_error("Extra bytes received");
    }
}

std::vector<uint8_t> Auth::create_none_auth_request(const std::string& username) const {
    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::USERAUTH_REQUEST);
    ssh_encoding::append_string(payload, username);
    ssh_encoding::append_string(payload, "ssh-connection");
    ssh_encoding::append_string(payload, "none");
    return payload;
}

AuthFailure Auth::parse_auth_failure(const std::vector<uint8_t>& payload) const {
    AuthFailure auth_failure;
    if (payload.size() == 0) {
        throw std::runtime_error("SSH_MSG_USERAUTH_FAILURE expected");
    }

    if (payload[0] != ssh_message::USERAUTH_FAILURE) {
        throw std::runtime_error("SSH_MSG_USERAUTH_FAILURE expected");
    }

    std::size_t position = 1;
    std::vector<uint8_t> authentication_method_vctr;
    authentication_method_vctr = ssh_encoding::read_string(payload, position);
    std::string authentication_methods(authentication_method_vctr.begin(), authentication_method_vctr.end());

    if (payload.size() - position != 1) {
        throw std::runtime_error("One byte expected");
    }

    auth_failure.available_methods = authentication_methods;
    auth_failure.partial_success = payload[position] != 0;
    
    position++;

    if (position != payload.size()) {
        throw std::runtime_error("No more bytes expected");
    }

    return auth_failure;

}

std::vector<uint8_t> Auth::create_password_auth_request(const std::string& username, const std::string& password) const {
    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::USERAUTH_REQUEST);
    ssh_encoding::append_string(payload, username);
    ssh_encoding::append_string(payload, "ssh-connection");
    ssh_encoding::append_string(payload, "password");
    payload.push_back(0);
    ssh_encoding::append_string(payload, password);
    return payload;
}

void Auth::validate_auth_success(const std::vector<uint8_t>& payload) const {
    if (payload.size() != 1 || payload[0] != ssh_message::USERAUTH_SUCCESS) {
        throw std::runtime_error("SSH_MSG_USERAUTH_SUCCESS expected");
    }
}