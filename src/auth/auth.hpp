#pragma once

#include <vector>
#include <cstdint>
#include <string>

struct AuthFailure {
    std::string available_methods;
    bool partial_success;
};

class Auth {

public:
    //Creates SSH_MSG_SERVICE_REQUEST for the "ssh-userauth" service
    std::vector<uint8_t> create_service_request() const;

    //Validates server accepted the "ssh-userauth" service
    void validate_service_accept(const std::vector<uint8_t>& payload) const;

    // Creates an authentication request using the "none" method
    std::vector<uint8_t> create_none_auth_request(const std::string& username) const;

    // Parses SSH_MSG_USERAUTH_FAILURE, including the remaining authentication
    AuthFailure parse_auth_failure(const std::vector<uint8_t>& payload) const;

    // Creates a password authentication request for the specified username
    std::vector<uint8_t> create_password_auth_request(const std::string& username, const std::string& password) const;
    
    // Validates SSH_MSG_USERAUTH_SUCCESS.
    void validate_auth_success(const std::vector<uint8_t>& payload) const;
private:


};