#pragma once

#include <vector>
#include <cstdint>
#include <string>

// Details returned by SSH_MSG_USERAUTH_FAILURE
struct AuthFailure {
    std::string available_methods;
    bool partial_success;
};

// Builds and validates SSH user-authentication messages
class Auth {

public:
    // Creates an SSH_MSG_SERVICE_REQUEST for the "ssh-userauth" service
    std::vector<uint8_t> create_service_request() const;

    // Validates that the server accepted the "ssh-userauth" service
    void validate_service_accept(const std::vector<uint8_t>& payload) const;

    // Creates a probe request using the "none" authentication method
    std::vector<uint8_t> create_none_auth_request(const std::string& username) const;

    // Parses SSH_MSG_USERAUTH_FAILURE and its remaining authentication methods
    AuthFailure parse_auth_failure(const std::vector<uint8_t>& payload) const;

    // Creates a password authentication request for the specified user
    std::vector<uint8_t> create_password_auth_request(const std::string& username, const std::string& password) const;
    
    // Validates an SSH_MSG_USERAUTH_SUCCESS response
    void validate_auth_success(const std::vector<uint8_t>& payload) const;
private:


};