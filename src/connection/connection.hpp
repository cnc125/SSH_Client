#pragma once

#include <cstdint>
#include <vector>
#include <string>

struct Channel {
    uint32_t local_id;
    uint32_t remote_id;

    uint32_t local_window;
    uint32_t remote_window;

    uint32_t local_max_packet;
    uint32_t remote_max_packet;

    bool open;
};

struct ChannelOpenFailure {
    uint32_t reason_code;
    std::string description;
    std::string language;
};

struct GlobalRequest {
    std::string request_name;
    bool want_reply;
    std::vector<uint8_t> request_data;
};

class Connection {
public:

    //creates payload for SSH_MSG_CHANNEL_OPEN to open channel
    std::vector<uint8_t> create_session_open(const Channel& channel) const;

    //parses SSH_MSG_CHANNEL_OPEN_CONFIRMATION response 
    void parse_open_confirmation(const std::vector<uint8_t>& payload, Channel& channel) const;

    //parses SSH_MSG_CHANNEL_OPEN_FAILURE response
    ChannelOpenFailure parse_open_failure(const std::vector<uint8_t>& payload, const Channel& channel) const;

    //parses SSH_MSG_GLOBAL_REQUEST
    GlobalRequest parse_global_request(const std::vector<uint8_t>& payload) const;

    //creates a payload for SSH_MSG_REQUEST_FAILURE
    std::vector<uint8_t> create_request_failure() const;
private:

};