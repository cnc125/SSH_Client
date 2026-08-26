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
    bool remote_eof_received;
    bool remote_close_received;
    bool local_close_sent;

    bool exit_status_received;
    uint32_t exit_status;
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

struct ChannelExitStatus {
    uint32_t exit_status;
    bool want_reply;
};

struct ChannelExtendedData {
    uint32_t data_type;
    std::vector<uint8_t> data;
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

    //creates a request to the open channel to run a command
    std::vector<uint8_t> create_exec_request(const Channel& channel, const std::string& command) const;

    //validates SSH_MSG_CHANNEL_SUCCESS
    void validate_channel_success(const std::vector<uint8_t>& payload, const Channel& channel) const;

    //validates SSH_MSG_CHANNEL_FAILURE
    void validate_channel_failure(const std::vector<uint8_t>& payload, const Channel& channel) const;

    //parses SSH_MSG_CHANNEL_WINDOW_ADJUDT
    void parse_window_adjust(const std::vector<uint8_t>& payload, Channel& channel) const;

    //parse responses from server after sending commands
    std::vector<uint8_t> parse_channel_data(const std::vector<uint8_t>& payload, Channel& channel) const;

    //parses SSH_MSG_CHANNEL_EOF
    void parse_channel_eof(const std::vector<uint8_t>& payload, Channel& channel) const;

    //Parses the "exit-status" SSH_MSG_CHANNEL_REQUEST.
    ChannelExitStatus parse_exit_status(const std::vector<uint8_t>& payload, Channel& channel) const;

    //Parse SSH_MSG_CHANNEL_CLOSE requests
    void parse_channel_close(const std::vector<uint8_t>& payload, Channel& channel) const;

    //Create channel close payload
    std::vector<uint8_t> create_channel_close(const Channel& channel) const;

    //Parse SSH_MSG_CHANNEL_EXTENDED_DATA
    ChannelExtendedData parse_channel_extended_data(const std::vector<uint8_t>& payload, Channel& channel) const;

    //Create window adjust requests
    std::vector<uint8_t> create_window_adjust(const Channel& channel, uint32_t bytes_to_add) const;
private:

};