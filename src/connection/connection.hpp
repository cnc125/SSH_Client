#pragma once

#include <cstdint>
#include <vector>
#include <string>

// Mutable state for one SSH connection-layer channel
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

// Details supplied when the server rejects a channel-open request
struct ChannelOpenFailure {
    uint32_t reason_code;
    std::string description;
    std::string language;
};

// Parsed SSH_MSG_GLOBAL_REQUEST data
struct GlobalRequest {
    std::string request_name;
    bool want_reply;
    std::vector<uint8_t> request_data;
};

// Exit status reported by the remote process
struct ChannelExitStatus {
    uint32_t exit_status;
    bool want_reply;
};

// Extended channel data, normally the remote process standard error stream
struct ChannelExtendedData {
    uint32_t data_type;
    std::vector<uint8_t> data;
};

// Builds, parses, and tracks SSH connection-layer channel messages
class Connection {
public:

    // Creates SSH_MSG_CHANNEL_OPEN for a new session channel
    std::vector<uint8_t> create_session_open(const Channel& channel) const;

    // Parses channel-open confirmation and records the server channel state
    void parse_open_confirmation(const std::vector<uint8_t>& payload, Channel& channel) const;

    // Parses a rejected channel-open response
    ChannelOpenFailure parse_open_failure(const std::vector<uint8_t>& payload, const Channel& channel) const;

    // Parses a server-wide global request
    GlobalRequest parse_global_request(const std::vector<uint8_t>& payload) const;

    // Creates SSH_MSG_REQUEST_FAILURE for an unsupported global request
    std::vector<uint8_t> create_request_failure() const;

    // Creates an "exec" request for an open channel
    std::vector<uint8_t> create_exec_request(const Channel& channel, const std::string& command) const;

    // Validates successful completion of a channel request
    void validate_channel_success(const std::vector<uint8_t>& payload, const Channel& channel) const;

    // Validates rejection of a channel request
    void validate_channel_failure(const std::vector<uint8_t>& payload, const Channel& channel) const;

    // Parses a remote-window increase and updates the channel state
    void parse_window_adjust(const std::vector<uint8_t>& payload, Channel& channel) const;

    // Parses channel data and consumes the advertised local window
    std::vector<uint8_t> parse_channel_data(const std::vector<uint8_t>& payload, Channel& channel) const;

    // Parses remote EOF and records it in the channel state
    void parse_channel_eof(const std::vector<uint8_t>& payload, Channel& channel) const;

    // Parses an "exit-status" channel request
    ChannelExitStatus parse_exit_status(const std::vector<uint8_t>& payload, Channel& channel) const;

    // Parses remote channel closure and records it in the channel state
    void parse_channel_close(const std::vector<uint8_t>& payload, Channel& channel) const;

    // Creates SSH_MSG_CHANNEL_CLOSE for the remote channel
    std::vector<uint8_t> create_channel_close(const Channel& channel) const;

    // Parses extended channel data and consumes the local window
    ChannelExtendedData parse_channel_extended_data(const std::vector<uint8_t>& payload, Channel& channel) const;

    // Creates a window-adjust message granting the server more capacity
    std::vector<uint8_t> create_window_adjust(const Channel& channel, uint32_t bytes_to_add) const;

    // Creates a PTY request using the local terminal type and dimensions
    std::vector<uint8_t> create_pty_request(const Channel& channel, const std::string& terminal_type, uint32_t columns, uint32_t rows) const;

    // Creates a request to start an interactive remote shell
    std::vector<uint8_t> create_shell_request(const Channel& channel) const;

    // Creates channel data carrying keyboard bytes to the remote shell
    std::vector<uint8_t> create_channel_data(const Channel& channel, const std::vector<uint8_t>& data) const;
private:

};