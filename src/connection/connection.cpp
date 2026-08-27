#include "connection.hpp"
#include "common/ssh_encoding.hpp"
#include "common/ssh_messages.hpp"
#include <stdexcept>
#include <array>
#include <cstddef>
#include <limits>

namespace {

    constexpr uint32_t MIN_MAX_PACKET_SIZE = 32768;
}

std::vector<uint8_t> Connection::create_session_open(const Channel& channel) const {

    if (channel.open) {
        throw std::runtime_error("Channel already opened");
    }

    if (channel.local_window == 0) {
        throw std::runtime_error("No channel data could be received");
    }

    if (channel.local_max_packet < MIN_MAX_PACKET_SIZE) {
        throw std::runtime_error("No channel-data packet could be accepted");
    }

    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::CHANNEL_OPEN);
    ssh_encoding::append_string(payload, "session");
    auto local_id = ssh_encoding::encode_uint32(channel.local_id);
    payload.insert(payload.end(), local_id.begin(), local_id.end());
    auto local_window = ssh_encoding::encode_uint32(channel.local_window);
    payload.insert(payload.end(), local_window.begin(), local_window.end());
    auto local_max_packet = ssh_encoding::encode_uint32(channel.local_max_packet);
    payload.insert(payload.end(), local_max_packet.begin(), local_max_packet.end());
    return payload;
}

void Connection::parse_open_confirmation(const std::vector<uint8_t>& payload, Channel& channel) const {
    if (channel.open) {
        throw std::runtime_error("Channel already open");
    }
    
    if (payload.empty() || payload[0] != ssh_message::CHANNEL_OPEN_CONFIRMATION) {
        throw std::runtime_error("Expected SSH_MSG_CHANNEL_OPEN_CONFIRMATION");
    }

    std::size_t position = 1;
    uint32_t recipient_channel = ssh_encoding::read_uint32(payload, position);
    uint32_t sender_channel = ssh_encoding::read_uint32(payload, position);
    uint32_t remote_window = ssh_encoding::read_uint32(payload, position);
    uint32_t remote_max_packet = ssh_encoding::read_uint32(payload, position);

    if (channel.local_id != recipient_channel) {
        throw std::runtime_error("Not the correct recipient channel");
    }

    if (remote_max_packet < MIN_MAX_PACKET_SIZE) {
        throw std::runtime_error("No channel-data packet can be sent");
    }

    if (position != payload.size()) {
        throw std::runtime_error("Payload contains more bytes than expected");
    }

    channel.remote_id = sender_channel;
    channel.remote_window = remote_window;
    channel.remote_max_packet = remote_max_packet;

    channel.open = true;
}

ChannelOpenFailure Connection::parse_open_failure(const std::vector<uint8_t>& payload, const Channel& channel) const {
    if (channel.open) {
        throw std::runtime_error("Open failure received for an already-open channel");
    }

    if (payload.empty() || payload[0] != ssh_message::CHANNEL_OPEN_FAILURE) {
        throw std::runtime_error("Expected SSH_MSG_CHANNEL_OPEN_FAILURE");
    }

    std::size_t position = 1;

    uint32_t recipient_channel = ssh_encoding::read_uint32(payload, position);
    uint32_t reason_code = ssh_encoding::read_uint32(payload, position);
    auto description_bytes = ssh_encoding::read_string(payload, position);
    auto language_bytes = ssh_encoding::read_string(payload, position);

    std::string description(description_bytes.begin(), description_bytes.end());

    std::string language(language_bytes.begin(), language_bytes.end());

    if (position != payload.size()) {
        throw std::runtime_error("Payload contains more bytes than expected");
    }

    if (recipient_channel != channel.local_id) {
        throw std::runtime_error("Not the correct recipient channel");
    }

    ChannelOpenFailure cof{};
    cof.reason_code = reason_code;
    cof.description = description;
    cof.language = language;

    return cof;

}

GlobalRequest Connection::parse_global_request(const std::vector<uint8_t>& payload) const {
    if (payload.empty() || payload[0] != ssh_message::GLOBAL_REQUEST) {
        throw std::runtime_error("Expected SSH_MSG_GLOBAL_REQUEST");
    }
    std::size_t position = 1;

    auto request_name_bytes = ssh_encoding::read_string(payload, position);
    std::string request_name(request_name_bytes.begin(), request_name_bytes.end());

    if (payload.size() - position < 1) {
        throw std::runtime_error("want_reply value expected");
    }

    bool want_reply = payload[position] != 0;
    position++;

    GlobalRequest gr{};
    gr.request_name = request_name;
    gr.want_reply = want_reply;
    gr.request_data.insert(gr.request_data.end(), payload.begin() + position, payload.end());

    return gr;
   
}

std::vector<uint8_t> Connection::create_request_failure() const {
    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::REQUEST_FAILURE);
    return payload;
}

std::vector<uint8_t> Connection::create_exec_request(const Channel& channel, const std::string& command) const {
    if (channel.open == false) {
        throw std::runtime_error("Channel must be open");
    }

    if (command.empty()) {
        throw std::runtime_error("Command must not be empty");
    }
    
    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::CHANNEL_REQUEST);
    auto remote_id = ssh_encoding::encode_uint32(channel.remote_id);
    payload.insert(payload.end(), remote_id.begin(), remote_id.end());
    ssh_encoding::append_string(payload, "exec");
    payload.push_back(1);
    ssh_encoding::append_string(payload, command);
    return payload;

}

void Connection::validate_channel_success(const std::vector<uint8_t>& payload, const Channel& channel) const {
    if (payload.empty() || payload[0] != ssh_message::CHANNEL_SUCCESS) {
        throw std::runtime_error("Expected SSH_MSG_CHANNEL_SUCCESS");
    }

    std::size_t position = 1;
    uint32_t recipient_channel = ssh_encoding::read_uint32(payload, position);
    if (recipient_channel != channel.local_id) {
        throw std::runtime_error("Channel ids did not match");
    }

    if (position != payload.size()) {
        throw std::runtime_error("Payload contains more bytes than expected");
    }

 }

void Connection::validate_channel_failure(const std::vector<uint8_t>& payload, const Channel& channel) const {
    if (payload.empty() || payload[0] != ssh_message::CHANNEL_FAILURE) {
        throw std::runtime_error("Expected SSH_MSG_CHANNEL_FAILURE");
    }

    std::size_t position = 1;
    uint32_t recipient_channel = ssh_encoding::read_uint32(payload, position);
    if (recipient_channel != channel.local_id) {
        throw std::runtime_error("Channel ids did not match");
    }

    if (position != payload.size()) {
        throw std::runtime_error("Payload contains more bytes than expected");
    }

}

void Connection::parse_window_adjust(const std::vector<uint8_t>& payload, Channel& channel) const {
    if (!channel.open) {
        throw std::runtime_error("Window adjustment received for a closed channel");
    }

    if (payload.empty() || payload[0] != ssh_message::CHANNEL_WINDOW_ADJUST) {
        throw std::runtime_error("Expected SSH_MSG_CHANNEL_WINDOW_ADJUST");
    }

    std::size_t position = 1;

    uint32_t recipient_channel = ssh_encoding::read_uint32(payload, position);
    uint32_t bytes_to_add = ssh_encoding::read_uint32(payload, position);

    if (recipient_channel != channel.local_id) {
        throw std::runtime_error("Channel ids did not match");
    }

    if (position != payload.size()) {
        throw std::runtime_error("Payload contains more bytes than expected");
    }

    if (bytes_to_add == 0) {
        throw std::runtime_error("Channel window adjustment must be greater than zero");
    }

    if (channel.remote_window > std::numeric_limits<uint32_t>::max() - bytes_to_add) {
        throw std::runtime_error("Remote channel window overflow");
    }

    channel.remote_window += bytes_to_add;
}

std::vector<uint8_t> Connection::parse_channel_data(const std::vector<uint8_t>& payload, Channel& channel) const {
    if (!channel.open) {
        throw std::runtime_error("Channel data received for a closed channel");
    }

    if (payload.empty() || payload[0] != ssh_message::CHANNEL_DATA) {
        throw std::runtime_error("Expected SSH_MSG_CHANNEL_DATA");
    }

    std::size_t position = 1;

    uint32_t recipient_channel = ssh_encoding::read_uint32(payload, position);
    if (recipient_channel != channel.local_id) {
        throw std::runtime_error("Channel ids did not match");
    }

    auto data_bytes = ssh_encoding::read_string(payload, position);

    if (position != payload.size()) {
        throw std::runtime_error("Payload contains more bytes than expected");
    }

    if (data_bytes.size() > channel.local_max_packet) {
        throw std::runtime_error("Channel data exceeds local maximum packet size");
    }

    if (data_bytes.size() > channel.local_window) {
        throw std::runtime_error("Data received exceeds maximum allowed size");
    }

    channel.local_window -= data_bytes.size();

    return data_bytes;
}

void Connection::parse_channel_eof(const std::vector<uint8_t>& payload, Channel& channel) const {
    if (!channel.open) {
        throw std::runtime_error("Channel data received for a closed channel");
    }

    if (channel.remote_eof_received) {
        throw std::runtime_error("EOF already received");
    }

    if (payload.empty() || payload[0] != ssh_message::CHANNEL_EOF) {
        throw std::runtime_error("Expected SSH_MSG_CHANNEL_EOF");
    }

    std::size_t position = 1;

    uint32_t recipient_channel = ssh_encoding::read_uint32(payload, position);
    if (recipient_channel != channel.local_id) {
        throw std::runtime_error("Channel ids did not match");
    }

    if (position != payload.size()) {
        throw std::runtime_error("No more bytes were expected");
    }

    channel.remote_eof_received = true;
}

ChannelExitStatus Connection::parse_exit_status(const std::vector<uint8_t>& payload, Channel& channel) const {
    if (!channel.open) {
        throw std::runtime_error("Exit status received for a closed channel");
    }

    if (channel.exit_status_received) {
        throw std::runtime_error("Exit status already received");
    }

    if (payload.empty() || payload[0] != ssh_message::CHANNEL_REQUEST) {
        throw std::runtime_error("Expected SSH_MSG_CHANNEL_REQUEST");
    }

    std::size_t position = 1;
    uint32_t recipient_channel = ssh_encoding::read_uint32(payload, position);
    if (recipient_channel != channel.local_id) {
        throw std::runtime_error("Channel ids did not match");
    }

    auto request_name_bytes = ssh_encoding::read_string(payload, position);
    std::string request_name(request_name_bytes.begin(), request_name_bytes.end());

    if (request_name != "exit-status") {
        throw std::runtime_error("Expected exit-status request");
    }

    if (payload.size() - position < 1) {
        throw std::runtime_error("want_reply value expected");
    }

    bool want_reply = payload[position] != 0;
    position++;

    uint32_t exit_status = ssh_encoding::read_uint32(payload, position);

    if (position != payload.size()) {
        throw std::runtime_error("Payload contains more bytes than expected");
    }

    channel.exit_status = exit_status;
    channel.exit_status_received = true;

    ChannelExitStatus ces{};
    ces.exit_status = exit_status;
    ces.want_reply = want_reply;

    return ces;

}

void Connection::parse_channel_close(const std::vector<uint8_t>& payload, Channel& channel) const {
    if (!channel.open) {
        throw std::runtime_error("Close request received for a closed channel");
    }

    if (channel.remote_close_received) {
        throw std::runtime_error("Channel close already received");
    }

    if (payload.empty() || payload[0] != ssh_message::CHANNEL_CLOSE) {
        throw std::runtime_error("Expected SSH_MSG_CHANNEL_CLOSE");
    }

    std::size_t position = 1;
    uint32_t recipient_channel = ssh_encoding::read_uint32(payload, position);
    if (recipient_channel != channel.local_id) {
        throw std::runtime_error("Channel ids did not match");
    }

    if (position != payload.size()) {
        throw std::runtime_error("Payload contains more bytes than expected");
    }

    channel.remote_close_received = true;
}

std::vector<uint8_t> Connection::create_channel_close(const Channel& channel) const {
    if (!channel.open) {
        throw std::runtime_error("Channel already closed");
    }
    
    if (channel.local_close_sent) {
        throw std::runtime_error("SSH_MSG_CHANNEL_CLOSE already been sent");
    }

    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::CHANNEL_CLOSE);
    auto remote_id = ssh_encoding::encode_uint32(channel.remote_id);
    payload.insert(payload.end(), remote_id.begin(), remote_id.end());
    return payload;
}

ChannelExtendedData Connection::parse_channel_extended_data(const std::vector<uint8_t>& payload, Channel& channel) const {
    if (!channel.open) {
        throw std::runtime_error("Extended data received for a closed channel");
    }

    if (payload.empty() || payload[0] != ssh_message::CHANNEL_EXTENDED_DATA) {
        throw std::runtime_error("Expected SSH_MSG_EXTENDED_DATA");
    }

    std::size_t position = 1;
    uint32_t recipient_channel = ssh_encoding::read_uint32(payload, position);
    if (recipient_channel != channel.local_id) {
        throw std::runtime_error("Channel ids did not match");
    }
    uint32_t data_type_code = ssh_encoding::read_uint32(payload, position);
    if (data_type_code != 1) {
        throw std::runtime_error("Unexpected data type code received");
    }

    auto data = ssh_encoding::read_string(payload, position);

    if (position != payload.size()) {
        throw std::runtime_error("Payload contains more bytes than expected");
    }

    if (data.size() > channel.local_max_packet) {
        throw std::runtime_error("Channel data exceeds local maximum packet size");
    }

    if (data.size() > channel.local_window) {
        throw std::runtime_error("Data received exceeds maximum allowed size");
    }

    channel.local_window -= data.size();

    ChannelExtendedData channel_extended_data{};
    channel_extended_data.data_type = data_type_code;
    channel_extended_data.data = data;

    return channel_extended_data;
}

std::vector<uint8_t> Connection::create_window_adjust(const Channel& channel, uint32_t bytes_to_add) const {
    if (!channel.open) {
        throw std::runtime_error("Channel already closed");
    }
    
    if (bytes_to_add == 0) {
        throw std::runtime_error("Must add a positive number of bytes");
    }

    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::CHANNEL_WINDOW_ADJUST);
    auto remote_id = ssh_encoding::encode_uint32(channel.remote_id);
    payload.insert(payload.end(), remote_id.begin(), remote_id.end());

    if (channel.local_window > std::numeric_limits<uint32_t>::max() - bytes_to_add) {
        throw std::runtime_error("Local channel window overflow");
    }
    auto bytes_arr = ssh_encoding::encode_uint32(bytes_to_add);
    payload.insert(payload.end(), bytes_arr.begin(), bytes_arr.end());
    return payload;
}

std::vector<uint8_t> Connection::create_pty_request(const Channel& channel, const std::string& terminal_type, uint32_t columns, uint32_t rows) const {
    if (!channel.open) {
        throw std::runtime_error("Channel already closed");
    }

    if (terminal_type.empty()) {
        throw std::runtime_error("Must provide a non-empty terminal_type");
    }

    if (columns == 0 || rows == 0) {
        throw std::runtime_error("Columns and rows must be non-zero values");
    }

    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::CHANNEL_REQUEST);
    auto remote_id = ssh_encoding::encode_uint32(channel.remote_id);
    payload.insert(payload.end(), remote_id.begin(), remote_id.end());
    ssh_encoding::append_string(payload, "pty-req");
    payload.push_back(1);
    ssh_encoding::append_string(payload, terminal_type);
    auto columns_arr = ssh_encoding::encode_uint32(columns);
    auto rows_arr = ssh_encoding::encode_uint32(rows);
    auto zero_arr = ssh_encoding::encode_uint32(0);
    payload.insert(payload.end(), columns_arr.begin(), columns_arr.end());
    payload.insert(payload.end(), rows_arr.begin(), rows_arr.end());
    payload.insert(payload.end(), zero_arr.begin(), zero_arr.end());
    payload.insert(payload.end(), zero_arr.begin(), zero_arr.end());
    std::vector<uint8_t> terminal_modes{0};
    ssh_encoding::append_string(payload, terminal_modes);
    return payload;
 }

 std::vector<uint8_t> Connection::create_shell_request(const Channel& channel) const {
    if (!channel.open) {
        throw std::runtime_error("Channel is already closed");
    }

    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::CHANNEL_REQUEST);
    auto remote_id = ssh_encoding::encode_uint32(channel.remote_id);
    payload.insert(payload.end(), remote_id.begin(), remote_id.end());
    ssh_encoding::append_string(payload, "shell");
    payload.push_back(1);
    return payload;
 }

 std::vector<uint8_t> Connection::create_channel_data(const Channel& channel, const std::vector<uint8_t>& data) const {
    if (!channel.open) {
        throw std::runtime_error("Channel is already closed");
    }

    if (channel.local_close_sent) {
        throw std::runtime_error("Request to close channel sent");
    }

    if (data.empty()) {
        throw std::runtime_error("No data to be sent"); 
    }

    if (data.size() > channel.remote_window) {
        throw std::runtime_error("Remote channel doesn't have enough capacity");
    }

    if (data.size() > channel.remote_max_packet) {
        throw std::runtime_error("Packet is too large to be sent");
    }

    std::vector<uint8_t> payload;
    payload.push_back(ssh_message::CHANNEL_DATA);
    auto remote_id = ssh_encoding::encode_uint32(channel.remote_id);
    payload.insert(payload.end(), remote_id.begin(), remote_id.end());
    ssh_encoding::append_string(payload, data);
    return payload;
 }
