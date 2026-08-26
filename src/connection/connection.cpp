#include "connection.hpp"
#include "common/ssh_encoding.hpp"
#include <stdexcept>
#include <array>
#include <cstddef>

namespace {
    //SSH Message Types
    constexpr uint8_t SSH_MSG_CHANNEL_OPEN = 90;
    constexpr uint8_t SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    constexpr uint8_t SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
    constexpr uint8_t SSH_MSG_GLOBAL_REQUEST = 80;
    constexpr uint8_t SSH_MSG_REQUEST_FAILURE = 82;

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
    payload.push_back(SSH_MSG_CHANNEL_OPEN);
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
    
    if (payload.size() == 0 || payload[0] != SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
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

    if (payload.size() == 0 || payload[0] != SSH_MSG_CHANNEL_OPEN_FAILURE) {
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
    if (payload.size() == 0 || payload[0] != SSH_MSG_GLOBAL_REQUEST) {
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
    payload.push_back(SSH_MSG_REQUEST_FAILURE);
    return payload;
 }