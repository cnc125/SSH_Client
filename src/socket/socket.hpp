#pragma once

#include <string>
#include <vector>
#include <cstdint>

class Socket {

public:
    enum class State {
        Uninitialised,
        Created,
        Connecting,
        Connected,
        Closing,
        Closed
    };

    Socket();
    ~Socket();

    bool create();
    bool connect(const std::string& host, uint16_t port);
    bool handle_epoll_event(uint32_t events);
    void write_bytes(const std::vector<uint8_t>& data);
    void set_read_callback(void (*cb)(const uint8_t*, size_t));
    State state();
    void close();

private:
    int fd_;
    int epoll_fd_;
    State state_;

    std::vector<uint8_t> outbuf_;
    std::vector<uint8_t> inbuf_;

    bool register_with_epoll();

    void pump_read();
    void pump_write();
    void update_epoll_interest();

    void (*read_callback_)(const uint8_t*, size_t);

};