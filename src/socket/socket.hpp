#pragma once

#include <string>
#include <vector>
#include <cstdint>

class Socket {

public:
    enum class State {
        Uninitialised,
        Connecting,
        Connected,
        Closing,
        Closed
    };

    //constructor and deconstructor
    Socket(int epoll_fd);
    ~Socket();

    //sets up file descriptor and sets to non-blocking returns true if successful
    bool create();

    //connects over TCP using provideded host and port number
    //registers file descriptor with epoll
    bool connect(const std::string& host, uint16_t port);

    //function handles epoll events by calling approriate write and read helpers
    bool handle_epoll_event(uint32_t events);

    //public function used by other layers to write data to the output
    void write_bytes(const std::vector<uint8_t>& data);

    //public function used by other layers to set callback function for reading input stream data
    void set_read_callback(void (*cb)(const uint8_t*, size_t));
    
    //returns current state
    State state();

    //closes file descriptor and resets properites of socket object
    void close();

private:
    int fd_;
    int epoll_fd_;
    State state_;

    std::vector<uint8_t> outbuf_;
    std::vector<uint8_t> inbuf_;

    //registers a file descriptor with epoll
    bool register_with_epoll();

    //helper for reading from input steam data
    bool pump_read();

    //helper for writing to output steam
    bool pump_write();

    //updates the events that epoll is monitoring
    void update_epoll_interest(uint32_t new_events);

    void (*read_callback_)(const uint8_t*, size_t);

};