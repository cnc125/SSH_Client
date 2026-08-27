#pragma once

#include <string>   
#include <cstdint>

// Owns one connected TCP socket and provides exact-length I/O
class Socket {

public:

    // Connects to the specified host and port; closes the socket on destruction
    Socket(const std::string& host, uint16_t port);
    ~Socket();

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    // Reads exactly len bytes into dst or throws if the connection closes
    void read_exact(uint8_t* dst, size_t len);

    // Writes exactly len bytes from src or throws on failure
    void write_exact(const uint8_t* src, size_t len);

    // Returns the native socket descriptor for polling
    int get_fd() const;

private:
    int fd_;

    // Creates the underlying IPv4 TCP socket
    bool create();

    // Connects the socket to the supplied host and port
    bool connect(const std::string& host, uint16_t port);

    // Closes the descriptor and marks the socket as inactive
    void close();
};