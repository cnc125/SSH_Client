#pragma once

#include <string>   
#include <cstdint>

class Socket {

public:

    //constructor and deconstructor
    Socket(const std::string& host, uint16_t port);
    ~Socket();

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    //reads len number of bytes from the socket and places them in dst
    void read_exact(uint8_t* dst, size_t len);

    //writes len number of bytes to the sockets from src
    void write_exact(const uint8_t* src, size_t len);

    //returns file descriptor for socket
    int get_fd() const;

private:
    int fd_;

    //sets up file descriptor and returns true if successful
    bool create();

    //connects over TCP using provideded host and port number
    bool connect(const std::string& host, uint16_t port);

    //closes file descriptor and resets properites of socket object
    void close();
};