#pragma once

#include <string>   
#include <cstdint>

class Socket {

public:

    //constructor and deconstructor
    Socket();
    ~Socket();

    //sets up file descriptor and returns true if successful
    bool create();

    //connects over TCP using provideded host and port number
    bool connect(const std::string& host, uint16_t port);

    void read_exact(uint8_t* dst, size_t len);
    void write_exact(const uint8_t* src, size_t len);
    
    //returns current state
    State state();

    //closes file descriptor and resets properites of socket object
    void close();

    int get_fd();

private:
    int fd_;
};