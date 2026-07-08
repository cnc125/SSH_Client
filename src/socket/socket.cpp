#include "socket.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <errno.h>
#include <cstring>


Socket::Socket() {
    fd_ = -1;
}

Socket::~Socket() {
    close();
}

//sets up file descriptor and sets to non-blocking returns true if successful
bool Socket::create() {
    //get file descriptor that uses IPV4 and TCP
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);

    if (fd_ == -1) {
        return false;
    }

    return true;
}

//connects over TCP using provideded host and port number
//registers file descriptor with epoll
bool Socket::connect(const std::string& host, uint16_t port) {
    sockaddr_in addr;
    //IPV4 address
    addr.sin_family = AF_INET;
    //Sets TCP port in network byte order
    addr.sin_port = htons(port);
    //Converts host string into binary IPV4 address eg. "192.168.1.10"
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    int result = ::connect(fd_, (sockaddr *)& addr, sizeof(addr));  

    if (result == 0) {
        return true;
    }

    return false;
}




//closes file descriptor and resets properites of socket object
void Socket::close() {
    if (fd_ == -1) {
        return;
    }

    ::close(fd_);
    fd_ = -1;
}