#include "socket.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <errno.h>
#include <cstring>

Socket::Socket() {

}

Socket::~Socket() {

}

bool Socket::create() {
    //get file descriptor that uses IPV4 and TCP
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);

    if (fd_ == -1) {
        return false;
    }
    
    //sets to non-blocking
    int flags = fcntl(fd_, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd_, F_SETFL, flags);

    state_ = State::Created;
    return true;
}

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
        state_ = State::Connected;
        register_with_epoll();
        return true;
    }

    if (result == -1 && errno == EINPROGRESS) {
        state_ = State::Connecting;
        register_with_epoll();
        return true;
    }

    return false;
}

bool Socket::register_with_epoll() {
    epoll_event event;
    event
}