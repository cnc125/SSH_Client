#include "socket.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>


Socket::Socket() {
    fd_ = -1;
}

Socket::~Socket() {
    close();
}

//sets up file descriptor and returns true if successful
bool Socket::create() {
    //get file descriptor that uses IPV4 and TCP
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);

    if (fd_ == -1) {
        return false;
    }

    return true;
}

//connects over TCP using provideded host and port number
bool Socket::connect(const std::string& host, uint16_t port) {
    sockaddr_in addr;
    //IPV4 address
    addr.sin_family = AF_INET;
    //Sets TCP port in network byte order
    addr.sin_port = htons(port);
    //Converts host string intoß binary IPV4 address eg. "192.168.1.10"
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    int result = ::connect(fd_, (sockaddr *)& addr, sizeof(addr));  

    if (result == 0) {
        return true;
    }

    return false;
}

void Socket::read_exact(uint8_t* dst, size_t len) {
    size_t received = 0;

    while (received < len) {
        ssize_t r = read(fd_, dst + received, len - received);

        if (r > 0) {
            received += r;
        } else if (r == 0) {
            throw std::runtime_error("Connection closed");
        } else {
            if (errno == EINTR) continue;
            throw std::runtime_error(strerror(errno));
        }
    }
}

void Socket::write_exact(const uint8_t* src, size_t len) {
    size_t written = 0;

    while (written < len) {
        ssize_t r = write(fd_, src + written, len - written);

        if (r > 0) {
            written += r;
        } else if (r == 0) {
            throw std::runtime_error("Write returned zero");
        } else {
            if (errno == EINTR) continue;
            throw std::runtime_error(strerror(errno));
        }

    }
}

//closes file descriptor and resets properites of socket object
void Socket::close() {
    if (fd_ == -1) {
        return;
    }

    ::close(fd_);
    fd_ = -1;
}

int Socket::get_fd() {
    return fd_;
}