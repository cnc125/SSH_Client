#include "socket.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>


Socket::Socket(const std::string& host, uint16_t port) {
    fd_ = -1;

    if (!create()) throw std::runtime_error("Failed to create socket");

    if (!connect(host, port)) throw std::runtime_error("Failed to connect to " + host);
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
    struct addrinfo addr_info{};
    addr_info.ai_family = AF_INET; //IPV4
    addr_info.ai_socktype = SOCK_STREAM; //TCP

    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &addr_info, &res) != 0) {
        return false;
    }

    int result = ::connect(fd_, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (result == 0) {
        return true;
    }

    return false;
}

//reads len number of bytes from the socket and places them in dst
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

//writes len number of bytes to the sockets from src
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

//returns file descriptor for socket
int Socket::get_fd() const {
    return fd_;
}