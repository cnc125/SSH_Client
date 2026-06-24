#include "socket.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <errno.h>
#include <cstring>
#include <iostream>


Socket::Socket(int epoll_fd) : epoll_fd_(epoll_fd) {
    fd_ = -1;
    state_ = State::Uninitialised;
    read_callback_ = nullptr;
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
    
    //sets to non-blocking
    int flags = fcntl(fd_, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd_, F_SETFL, flags);

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

//registers a file descriptor with epoll
bool Socket::register_with_epoll() {
    epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;

    int result = epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd_, &event);

    if (result == -1) {
        int err = errno;
        std::cerr << "epoll_ctl ADD failed: " << strerror(err) << "\n";
        return false;
    }
    return true;
}

//function handles epoll events by calling approriate write and read helpers
bool Socket::handle_epoll_event(uint32_t events) {

    if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        //error or connection closed
        return false;
    }
    if (events & EPOLLIN) {
        if (!pump_read()) {
            return false;
        }
    }
    if (events & EPOLLOUT) {
        if (state_ == State::Connecting) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len);

            if (err == 0) {
                // success
                state_ = State::Connected;
                update_epoll_interest(EPOLLIN);
            } else {
                // handshake failed
                return false;
            }
        } 
        if (state_ == State::Connected) {
            if (!pump_write()) {
                return false;
            }
        }          
    }
    return true;
}

//helper for reading from input steam data
bool Socket::pump_read() {

    char temp[4096];

    while (true) {
        ssize_t n = recv(fd_, temp, sizeof(temp), 0);

        if (n > 0) {
            inbuf_.insert(inbuf_.end(), temp, temp + n);
            continue;
        }

        if (n == 0) {
            return false; //remote closed
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) break;

        return false;  
    }

    if (read_callback_) {
        read_callback_(inbuf_.data(), inbuf_.size());
        inbuf_.clear();
    }

    return true;
}

//helper for writing to output steam
bool Socket::pump_write() {
    while (!outbuf_.empty()) {
        ssize_t n = send(fd_, outbuf_.data(), outbuf_.size(), 0);

        if (n>0) {
            outbuf_.erase(outbuf_.begin(), outbuf_.begin() + n);
            continue;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return true;
        }

        return false;
    }
    update_epoll_interest(EPOLLIN);
    return true;
}

//public function used by other layers to write data to the output
void Socket::write_bytes(const std::vector<uint8_t>& data) {
    outbuf_.insert(outbuf_.end(), data.begin(), data.end());

    update_epoll_interest(EPOLLIN | EPOLLOUT);
}

//public function used by other layers to set callback function for reading input stream data
void Socket::set_read_callback(void (*cb)(const uint8_t*, size_t)) {
    read_callback_ = cb;
}

//updates the events that epoll is monitoring
void Socket::update_epoll_interest(uint32_t new_events) {
    new_events |= EPOLLET;

    epoll_event event;
    event.events = new_events;
    event.data.ptr = this;

    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd_, &event) == -1) {
        int err = errno;
        std::cerr << "epoll_ctl ADD failed: " << strerror(err) << "\n";
    }
}

//returns current state
Socket::State Socket::state() {
    return state_;
}

//closes file descriptor and resets properites of socket object
void Socket::close() {
    if (fd_ == -1) {
        return;
    }

    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd_, nullptr);

    ::close(fd_);
    fd_ = -1;

    inbuf_.clear();
    outbuf_.clear();

    read_callback_ = nullptr;
}