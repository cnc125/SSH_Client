#include "socket/socket.hpp"
#include <sys/epoll.h>
#include <iostream>

int main() {
    int epoll_fd = epoll_create1(0);

    Socket sock(epoll_fd);
    sock.create();
    sock.set_read_callback([](const uint8_t* data, size_t len) {
        std::cout << "Received " << len << " bytes: ";
        std::cout.write((const char*)data, len);
        std::cout << "\n";
    });
    sock.connect("127.0.0.1", 9000);

    std::string msg = "hello from socket\n";
    sock.write_bytes(std::vector<uint8_t>(msg.begin(), msg.end()));
    epoll_event events[16];
    while (true) {
        int n = epoll_wait(epoll_fd, events, 16, -1);
        for (int i = 0; i < n; i++) {
            Socket* s = (Socket*)events[i].data.ptr;
            if (!s->handle_epoll_event(events[i].events)) {
                std::cout << "Socket closed\n";
                return 0;
            }
        }
    }
}
