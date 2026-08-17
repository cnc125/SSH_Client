#include "socket/socket.hpp"
#include "transport/transport.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <sodium.h>

namespace {
    constexpr uint8_t SSH_MSG_KEXINIT = 20;
}

// read server version string one byte at a time until newline
std::string read_version(Socket& sock) {
    std::string version;
    uint8_t byte;

    while (true) {
        sock.read_exact(&byte, 1);
        if (byte == '\n') break;
        if (byte != '\r') version += static_cast<char>(byte);
    }
    return version;
}

//exchange identification strings with the server
void exchange_identification(Socket &sock) {
    std::string server_version = read_version(sock);
        std::cout << "Server: " << server_version << "\n";

        if (server_version.substr(0, 7) != "SSH-2.0")
            throw std::runtime_error("Not SSH-2.0: " + server_version);

        std::string client_version = "SSH-2.0-ConorSSH_0.1";
        std::string line = client_version + "\r\n";
        std::vector<uint8_t> bytes(line.begin(), line.end());
        sock.write_exact(bytes.data(), bytes.size());

        std::cout << "Client: " << client_version << "\n";
        std::cout << "Version exchange complete\n";
}

//receive SSH_MSG_KEXINIT
void receive_kexinit(Transport& transport) {
    std::vector<uint8_t> payload = transport.receive_packet();
    if (payload.empty()) {
        throw std::runtime_error("SSH Packet is empty");
    }
    if (payload[0] != SSH_MSG_KEXINIT) {
        throw std::runtime_error("SSH Packet doesn't contain expected KEX information");
    }
    std::cout << "Received message 20\n";

}

int main() {
    try {
        int result = sodium_init();
        if (result == -1) {
            throw std::runtime_error("Sodium could not be initialised");
        }
        Socket sock("127.0.0.1", 22);
        exchange_identification(sock);

        Transport transport(sock);
        receive_kexinit(transport);


    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}