#include "socket/socket.hpp"
#include "transport/transport.hpp"
#include "kex/kex.hpp"
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

//send SSH_MSG_KEXINIT
KexInit send_kexinit(Transport& transport) {
    Kex kex;
    KexInit payload = kex.create_client_kexinit();
    transport.send_packet(payload.raw_payload);
    return payload;
}

//receive SSH_MSG_KEXINIT
KexInit receive_kexinit(Transport& transport) {
    std::vector<uint8_t> payload = transport.receive_packet();
    if (payload.empty()) {
        throw std::runtime_error("SSH Packet is empty");
    }
    if (payload[0] != SSH_MSG_KEXINIT) {
        throw std::runtime_error("SSH Packet doesn't contain expected KEX information");
    }
    std::cout << "Received message 20\n";
    Kex kex;
    KexInit server_kexinit = kex.parse_kexinit(payload);
    return server_kexinit;
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
        KexInit client_kexinit = send_kexinit(transport);
        KexInit server_kexinit = receive_kexinit(transport);

        Kex kex;
        NegotiatedAlgorithms algorithms = kex.negotiate(client_kexinit, server_kexinit);

        std::cout << "Negotiated algorithms:\n";
        std::cout << "KEX: " << algorithms.kex_algorithm << '\n';
        std::cout << "Host key: " << algorithms.host_key_algorithm << '\n';
        std::cout << "Encryption client -> server: "
          << algorithms.encryption_cs_algorithm << '\n';
        std::cout << "Encryption server -> client: "
          << algorithms.encryption_sc_algorithm << '\n';
        std::cout << "MAC client -> server: "
          << algorithms.mac_cs_algorithm << '\n';
        std::cout << "MAC server -> client: "
          << algorithms.mac_sc_algorithm << '\n';
        std::cout << "Compression client -> server: "
          << algorithms.compression_cs_algorithm << '\n';
        std::cout << "Compression server -> client: "
          << algorithms.compression_sc_algorithm << '\n';

        Curve25519State keypair;
        if (algorithms.kex_algorithm == "curve25519-sha256") {
            keypair = kex.create_curve25519_keypair();
        } else {
            throw std::runtime_error("Negotiated algorithm not implemented");
        }
        std::vector<uint8_t> ecdh_init = kex.create_ecdh_init_payload(keypair);
        transport.send_packet(ecdh_init);

        std::cout << "Sent SSH_MSG_KEX_ECDH_INIT\n";

        auto reply = transport.receive_packet();
        if (reply.empty()) {
            throw std::runtime_error("Empty SSH reply");
        }
        if (reply[0] != 31) {
            throw std::runtime_error("Expected an SSH_MSG_KEX_ECDH_REPLY");
        } else {
            std::cout << "Received SSH_MSG_KEX_ECDH_REPLY\n";
        }
        EcdhReply ecdh_reply = kex.parse_ecdh_reply(reply);
        kex.calculate_shared_secret(keypair, ecdh_reply.server_public_key);
        std::cout << "Shared secret calculated successfully\n";


    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}