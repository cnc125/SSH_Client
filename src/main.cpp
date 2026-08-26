#include "socket/socket.hpp"
#include "transport/transport.hpp"
#include "connection/connection.hpp"
#include "auth/auth.hpp"
#include "kex/kex.hpp"
#include "terminal/terminal.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <sodium.h>

namespace {
    constexpr uint8_t SSH_MSG_KEXINIT = 20;
    constexpr uint8_t SSH_MSG_NEWKEYS = 21;
    constexpr uint32_t LOCAL_WINDOW_TARGET = 1024 * 1024;
    constexpr uint32_t LOCAL_WINDOW_THRESHOLD = 512 * 1024;
}

struct IdentificationExchange {
    std::string client;
    std::string server;
};

std::string format_sha256_fingerprint(const std::array<uint8_t, 32>& fingerprint) {
    std::size_t encoded_size = sodium_base64_ENCODED_LEN(fingerprint.size(), sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    std::vector<char> encoded(encoded_size);
    sodium_bin2base64(encoded.data(), encoded.size(), fingerprint.data(), fingerprint.size(), sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    return "SHA256:" + std::string(encoded.data());
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
IdentificationExchange exchange_identification(Socket &sock) {

    IdentificationExchange id_exchange{};

    std::string server_version = read_version(sock);
    id_exchange.server = server_version;
    std::cout << "Server: " << server_version << "\n";

    if (server_version.substr(0, 7) != "SSH-2.0")
        throw std::runtime_error("Not SSH-2.0: " + server_version);

    std::string client_version = "SSH-2.0-ConorSSH_0.1";
    id_exchange.client = client_version;
    std::string line = client_version + "\r\n";
    std::vector<uint8_t> bytes(line.begin(), line.end());
    sock.write_exact(bytes.data(), bytes.size());

    std::cout << "Client: " << client_version << "\n";
    std::cout << "Version exchange complete\n";

    return id_exchange;
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

void handle_global_request(const std::vector<uint8_t>& payload, Connection& connection, Transport& transport) {
    GlobalRequest gr = connection.parse_global_request(payload);
    std::cout << "Received SSH_MSG_GLOBAL_REQUEST: " << gr.request_name << "\n";
    if (gr.want_reply) {
        transport.send_packet(connection.create_request_failure());
    }
}

void open_session_channel(Connection& connection, Transport& transport, Channel& channel) {
    transport.send_packet(connection.create_session_open(channel));

    while (!channel.open) {
        auto session_open_response = transport.receive_packet();
        if (session_open_response.size() == 0) {
            throw std::runtime_error("Packet contained 0 bytes");
        }

        if (session_open_response[0] == 91) {
            connection.parse_open_confirmation(session_open_response, channel);
            std::cout << "Connection opened\n";
        }
        else if (session_open_response[0] == 92) {
            ChannelOpenFailure failure = connection.parse_open_failure(session_open_response, channel);
            throw std::runtime_error("Connection failed to open");
        }
        else if (session_open_response[0] == 80) {
            handle_global_request(session_open_response, connection, transport);
        } else {
            throw std::runtime_error("Unexpected response received during session channel opening");
        }
    }
}

void wait_for_channel_request_result(Connection& connection, Transport& transport, Channel& channel, const std::string& request_name) {
    bool request_accepted = false;

    while (!request_accepted) {
        auto command_response = transport.receive_packet();
        if (command_response.size() == 0) {
            throw std::runtime_error("Packet contained 0 bytes");
        }
        
        if (command_response[0] == 99) {
            connection.validate_channel_success(command_response, channel);
            std::cout << request_name + " request accepted\n";
            request_accepted = true;
        }
        else if (command_response[0] == 100) {
            connection.validate_channel_failure(command_response, channel);
            throw std::runtime_error(request_name + " request rejected");
        }
        else if (command_response[0] == 80) {
            handle_global_request(command_response, connection, transport);
        }
        else if (command_response[0] == 93) {
            connection.parse_window_adjust(command_response, channel);
        }
        else {
            throw std::runtime_error("Unexpected response received while waiting for " + request_name);
        }
    }
}


void request_exec(Connection& connection, Transport& transport, Channel& channel, const std::string& command) {
    transport.send_packet(connection.create_exec_request(channel, command));
    wait_for_channel_request_result(connection, transport, channel, "exec");
}

uint32_t process_command_messages(Connection& connection, Transport& transport, Channel& channel) {
    while (channel.open) {
        std::vector<uint8_t> response = transport.receive_packet();
        bool consumed_local_window = false;
        if (response.size() == 0) {
            throw std::runtime_error("Packet contained 0 bytes");
        }

        uint8_t message_type = response[0];

        if (message_type == 94) {
            std::vector<uint8_t> data = connection.parse_channel_data(response, channel);
            std::cout.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
            std::cout.flush();
            consumed_local_window = true;
        }
        else if (message_type == 93) {
            connection.parse_window_adjust(response, channel);
        }
        else if (message_type == 80) {
            handle_global_request(response, connection, transport);
        }
        else if (message_type == 96) {
            connection.parse_channel_eof(response, channel);
            std::cout << "EOF received\n";
        }
        else if (message_type == 98) {
            ChannelExitStatus channel_exit_status = connection.parse_exit_status(response, channel);
            std::cout << "Remote exit status: " << channel_exit_status.exit_status << "\n";
        }
        else if (message_type == 97) {
            connection.parse_channel_close(response, channel);
            if (!channel.local_close_sent) {
                transport.send_packet(connection.create_channel_close(channel));
                channel.local_close_sent = true;
            }
            
            if (channel.local_close_sent && channel.remote_close_received) {
                channel.open = false;
                std::cout << "Channel closed successfully\n";
            }
        }
        else if (message_type == 95) {
            ChannelExtendedData channel_extended_data = connection.parse_channel_extended_data(response, channel);
            std::cerr.write(reinterpret_cast<const char*>(channel_extended_data.data.data()),static_cast<std::streamsize>(channel_extended_data.data.size()));
            std::cerr.flush();
            consumed_local_window = true;
        }
        else {
            throw std::runtime_error("Unexpected message received when processing command");
        }

        if (consumed_local_window && channel.open && channel.local_window <= LOCAL_WINDOW_THRESHOLD) {
            uint32_t difference = LOCAL_WINDOW_TARGET - channel.local_window;
            auto adjust_packet = connection.create_window_adjust(channel, difference);
            transport.send_packet(adjust_packet);
            channel.local_window += difference;
        }
    }
    if (!channel.exit_status_received) {
        throw std::runtime_error("No exit status available");
    }
    return channel.exit_status;
}

void request_pty(Connection& connection, Transport& transport, Channel& channel, const TerminalInfo& terminal_info) {
    transport.send_packet(connection.create_pty_request(channel, terminal_info.type, terminal_info.columns, terminal_info.rows));
    wait_for_channel_request_result(connection, transport, channel, "pty-req");
}

int main() {
    try {
        int result = sodium_init();
        if (result == -1) {
            throw std::runtime_error("Sodium could not be initialised");
        }
        Socket sock("127.0.0.1", 22);
        IdentificationExchange id = exchange_identification(sock);

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

        std::array<uint8_t, 32> exchange_hash = kex.calculate_exchange_hash(id.client, id.server, client_kexinit, server_kexinit, keypair, ecdh_reply);

        Ed25519VerificationData verification_data = kex.parse_ed25519_verification_data(ecdh_reply, algorithms.host_key_algorithm);

        kex.verify_ed25519_signature(verification_data, exchange_hash);
        std::array<uint8_t, 32> fingerprint = kex.calculate_host_key_fingerprint(ecdh_reply.server_host_key);

        std::string fingerprint_text = format_sha256_fingerprint(fingerprint);
        std::cout << "Server host key fingerprint: " << fingerprint_text << '\n';

        std::string answer;

        std::cout << "Do you trust this host key? [yes/no]: ";
        std::getline(std::cin, answer);

        if (answer != "yes") {
            throw std::runtime_error("Host key was not trusted"); 
        }

        std::array<uint8_t, 32> session_id = exchange_hash;

        TransportKeyMaterial transport_keys = kex.derive_transport_keys(keypair.shared_secret, exchange_hash, session_id);

        //send NEWKEYS
        std::vector<uint8_t> payload_newkeys{};
        payload_newkeys.push_back(SSH_MSG_NEWKEYS);
        transport.send_packet(payload_newkeys);
        transport.enable_outgoing_encryption(transport_keys.iv_cs, transport_keys.encryption_key_cs, transport_keys.mac_key_cs);

        //get server NEWKEYS response
        std::vector<uint8_t> server_newkeys = transport.receive_packet();
        if (server_newkeys.size() != 1) {
            throw std::runtime_error("Expected a packet of length 1 byte");
        }
        if (server_newkeys[0] != SSH_MSG_NEWKEYS) {
            throw std::runtime_error("Expected a SSH_MSG_NEWKEYS packet");
        }
        std::cout << "NEWKEYS exchange completed" << "\n";
        transport.enable_incoming_encryption(transport_keys.iv_sc, transport_keys.encryption_key_sc, transport_keys.mac_key_sc);

        //authentication
        Auth auth;
        std::vector<uint8_t> payload = auth.create_service_request();
        transport.send_packet(payload);

        std::vector<uint8_t> auth_response = transport.receive_packet();
        auth.validate_service_accept(auth_response);

        std::cout << "User authentication service accepted\n";

        transport.send_packet(auth.create_none_auth_request("cnc125"));
        AuthFailure auth_failure = auth.parse_auth_failure(transport.receive_packet());
        
        std::cout << "Available Methods: " << auth_failure.available_methods << "\n";
        std::cout << "Partial Success: " << auth_failure.partial_success << "\n";

        Terminal terminal;
        std::string password = terminal.read_hidden_input("Password: ");
        std::vector<uint8_t> auth_request = auth.create_password_auth_request("cnc125", password);
        transport.send_packet(auth_request);
        auth_response = transport.receive_packet();
        if (auth_response.size() == 0) {
            throw std::runtime_error("Packet contained 0 bytes");
        }
        if (auth_response[0] == 52) {
            auth.validate_auth_success(auth_response);
            std::cout << "Authentication Complete\n";
        }
        else if (auth_response[0] == 51) {
            auth.parse_auth_failure(auth_response);
            throw std::runtime_error("Password authentication rejected");
        }
        else {
            throw std::runtime_error("Unexpected response - authentication");
        }


        //CONNECTION LAYER
        Connection connection;
        Channel channel{};
        channel.local_id = 0;
        channel.local_window = LOCAL_WINDOW_TARGET;
        channel.local_max_packet = 32 * 1024;

        open_session_channel(connection, transport, channel);
        TerminalInfo terminal_info = terminal.get_terminal_info();
        request_pty(connection, transport, channel, terminal_info);
        request_exec(connection, transport, channel, "ls SSH-Cli");
        uint32_t remote_status = process_command_messages(connection, transport, channel);
        
        if (remote_status == 0) {
            std::cout << "Command succeeded\n";
        } else {
            std::cout << "Command failed with status: " << remote_status << '\n';
        } 
  
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}