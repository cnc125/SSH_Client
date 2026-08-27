#include "socket/socket.hpp"
#include "transport/transport.hpp"
#include "connection/connection.hpp"
#include "auth/auth.hpp"
#include "kex/kex.hpp"
#include "terminal/terminal.hpp"
#include <iostream>
#include <array>
#include <cstddef>
#include <string>
#include <vector>
#include <stdexcept>
#include <sodium.h>
#include <poll.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include "known_hosts/known_hosts.hpp"
#include "common/ssh_messages.hpp"
#include <cstdlib>

namespace {
    struct ClientConfig {
        std::string hostname = "127.0.0.1";
        uint16_t port = 22;
        std::string username = "cnc125";
        std::string identification = "SSH-2.0-ConorSSH_0.1";
        std::string known_hosts_relative_path = "/.conorssh/known_hosts";
    };

    constexpr uint32_t LOCAL_WINDOW_TARGET = 1024 * 1024;
    constexpr uint32_t LOCAL_WINDOW_THRESHOLD = 512 * 1024;
    constexpr uint32_t LOCAL_MAX_PACKET_SIZE = 32 * 1024;
    constexpr uint32_t INITIAL_CHANNEL_ID = 0;
    constexpr std::size_t SHA256_DIGEST_SIZE = 32;
    constexpr std::size_t KEYBOARD_BUFFER_SIZE = 1024;
    constexpr std::size_t KEYBOARD_INPUT_INDEX = 0;
    constexpr std::size_t SOCKET_INPUT_INDEX = 1;
    constexpr std::size_t POLL_INPUT_COUNT = 2;
    constexpr int POLL_WAIT_INDEFINITELY = -1;
    constexpr std::size_t NEWKEYS_PAYLOAD_SIZE = 1;
}

struct IdentificationExchange {
    std::string client;
    std::string server;
};

std::string format_sha256_fingerprint(const std::array<uint8_t, SHA256_DIGEST_SIZE>& fingerprint) {
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
IdentificationExchange exchange_identification(Socket &sock, const std::string& client_version) {

    IdentificationExchange id_exchange{};

    std::string server_version = read_version(sock);
    id_exchange.server = server_version;

    if (server_version.substr(0, 7) != "SSH-2.0")
        throw std::runtime_error("Not SSH-2.0: " + server_version);

    id_exchange.client = client_version;
    std::string line = client_version + "\r\n";
    std::vector<uint8_t> bytes(line.begin(), line.end());
    sock.write_exact(bytes.data(), bytes.size());

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
    if (payload[0] != ssh_message::KEXINIT) {
        throw std::runtime_error("SSH Packet doesn't contain expected KEX information");
    }
    Kex kex;
    KexInit server_kexinit = kex.parse_kexinit(payload);
    return server_kexinit;
}

void handle_global_request(const std::vector<uint8_t>& payload, Connection& connection, Transport& transport) {
    GlobalRequest gr = connection.parse_global_request(payload);
    if (gr.want_reply) {
        transport.send_packet(connection.create_request_failure());
    }
}

void open_session_channel(Connection& connection, Transport& transport, Channel& channel) {
    transport.send_packet(connection.create_session_open(channel));

    while (!channel.open) {
        auto session_open_response = transport.receive_packet();
        if (session_open_response.empty()) {
            throw std::runtime_error("Packet contained 0 bytes");
        }

        if (session_open_response[0] == ssh_message::CHANNEL_OPEN_CONFIRMATION) {
            connection.parse_open_confirmation(session_open_response, channel);
        }
        else if (session_open_response[0] == ssh_message::CHANNEL_OPEN_FAILURE) {
            ChannelOpenFailure failure = connection.parse_open_failure(session_open_response, channel);
            throw std::runtime_error("Connection failed to open");
        }
        else if (session_open_response[0] == ssh_message::GLOBAL_REQUEST) {
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
        if (command_response.empty()) {
            throw std::runtime_error("Packet contained 0 bytes");
        }
        
        if (command_response[0] == ssh_message::CHANNEL_SUCCESS) {
            connection.validate_channel_success(command_response, channel);
            request_accepted = true;
        }
        else if (command_response[0] == ssh_message::CHANNEL_FAILURE) {
            connection.validate_channel_failure(command_response, channel);
            throw std::runtime_error(request_name + " request rejected");
        }
        else if (command_response[0] == ssh_message::GLOBAL_REQUEST) {
            handle_global_request(command_response, connection, transport);
        }
        else if (command_response[0] == ssh_message::CHANNEL_WINDOW_ADJUST) {
            connection.parse_window_adjust(command_response, channel);
        }
        else {
            throw std::runtime_error("Unexpected response received while waiting for " + request_name);
        }
    }
}

void request_pty(Connection& connection, Transport& transport, Channel& channel, const TerminalInfo& terminal_info) {
    transport.send_packet(connection.create_pty_request(channel, terminal_info.type, terminal_info.columns, terminal_info.rows));
    wait_for_channel_request_result(connection, transport, channel, "pty-req");
}

void request_shell(Connection& connection, Transport& transport, Channel& channel) {
    transport.send_packet(connection.create_shell_request(channel));
    wait_for_channel_request_result(connection, transport, channel, "shell");
}

void run_interactive_shell(Socket& sock, Connection& connection, Transport& transport, Channel& channel, Terminal& terminal) {
    terminal.enable_raw_mode();
    pollfd inputs[POLL_INPUT_COUNT]{};
    inputs[KEYBOARD_INPUT_INDEX].fd = STDIN_FILENO;
    inputs[KEYBOARD_INPUT_INDEX].events = POLLIN;
    inputs[SOCKET_INPUT_INDEX].fd = sock.get_fd();
    inputs[SOCKET_INPUT_INDEX].events = POLLIN;

    while (channel.open) {
        if (channel.remote_window > 0) {
            inputs[KEYBOARD_INPUT_INDEX].events = POLLIN;
        } else {
            inputs[KEYBOARD_INPUT_INDEX].events = 0;
        }
        // Wait until keyboard or socket input is ready.
        int read_count = poll(inputs, POLL_INPUT_COUNT, POLL_WAIT_INDEFINITELY);

        if (read_count == -1) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error("poll failed");
        }

        if (inputs[KEYBOARD_INPUT_INDEX].revents & POLLIN) {
            std::array<uint8_t, KEYBOARD_BUFFER_SIZE> keyboard_buffer{};

            std::size_t max_read = keyboard_buffer.size();

            max_read = std::min(max_read, static_cast<std::size_t>(channel.remote_window));

            max_read = std::min(max_read, static_cast<std::size_t>(channel.remote_max_packet));

            ssize_t bytes_read = read(STDIN_FILENO, keyboard_buffer.data(), max_read);
            if (bytes_read == -1) {
                throw std::runtime_error("Failed to read keyboard input");
            }
            if (bytes_read > 0) {
                std::vector<uint8_t> keyboard_data(keyboard_buffer.begin(), keyboard_buffer.begin() + bytes_read);
                transport.send_packet(connection.create_channel_data(channel, keyboard_data));
                channel.remote_window -= keyboard_data.size();
            }
        }
        if (inputs[SOCKET_INPUT_INDEX].revents & POLLIN) {
            std::vector<uint8_t> response = transport.receive_packet();
            if (response.empty()) {
                throw std::runtime_error("Received an empty SSH packet");
            }
            uint8_t message_type = response[0];
            bool consumed_local_window = false;

            if (message_type == ssh_message::CHANNEL_DATA) {
                std::vector<uint8_t> data = connection.parse_channel_data(response, channel);
                std::cout.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
                std::cout.flush();
                consumed_local_window = true;
            } else if (message_type == ssh_message::CHANNEL_WINDOW_ADJUST) {
                connection.parse_window_adjust(response, channel);
            } else if (message_type == ssh_message::GLOBAL_REQUEST) {
                handle_global_request(response, connection, transport);
            } else if (message_type == ssh_message::CHANNEL_EXTENDED_DATA) {
                ChannelExtendedData extended = connection.parse_channel_extended_data(response, channel);
                std::cerr.write(reinterpret_cast<const char*>(extended.data.data()), static_cast<std::streamsize>(extended.data.size()));
                std::cerr.flush();
                consumed_local_window = true;
            } else if (message_type == ssh_message::CHANNEL_EOF) {
                connection.parse_channel_eof(response, channel);
            } else if (message_type == ssh_message::CHANNEL_REQUEST) {
                connection.parse_exit_status(response, channel);
            } else if (message_type == ssh_message::CHANNEL_CLOSE) {
                connection.parse_channel_close(response, channel);
                if (!channel.local_close_sent) {
                    transport.send_packet(
                    connection.create_channel_close(channel));
                    channel.local_close_sent = true;
                }
            } else {
                throw std::runtime_error("Unexpected SSH message during interactive shell");
            }
            if (consumed_local_window && channel.open && channel.local_window <= LOCAL_WINDOW_THRESHOLD) {
                uint32_t difference = LOCAL_WINDOW_TARGET - channel.local_window;

                transport.send_packet(connection.create_window_adjust(channel, difference));

                channel.local_window += difference;
            }
            if (channel.local_close_sent && channel.remote_close_received) {
                channel.open = false;
            }
        }
        if (channel.open && (inputs[SOCKET_INPUT_INDEX].revents & (POLLERR | POLLHUP | POLLNVAL))) {
            throw std::runtime_error("SSH socket closed unexpectedly");
        }
    }
    terminal.restore();
}


// Completes key exchange, verifies the host, and enables encrypted transport
void perform_key_exchange(Transport& transport, const IdentificationExchange& id, KnownHosts& known_hosts, const std::string& hostname) {
    KexInit client_kexinit = send_kexinit(transport);
    KexInit server_kexinit = receive_kexinit(transport);

    Kex kex;
    NegotiatedAlgorithms algorithms = kex.negotiate(client_kexinit, server_kexinit);

    Curve25519State keypair;
    if (algorithms.kex_algorithm == "curve25519-sha256") {
        keypair = kex.create_curve25519_keypair();
    } else {
        throw std::runtime_error("Negotiated algorithm not implemented");
    }
    std::vector<uint8_t> ecdh_init = kex.create_ecdh_init_payload(keypair);
    transport.send_packet(ecdh_init);

    auto reply = transport.receive_packet();
    if (reply.empty()) {
        throw std::runtime_error("Empty SSH reply");
    }
    if (reply[0] != ssh_message::KEX_ECDH_REPLY) {
        throw std::runtime_error("Expected an SSH_MSG_KEX_ECDH_REPLY");
    }
    EcdhReply ecdh_reply = kex.parse_ecdh_reply(reply);
    kex.calculate_shared_secret(keypair, ecdh_reply.server_public_key);

    std::array<uint8_t, SHA256_DIGEST_SIZE> exchange_hash = kex.calculate_exchange_hash(id.client, id.server, client_kexinit, server_kexinit, keypair, ecdh_reply);

    Ed25519VerificationData verification_data = kex.parse_ed25519_verification_data(ecdh_reply, algorithms.host_key_algorithm);

    kex.verify_ed25519_signature(verification_data, exchange_hash);
    std::array<uint8_t, SHA256_DIGEST_SIZE> fingerprint = kex.calculate_host_key_fingerprint(ecdh_reply.server_host_key);

    std::string fingerprint_text = format_sha256_fingerprint(fingerprint);
    HostKeyStatus host_status = known_hosts.check(hostname, algorithms.host_key_algorithm, ecdh_reply.server_host_key);

    if (host_status == HostKeyStatus::Match) {
        std::cout << "Server host key matches known host\n";
    } else if (host_status == HostKeyStatus::Changed) {
        std::cerr << "WARNING: Server host key has changed!\n";
        std::cerr << "Received fingerprint: " << fingerprint_text << '\n';
        throw std::runtime_error("Refusing connection due to changed host key");
    } else {
        std::cout << "Unknown server host key\n";
        std::cout << "Fingerprint: " << fingerprint_text << '\n';

        std::cout << "Do you trust this host key? [yes/no]: ";

        std::string answer;
        std::getline(std::cin, answer);

        if (answer != "yes") {
            throw std::runtime_error("Host key was not trusted");
        }

        known_hosts.add(hostname, algorithms.host_key_algorithm, ecdh_reply.server_host_key);
        std::cout << "Host key saved\n";
    }

    std::array<uint8_t, SHA256_DIGEST_SIZE> session_id = exchange_hash;

    TransportKeyMaterial transport_keys = kex.derive_transport_keys(keypair.shared_secret, exchange_hash, session_id);

    //send NEWKEYS
    std::vector<uint8_t> payload_newkeys{};
    payload_newkeys.push_back(ssh_message::NEWKEYS);
    transport.send_packet(payload_newkeys);
    transport.enable_outgoing_encryption(transport_keys.iv_cs, transport_keys.encryption_key_cs, transport_keys.mac_key_cs);

    //get server NEWKEYS response
    std::vector<uint8_t> server_newkeys = transport.receive_packet();
    if (server_newkeys.size() != NEWKEYS_PAYLOAD_SIZE) {
        throw std::runtime_error("Expected a packet of length 1 byte");
    }
    if (server_newkeys[0] != ssh_message::NEWKEYS) {
        throw std::runtime_error("Expected a SSH_MSG_NEWKEYS packet");
    }
    transport.enable_incoming_encryption(transport_keys.iv_sc, transport_keys.encryption_key_sc, transport_keys.mac_key_sc);
}

// Authenticates the configured user with a password
void authenticate_user(Transport& transport, Terminal& terminal, const std::string& username) {
    //authentication
    Auth auth;
    std::vector<uint8_t> payload = auth.create_service_request();
    transport.send_packet(payload);

    std::vector<uint8_t> auth_response = transport.receive_packet();
    auth.validate_service_accept(auth_response);


    transport.send_packet(auth.create_none_auth_request(username));
    auth.parse_auth_failure(transport.receive_packet());

    std::string password = terminal.read_hidden_input("Password: ");
    std::vector<uint8_t> auth_request = auth.create_password_auth_request(username, password);
    transport.send_packet(auth_request);
    auth_response = transport.receive_packet();
    if (auth_response.empty()) {
        throw std::runtime_error("Packet contained 0 bytes");
    }
    if (auth_response[0] == ssh_message::USERAUTH_SUCCESS) {
        auth.validate_auth_success(auth_response);
        std::cout << "Authentication Complete\n";
    }
    else if (auth_response[0] == ssh_message::USERAUTH_FAILURE) {
        auth.parse_auth_failure(auth_response);
        throw std::runtime_error("Password authentication rejected");
    }
    else {
        throw std::runtime_error("Unexpected response - authentication");
    }

}

// Opens a session channel and runs the interactive remote shell
void run_connection_session(Socket& sock, Transport& transport, Terminal& terminal) {
    //CONNECTION LAYER
    Connection connection;
    Channel channel{};
    channel.local_id = INITIAL_CHANNEL_ID;
    channel.local_window = LOCAL_WINDOW_TARGET;
    channel.local_max_packet = LOCAL_MAX_PACKET_SIZE;

    open_session_channel(connection, transport, channel);
    TerminalInfo terminal_info = terminal.get_terminal_info();
    request_pty(connection, transport, channel, terminal_info);
    request_shell(connection, transport, channel);
    run_interactive_shell(sock, connection, transport, channel, terminal);

    if (channel.exit_status_received) {
        std::cout << "\nRemote exit status: " << channel.exit_status << '\n';
    }
}

int main() {
    try {
        const ClientConfig config{};
        int result = sodium_init();
        if (result == -1) {
            throw std::runtime_error("Sodium could not be initialised");
        }
        const char* home_directory = std::getenv("HOME");

        if (home_directory == nullptr) {
            throw std::runtime_error("HOME environment variable could not be accessed");
        }
        KnownHosts known_hosts(std::string(home_directory) + config.known_hosts_relative_path);

        Socket sock(config.hostname, config.port);
        IdentificationExchange id = exchange_identification(sock, config.identification);

        Transport transport(sock);
        perform_key_exchange(transport, id, known_hosts, config.hostname);

        Terminal terminal;
        authenticate_user(transport, terminal, config.username);

        run_connection_session(sock, transport, terminal);
  
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}