# ConorSSH

This is an SSHv2 client written in C++17; I made the project to strengthen my systems
programming and learn about network protocols and cryptography. This project implements
the SSH protocol itself and is not a wrapped SSH client library.

ConorSSH can negotiate a secure transport, authenticate an OpenSSH server,
verify its persistent identity, perform password authentication, open a PTY,
and run an interactive remote shell.

## Highlights

- SSHv2 identification exchange
- Binary SSH packet framing and cryptographically secure random padding
- `SSH_MSG_KEXINIT` algorithm negotiation
- Curve25519 ephemeral key exchange
- Ed25519 server signature verification
- SHA-256 host-key fingerprints
- Persistent trust-on-first-use host verification
- AES-256-CTR transport encryption
- HMAC-SHA-256 packet authentication
- Encrypted packet sequence tracking
- Password user authentication
- SSH channel flow control and window adjustment
- PTY allocation and interactive remote shells
- Raw local-terminal mode with simultaneous keyboard and socket polling
- EOF, exit-status, and channel-close handling

## Supported Algorithms

| Purpose | Algorithm |
| --- | --- |
| Key exchange | `curve25519-sha256` |
| Server host key | `ssh-ed25519` |
| Encryption | `aes256-ctr` |
| Packet MAC | `hmac-sha2-256` |
| Compression | `none` |
| User authentication | Password |

I chooe this small set of algorithms to keep the implementation focused whilst 
including every major stage of a real SSHv2 connection.

## How It Works

```text
TCP connection
    |
    v
SSH identification exchange
    |
    v
KEXINIT algorithm negotiation
    |
    v
Curve25519 shared-secret calculation
    |
    v
Ed25519 server signature verification
    |
    v
Persistent known-host verification
    |
    v
Session-key derivation and NEWKEYS
    |
    v
Password authentication
    |
    v
Session channel and PTY allocation
    |
    v
Interactive encrypted shell
```

I split the implementation of the SSH protocol into multiple layers

| Module | Responsibility |
| --- | --- |
| `socket` | Controls the TCP connection, reads and writes |
| `transport` | Frames and decodes SSH packets and applies encryption |
| `kex` | Determines algorithms, performs Curve25519 KEX, verifies Ed25519 signatures and constructs keys |
| `known_hosts` | Stores identities of trusted servers |
| `auth` | Validates user password |
| `connection` | Manages channels, requests, data, EOF and closure |
| `terminal` | Handles hidden password input, PTY information, and raw terminal mode |
| `main` | Orchestrates the stages of opening the connection and sending data |

## Dependencies

- A C++17 compiler
- GNU Make
- [libsodium](https://doc.libsodium.org/)
- [OpenSSL](https://www.openssl.org/) development libraries
- A POSIX-compatible operating system

On Ubuntu or Debian:

```bash
sudo apt update
sudo apt install build-essential libsodium-dev libssl-dev
```

An SSH server is required to run the client. For local interoperability testing:

```bash
sudo apt install openssh-server
```

## Build

```bash
make
```

The executable is created at:

```text
bin/ssh
```

Remove generated objects and the executable with:

```bash
make clean
```

## Run

Provide the username and host in `username@host` format:

```bash
./bin/ssh <username>@<host> [port]
```

The port is optional and defaults to `22`. For example:

```bash
./bin/ssh cnc125@127.0.0.1
```

After the host is verified and password authentication succeeds, the client
opens an interactive remote shell. Type `exit` to close the session cleanly.

## Server Identity and Known Hosts

On the first connection, ConorSSH displays the server's SHA-256 host-key
fingerprint and asks whether the key should be trusted. Accepted keys are stored
in:

```text
~/.conorssh/known_hosts
```

Later connections behave as follows:

- A matching key is accepted automatically.
- An unknown host requires explicit approval.
- A changed key produces a warning and the connection is refused.

ConorSSH uses its own intentionally simple known-hosts file instead of modifying
OpenSSH's `~/.ssh/known_hosts` file.

## Cryptography

The project implements SSH message construction, parsing, negotiation, state
management, and protocol orchestration. Established libraries provide the
cryptographic primitives:

- libsodium provides secure randomness, Curve25519, Ed25519, SHA-256,
  HMAC-SHA-256 and Base64 helpers.
- OpenSSL EVP provides AES-256-CTR encryption and decryption.

I decided not to implement custom cryptographic algorithms as they would make the client
less secure without improving the SSH protocol implementation. This allowed me to focus on the more interesting parts of the project for me of implementing SSH correctly.

## Current Limitations

- Password authentication only; public-key user authentication is not supported
- No SSH rekeying during long-lived sessions
- Fixed supported algorithm suite
- One interactive session channel per connection
- No proxying, forwarding, SFTP or SCP support

## What I Learned

This project provided practical experience with:

- Binary network-protocol design and defensive parsing
- Endianness and SSH length-prefixed data types
- Cryptographic key exchange, signatures, fingerprints and session keys
- TCP sockets and exact-length I/O
- POSIX terminal modes and I/O multiplexing with `poll()`
- Flow control, state machines, and protocol error handling

