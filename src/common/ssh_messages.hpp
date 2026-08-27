#pragma once

#include <cstdint>

// SSH transport, authentication, and connection protocol message numbers
namespace ssh_message {

inline constexpr uint8_t SERVICE_REQUEST = 5;
inline constexpr uint8_t SERVICE_ACCEPT = 6;

inline constexpr uint8_t KEXINIT = 20;
inline constexpr uint8_t NEWKEYS = 21;
inline constexpr uint8_t KEX_ECDH_INIT = 30;
inline constexpr uint8_t KEX_ECDH_REPLY = 31;

inline constexpr uint8_t USERAUTH_REQUEST = 50;
inline constexpr uint8_t USERAUTH_FAILURE = 51;
inline constexpr uint8_t USERAUTH_SUCCESS = 52;

inline constexpr uint8_t GLOBAL_REQUEST = 80;
inline constexpr uint8_t REQUEST_SUCCESS = 81;
inline constexpr uint8_t REQUEST_FAILURE = 82;

inline constexpr uint8_t CHANNEL_OPEN = 90;
inline constexpr uint8_t CHANNEL_OPEN_CONFIRMATION = 91;
inline constexpr uint8_t CHANNEL_OPEN_FAILURE = 92;
inline constexpr uint8_t CHANNEL_WINDOW_ADJUST = 93;
inline constexpr uint8_t CHANNEL_DATA = 94;
inline constexpr uint8_t CHANNEL_EXTENDED_DATA = 95;
inline constexpr uint8_t CHANNEL_EOF = 96;
inline constexpr uint8_t CHANNEL_CLOSE = 97;
inline constexpr uint8_t CHANNEL_REQUEST = 98;
inline constexpr uint8_t CHANNEL_SUCCESS = 99;
inline constexpr uint8_t CHANNEL_FAILURE = 100;

} // namespace ssh_message
