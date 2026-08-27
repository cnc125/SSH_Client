#pragma once

#include <string>
#include <cstdint>
#include <termios.h>

// Local terminal type and character dimensions sent in a PTY request
struct TerminalInfo {
    std::string type;
    uint32_t columns;
    uint32_t rows;
};

// Manages local terminal information, hidden input, and raw mode
class Terminal {

public:

    // Starts with no saved terminal mode active
    Terminal();

    // Terminal-mode ownership must not be copied
    Terminal(const Terminal&) = delete;
    Terminal& operator=(const Terminal&) = delete;

    // Restores saved terminal settings if necessary
    ~Terminal();

    // Reads one line while temporarily disabling local terminal echo
    std::string read_hidden_input(const std::string& prompt);

    // Returns the local terminal type and current character dimensions
    TerminalInfo get_terminal_info() const;

    // Enables byte-at-a-time input and saves the previous terminal settings
    void enable_raw_mode();
    // Restores the terminal settings saved before raw mode
    void restore();

private:

    termios original_settings_;
    bool raw_mode_active_;


};