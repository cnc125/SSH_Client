#pragma once

#include <string>
#include <cstdint>
#include <termios.h>

struct TerminalInfo {
    std::string type;
    uint32_t columns;
    uint32_t rows;
};

class Terminal {

public:

    Terminal();

    //prevent copying
    Terminal(const Terminal&) = delete;
    Terminal& operator=(const Terminal&) = delete;

    ~Terminal();

    std::string read_hidden_input(const std::string& prompt);

    TerminalInfo get_terminal_info() const;

    void enable_raw_mode();
    void restore();

private:

    termios original_settings_;
    bool raw_mode_active_;


};