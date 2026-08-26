#include "terminal.hpp"
#include <termios.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>
#include <sys/ioctl.h>
#include <cstdlib>

namespace {
    constexpr uint32_t DEFAULT_TERMINAL_COLUMNS = 80;
    constexpr uint32_t DEFAULT_TERMINAL_ROWS = 24;
    constexpr const char* DEFAULT_TERMINAL_TYPE = "xterm-256color";
}

Terminal::Terminal() : original_settings_{}, raw_mode_active_(false) {
}

std::string Terminal::read_hidden_input(const std::string& prompt) {
    std::cout << prompt << std::flush;

    termios original;
    if (tcgetattr(STDIN_FILENO, &original) == -1) {
        throw std::runtime_error("Failed to save current terminal settings");
    }
    termios hidden = original;
    hidden.c_lflag &= ~ECHO;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &hidden) == -1) {
        throw std::runtime_error("Failed to disable terminal echo");
    }

    std::string password;
    bool read_succeeded = false;

    try {
        read_succeeded = static_cast<bool>(std::getline(std::cin, password));
    } catch (...) {
        tcsetattr(STDIN_FILENO, TCSANOW, &original);
        std::cout << "\n";
        throw;
    }
    

    if (tcsetattr(STDIN_FILENO, TCSANOW, &original) == -1) {
        throw std::runtime_error("Failed to reenable terminal echo");
    }

    if (!read_succeeded) {
        throw std::runtime_error("Password not read correctly");
    }
    
    std::cout << "\n";

    return password;

}

TerminalInfo Terminal::get_terminal_info() const {
    TerminalInfo info{};
    const char* term_value = std::getenv("TERM");

    if (term_value == nullptr || term_value[0] == '\0') {
        info.type = DEFAULT_TERMINAL_TYPE;
    } else {
        info.type = term_value;
    }

    //fallback values
    info.columns = DEFAULT_TERMINAL_COLUMNS;
    info.rows = DEFAULT_TERMINAL_ROWS;

    winsize dimensions{};
    int result = ioctl(STDIN_FILENO, TIOCGWINSZ, &dimensions);

    if (result != -1 && dimensions.ws_col != 0 && dimensions.ws_row != 0) {
        info.columns = dimensions.ws_col;
        info.rows = dimensions.ws_row;
    }

    return info;
}

void Terminal::enable_raw_mode() {
    if (raw_mode_active_) {
        return;
    }

    if (tcgetattr(STDIN_FILENO, &original_settings_) == -1) {
        throw std::runtime_error("Failed to read terminal settings");
    }

    termios raw_settings = original_settings_;
    cfmakeraw(&raw_settings);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw_settings) == -1) {
        throw std::runtime_error("Failed to enable raw terminal mode");
    }

    raw_mode_active_ = true;
}

void Terminal::restore() {
    if (!raw_mode_active_) {
        return;
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &original_settings_) == -1) {
        throw std::runtime_error("Failed to restore terminal settings");
    }

    raw_mode_active_ = false;
}

Terminal::~Terminal() {
    if (raw_mode_active_) {
        tcsetattr(STDIN_FILENO, TCSANOW, &original_settings_);
    }
}