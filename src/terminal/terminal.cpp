#include "terminal.hpp"
#include <termios.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>
#include <sys/ioctl.h>
#include <cstdlib>

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
    bool read_succeeded = static_cast<bool>(std::getline(std::cin, password));

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
        info.type = "xterm-256color";
    } else {
        info.type = term_value;
    }

    //fallback values
    info.columns = 80;
    info.rows = 24;

    winsize dimensions{};
    int result = ioctl(STDIN_FILENO, TIOCGWINSZ, &dimensions);

    if (result != -1 && dimensions.ws_col != 0 && dimensions.ws_row != 0) {
        info.columns = dimensions.ws_col;
        info.rows = dimensions.ws_row;
    }

    return info;
    

}