#include "terminal.hpp"
#include <termios.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>

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