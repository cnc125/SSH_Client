#pragma once

#include <string>
#include <cstdint>

struct TerminalInfo {
    std::string type;
    uint32_t columns;
    uint32_t rows;
};

class Terminal {

public:
    std::string read_hidden_input(const std::string& prompt);

    TerminalInfo get_terminal_info() const;

private:


};