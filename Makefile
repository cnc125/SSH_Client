CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g -I src
LDFLAGS  = -lsodium -lcrypto

TARGET   = bin/ssh

SRCS     = src/main.cpp \
           src/common/ssh_encoding.cpp \
           src/socket/socket.cpp \
           src/transport/transport.cpp \
           src/kex/kex.cpp \
           src/auth/auth.cpp \
           src/connection/connection.cpp \
           src/terminal/terminal.cpp

OBJS     = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

install: $(TARGET)
	mkdir -p ~/.local/bin
	cp $(TARGET) ~/.local/bin/ssh

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all install clean