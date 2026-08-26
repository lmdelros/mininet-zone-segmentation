CXX := g++
CXXFLAGS := -std=c++11 -Wall -Wextra -O2 -pthread
TARGET := firewall_daemon
SRC := firewall_daemon.cpp

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
