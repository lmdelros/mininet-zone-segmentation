CXX := g++
CXXFLAGS := -std=c++11 -Wall -Wextra -O2 -pthread
TARGET := firewall_daemon
SRC := firewall_daemon.cpp
# Generated from ../policy.json; not committed. The generator runs on
# every build but only rewrites the header when the policy changed, so
# an unchanged policy doesn't trigger a recompile.
POLICY_HEADER := policy_generated.h
PYTHON ?= python3

.PHONY: all run clean FORCE

all: $(TARGET)

$(POLICY_HEADER): FORCE
	$(PYTHON) ../tools/gen_policy_header.py ../policy.json -o $@

$(TARGET): $(SRC) $(POLICY_HEADER)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET) $(POLICY_HEADER)
