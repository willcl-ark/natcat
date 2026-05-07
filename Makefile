CXX ?= c++
CXXSTD ?= -std=c++17
CXXFLAGS ?= -Wall -Wextra -pedantic -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?=

.PHONY: all clean

all: client

client: client.cpp
	$(CXX) $(CPPFLAGS) $(CXXSTD) $(CXXFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) client
