CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wpedantic
LDFLAGS  :=
TARGET   := mp3fm
SRC      := mp3fm.cpp

MINGW_CXX := x86_64-w64-mingw32-g++
WIN_TARGET := mp3fm.exe

.PHONY: all clean windows

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

windows: $(WIN_TARGET)

$(WIN_TARGET): $(SRC)
	$(MINGW_CXX) $(CXXFLAGS) -static -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET) $(WIN_TARGET)
