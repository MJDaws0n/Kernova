# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude

# Folders
SRC = src
INCLUDE = include
BUILD = build

# Source files
SRCS = $(wildcard $(SRC)/*.c)
OBJS = $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(SRCS))

# Final executable
TARGET = $(BUILD)/kernova_bin

# Default target
all: $(BUILD) $(TARGET)

# Link object files into executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

# Compile .c files into .o files
$(BUILD)/%.o: $(SRC)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# Create build folder if it doesn't exist
$(BUILD):
	mkdir -p $(BUILD)

# Clean build files
clean:
	rm -rf $(BUILD)

.PHONY: all clean