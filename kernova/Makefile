# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude

# Optional accurate execution backend (Unicorn + Capstone)
# Auto-detect if available; can be overridden: `make USE_UNICORN=0`
USE_UNICORN ?= 1
PKG_CONFIG ?= pkg-config
HAVE_PKG_CONFIG := $(shell command -v $(PKG_CONFIG) >/dev/null 2>&1 && echo 1 || echo 0)
ifeq ($(HAVE_PKG_CONFIG),1)
HAVE_UNICORN := $(shell $(PKG_CONFIG) --exists unicorn capstone >/dev/null 2>&1 && echo 1 || echo 0)
else
HAVE_UNICORN := 0
endif

# Folders
SRC = src
INCLUDE = include
BUILD = build

# Source files
COMMON_SRCS = $(SRC)/main.c $(SRC)/parse.c $(SRC)/parse_sections.c $(SRC)/startup.c

ifeq ($(USE_UNICORN),1)
ifeq ($(HAVE_UNICORN),1)
SRCS = $(COMMON_SRCS) $(SRC)/execute_unicorn.c
CFLAGS += $(shell $(PKG_CONFIG) --cflags unicorn capstone)
LDFLAGS += $(shell $(PKG_CONFIG) --libs unicorn capstone)
else
SRCS = $(COMMON_SRCS) $(SRC)/execute.c
endif
else
SRCS = $(COMMON_SRCS) $(SRC)/execute.c
endif

OBJS = $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(SRCS))

# Final executable
TARGET = $(BUILD)/kernova_bin

# Default target
all: $(BUILD) $(TARGET)

# Link object files into executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

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