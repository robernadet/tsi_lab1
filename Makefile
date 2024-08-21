# Variables
CC = gcc
CFLAGS = -Wall -Iinclude -fPIC
LDFLAGS = -shared -lpam -lcotp -lssl -lcrypto -lcurl -lqrencode -lgcrypt -Llib
SRC_DIR = src
OBJ_DIR = obj
INCLUDE_DIR = include
TARGET = pam_totp_2fa.so

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Targets
all: $(TARGET)

# Build target
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create object directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Clean up build files
clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean
