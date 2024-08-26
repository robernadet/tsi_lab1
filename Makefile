# Variables
CC = gcc
CFLAGS = -Wall -Iinclude -fPIC
LDFLAGS = -shared
LIBS = -lpam -lcotp -lssl -lcrypto -lcurl -lqrencode -lgcrypt -lpam_misc
SRC_DIR = src
OBJ_DIR = obj
INCLUDE_DIR = include
MODULE_TARGET = pam_totp_2fa.so
EXEC_TARGET = main
INSTALL_DIR = /lib/x86_64-linux-gnu/security

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Object files
MAIN_OBJ = $(OBJ_DIR)/main.o
MODULE_OBJS = $(OBJ_DIR)/pam_totp_2fa.o

# Targets
all: $(MODULE_TARGET) $(EXEC_TARGET)

# Build shared module
$(MODULE_TARGET): $(MODULE_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Build executable
$(EXEC_TARGET): $(MAIN_OBJ)
	$(CC) $(MAIN_OBJ) -o $@ $(LIBS)

# Install the shared module
install: $(MODULE_TARGET)
	mkdir -p $(INSTALL_DIR)
	cp $(MODULE_TARGET) $(INSTALL_DIR)/

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create object directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Clean up build files
clean:
	rm -rf $(OBJ_DIR) $(MODULE_TARGET) $(EXEC_TARGET)

.PHONY: all clean install
