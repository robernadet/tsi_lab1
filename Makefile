# Variables
CC = gcc
CFLAGS = -Wall -Iinclude -fPIC `pkg-config --cflags libgcrypt`
LDFLAGS = -shared
LIBS = -lpam -lcotp -lssl -lcrypto -lcurl -lqrencode `pkg-config --libs libgcrypt`
SRC_DIR = src
OBJ_DIR = obj
INCLUDE_DIR = include
MODULE_TOTP_TARGET = pam_totp_2fa.so
MODULE_STORE_PASSWORD_TARGET = pam_store_password.so
EXEC_TARGET = main
INSTALL_DIR = /lib/x86_64-linux-gnu/security

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Object files
MAIN_OBJ = $(OBJ_DIR)/main.o
MODULE_TOTP_OBJS = $(OBJ_DIR)/pam_totp_2fa.o $(OBJ_DIR)/crypt.o
MODULE_STORE_PASSWORD_OBJS = $(OBJ_DIR)/pam_store_password.o $(OBJ_DIR)/crypt.o

# Targets
all: $(MODULE_TOTP_TARGET) $(MODULE_STORE_PASSWORD_TARGET) $(EXEC_TARGET)

# Build shared modules
$(MODULE_TOTP_TARGET): $(MODULE_TOTP_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(MODULE_STORE_PASSWORD_TARGET): $(MODULE_STORE_PASSWORD_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Build executable
$(EXEC_TARGET): $(MAIN_OBJ)
	$(CC) $(MAIN_OBJ) -o $@ $(LIBS)

# Copy shared modules to the install directory
install: all
	mkdir -p $(INSTALL_DIR)
	cp $(MODULE_TOTP_TARGET) $(INSTALL_DIR)/
	cp $(MODULE_STORE_PASSWORD_TARGET) $(INSTALL_DIR)/

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create object directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Clean up build files
clean:
	rm -rf $(OBJ_DIR) $(MODULE_TOTP_TARGET) $(MODULE_STORE_PASSWORD_TARGET) $(EXEC_TARGET)

.PHONY: all clean install
