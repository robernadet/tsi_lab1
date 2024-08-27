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
LIB_TARGET = libencrypt_decrypt_seed.a

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c) $(SRC_DIR)/encrypt_decrypt_seed.c
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Object files
MAIN_OBJ = $(OBJ_DIR)/main.o
MODULE_OBJS = $(OBJ_DIR)/pam_totp_2fa.o
LIB_OBJS = $(OBJ_DIR)/encrypt_decrypt_seed.o

# Targets
all: $(MODULE_TARGET) $(EXEC_TARGET) $(LIB_TARGET)

# Build shared module
$(MODULE_TARGET): $(MODULE_OBJS) $(LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Build executable
$(EXEC_TARGET): $(MAIN_OBJ) $(LIB_OBJS)
	$(CC) $(MAIN_OBJ) $(LIB_OBJS) -o $@ $(LIBS)

# Build static library
$(LIB_TARGET): $(LIB_OBJS)
	ar rcs $@ $^

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
	rm -rf $(OBJ_DIR) $(MODULE_TARGET) $(EXEC_TARGET) $(LIB_TARGET)

.PHONY: all clean install
