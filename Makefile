# Variables
CC = gcc
CFLAGS = -Wall -Iinclude -fPIC
LDFLAGS = -shared
LIBS = -lpam -lcotp -lqrencode -lgcrypt -lpam_misc
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
MAIN_OBJ = $(OBJ_DIR)/main.o $(OBJ_DIR)/encrypt_decrypt_seed.o $(OBJ_DIR)/file_manager.o
MODULE_OBJS = $(OBJ_DIR)/pam_totp_2fa.o $(OBJ_DIR)/encrypt_decrypt_seed.o $(OBJ_DIR)/file_manager.o

# Targets
all: $(MODULE_TARGET) $(EXEC_TARGET)

# Build shared module
$(MODULE_TARGET): $(MODULE_OBJS)
	@echo "Building shared module: $(MODULE_TARGET)"
	@$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Build executable
$(EXEC_TARGET): $(MAIN_OBJ)
	@echo "Building executable: $(EXEC_TARGET)"
	@$(CC) $(MAIN_OBJ) -o $@ $(LIBS)

# Install the shared module
install: $(MODULE_TARGET)
	@echo "Installing module: $(MODULE_TARGET) to $(INSTALL_DIR)"
	@mkdir -p $(INSTALL_DIR)
	@cp $(MODULE_TARGET) $(INSTALL_DIR)/
	@strip $(INSTALL_DIR)/$(MODULE_TARGET)
	@ln -sf $(INSTALL_DIR)/$(MODULE_TARGET) /lib/$(MODULE_TARGET)

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Create object directory if it doesn't exist
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

# Clean up build files
clean:
	@echo "Cleaning up..."
	@rm -rf $(OBJ_DIR) $(MODULE_TARGET) $(EXEC_TARGET)

.PHONY: all clean install
