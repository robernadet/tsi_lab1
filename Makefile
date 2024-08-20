# Variables
CC = gcc
CFLAGS = -Wall -Iinclude
LDFLAGS = -lpam -lcotp -lssl -lcrypto

# Archivos fuente
PAM_SRC = src/pam_totp_2fa.c
MAIN_SRC = src/main.c

# Archivos objeto
PAM_OBJ = pam_totp_2fa.o
MAIN_OBJ = main.o

# Nombre del módulo PAM
PAM_MODULE = pam_totp_2fa.so

# Nombre del ejecutable principal
MAIN_EXEC = main

# Regla por defecto
all: $(PAM_MODULE) $(MAIN_EXEC)

# Compilar el módulo PAM
$(PAM_MODULE): $(PAM_OBJ)
	$(CC) -shared -o $@ $(PAM_OBJ) $(LDFLAGS)

# Compilar el programa principal
$(MAIN_EXEC): $(MAIN_OBJ)
	$(CC) -o $@ $(MAIN_OBJ) $(LDFLAGS)

# Regla para compilar el módulo PAM en objeto
$(PAM_OBJ): $(PAM_SRC)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

# Regla para compilar el programa principal en objeto
$(MAIN_OBJ): $(MAIN_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Limpiar archivos generados
clean:
	rm -f $(PAM_OBJ) $(MAIN_OBJ) $(PAM_MODULE) $(MAIN_EXEC)

.PHONY: all clean
