# Makefile

# Compilador
CC = gcc

# Opciones de compilación
CFLAGS = -Wall -Iinclude

# Opciones de enlazado
LDFLAGS = -lpam -lcotp -lssl -lcrypto -lcurl

# Directorios
LIBDIR = lib
INCLUDEDIR = include

# Archivos de objetos
OBJS = main.o

# Objetivo principal
all: pam_totp_2fa.so main

# Compilar la biblioteca PAM
pam_totp_2fa.so: pam_totp_2fa.o
	$(CC) -shared -o $@ $^ -lpam -lcotp -lssl -lcrypto -L$(LIBDIR)

# Compilar el archivo de objetos
main.o: src/main.c
	$(CC) $(CFLAGS) -c $< -o $@

# Enlazar el ejecutable principal
main: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Limpiar los archivos generados
clean:
	rm -f $(OBJS) pam_totp_2fa.so main

.PHONY: all clean
