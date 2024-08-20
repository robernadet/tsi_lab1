# Compilador
CC = gcc

# Opciones de compilación
CFLAGS = -Wall -I$(INCLUDEDIR)

# Opciones de enlazado
LDFLAGS = -lpam -lcotp -lssl -lcrypto -lcurl -lqrencode -lgcrypt -L$(LIBDIR)

# Directorios
LIBDIR = lib
INCLUDEDIR = include

# Archivos de objetos
OBJS = main.o pam_totp_2fa.o

# Objetivo principal
all: pam_totp_2fa.so main

# Compilar la biblioteca PAM
pam_totp_2fa.so: pam_totp_2fa.o
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Compilar los archivos de objetos
main.o: src/main.c
	$(CC) $(CFLAGS) -c $< -o $@

pam_totp_2fa.o: src/pam_totp_2fa.c
	$(CC) $(CFLAGS) -c $< -o $@

# Enlazar el ejecutable principal
main: main.o
	$(CC) -o $@ $^ $(LDFLAGS)

# Limpiar los archivos generados
clean:
	rm -f $(OBJS) pam_totp_2fa.so main

.PHONY: all clean
