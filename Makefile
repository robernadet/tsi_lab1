# Definir el compilador
CC = gcc

# Definir las banderas del compilador
CFLAGS = -Wall -fPIC -I/usr/include/security -I/usr/local/include

# Definir las banderas del enlazador
LDFLAGS = -L/usr/local/lib

# Bibliotecas a vincular
LIBS = -lcotp -lgcrypt -lpam -lpam_misc

# Definir el nombre del módulo PAM a generar
PAM_TARGET = pam_totp_2fa.so

# Definir el nombre del archivo ejecutable principal
MAIN_TARGET = main

# Definir los archivos fuente
PAM_SRCS = src/pam_totp_2fa.c
MAIN_SRCS = src/main.c

# Definir el directorio de instalación de módulos PAM
PAM_MODULE_DIR = /lib/security

# Regla para compilar todo (módulo PAM y ejecutable)
all: $(PAM_TARGET) $(MAIN_TARGET)

# Regla para compilar el módulo PAM
$(PAM_TARGET): $(PAM_SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ $(LIBS)

# Regla para compilar el archivo principal
$(MAIN_TARGET): $(MAIN_SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

# Regla para instalar el módulo PAM
install: $(PAM_TARGET)
	install -m 0644 $(PAM_TARGET) $(PAM_MODULE_DIR)

# Regla para limpiar los archivos compilados
clean:
	rm -f $(PAM_TARGET) $(MAIN_TARGET)

# Regla para limpiar y recompilar
rebuild: clean all
