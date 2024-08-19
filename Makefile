CC = gcc
CFLAGS = -Wall -Iinclude
LDFLAGS = -lcotp -lpam

TARGETS = main pam_totp_2fa.so

all: $(TARGETS)

main: src/main.c
	$(CC) $(CFLAGS) -o main src/main.c $(LDFLAGS)

pam_totp_2fa.so: src/pam_totp_2fa.c
	$(CC) $(CFLAGS) -fPIC -shared -o pam_totp_2fa.so src/pam_totp_2fa.c $(LDFLAGS)

clean:
	rm -f main pam_totp_2fa.so
