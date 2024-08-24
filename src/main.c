#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <gcrypt.h>
#include <cotp.h>
#include <qrencode.h>
#include "../include/utils.h"

// Initialize Libgcrypt
void initialize_libgcrypt() {
  if (!gcry_check_version(GCRYPT_VERSION)) {
    fprintf(stderr, "Error: incorrect Libgcrypt version\n");
    exit(EXIT_FAILURE);
  }
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

// Function to generate a secure random seed of 20 bytes
char *generate_random_seed() {
  char *random_seed = malloc(SEED_SIZE);
  if (!random_seed) {
    fprintf(stderr, "Error allocating memory for the seed\n");
    return NULL;
  }
  gcry_randomize(random_seed, SEED_SIZE, GCRY_STRONG_RANDOM);
  return random_seed;
}

void saveSeed(const char *base32, const char *username) {
  char filepath[256];
  snprintf(filepath, sizeof(filepath), "/home/%s/.totp_seed", username);

  umask(077); // Only owner can read/write
  FILE *file = fopen(filepath, "w");
  if (file == NULL) {
    perror("Error opening the user's seed file");
    return;
  }
  if (fprintf(file, "%s\n", base32) < 0) {
    perror("Error writing the seed to the user's seed file");
  }
  fclose(file);
  printf("Seed saved for user %s in %s.\n", username, filepath);
}

char *generateSeed(const char *username) {
  initialize_libgcrypt();
  char *random_seed = generate_random_seed();
  if (!random_seed) {
    return NULL;
  }
  cotp_error_t err_code = NO_ERROR;
  char *base32 = base32_encode((unsigned char *)random_seed, SEED_SIZE, &err_code);
  free(random_seed);
  if (err_code != NO_ERROR) {
    printf("Error generating the seed: %d\n", err_code);
    return NULL;
  }
  saveSeed(base32, username);
  return base32;
}

void generate_qr_code(const char *username, const char *base32_secret) {
  char url[512];

  snprintf(url, sizeof(url),
           "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
           ISSUER, username, base32_secret, ISSUER, ALGORITHM, DIGITS, PERIOD);

  printf("URL to scan with Google Authenticator: %s\n", url);

  QRcode *qrcode = QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
  if (qrcode != NULL) {
    for (int y = 0; y < qrcode->width; y++) {
      for (int x = 0; x < qrcode->width; x++) {
        printf("%s", qrcode->data[y * qrcode->width + x] & 1 ? "██" : "  ");
      }
      printf("\n");
    }
    QRcode_free(qrcode);
  } else {
    perror("Error generating the QR code");
  }
}

const char *get_username() {
  const char *username = getlogin();
  if (username == NULL) {
    struct passwd *pw = getpwuid(getuid());
    if (pw) {
      username = pw->pw_name;
    } else {
      perror("Could not get the username");
      exit(EXIT_FAILURE);
    }
  }
  return username;
}

int main(int argc, char *argv[]) {
  const char *username = get_username();
  printf("Generating seed for user: %s\n", username);
  char *seed = generateSeed(username);
  if (seed != NULL) {
    generate_qr_code(username, seed);
    free(seed);
  } else {
    printf("There was a problem generating the seed.\n");
  }

  return 0;
}