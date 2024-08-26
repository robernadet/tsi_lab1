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
// #include "crypt.c"

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

//Encriptar
void encrypt_seed(unsigned char key[tam_buff], size_t size_key,unsigned char encrypted[tam_buff],size_t size_encrypted){
   gcry_cipher_hd_t handle;

    unsigned char data[tam_buff] = "Hello, World!";  // Datos de la seed a cifrar

    size_t data_len = sizeof(data);
    
    // Inicializa la biblioteca
    gcry_check_version(NULL);

    // Inicializa el manejador de cifrado (AES-128 en este caso)
    gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
    
    // Configura la clave
    gcry_cipher_setkey(handle, key, size_key);
    
    // Cifra los datos
    gcry_cipher_encrypt(handle, encrypted, size_encrypted, data, data_len);
    

    // Cierra el manejador
    gcry_cipher_close(handle);
  
}

void print_encrypt(unsigned char  buff[tam_buff],size_t size_buff){
        printf("Data: ");
    for (size_t i = 0; i < size_buff; i++) {
        printf("%02x", buff[i]);
    }
    printf("\n");
}

void print_decrypt(unsigned char  buff[tam_buff]){
  printf("Decrypted data: %s\n", buff);
}

void desencrypt_seed(unsigned char key[tam_buff], size_t size_key,unsigned char encrypted[tam_buff],size_t size_encrypted,unsigned char decrypted[tam_buff],size_t size_decrypted){
    gcry_cipher_hd_t handle;
    // unsigned char key[tam_buff] = {"1906"};  // Ejemplo de clave de 128 bits
    // unsigned char encrypted[tam_buff] = {"c0f67e3fbfd58d0aab8925c9a4cd73eb"};
    // unsigned char decrypted[tam_buff];  // Buffer para datos descifrados
    size_t data_len = size_encrypted;
    
    // Inicializa la biblioteca
    gcry_check_version(NULL);

    // Inicializa el manejador de cifrado (AES-128 en este caso)
    gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
    
    // Configura la clave
    gcry_cipher_setkey(handle, key, size_key);
    
    // Descifra los datos
    gcry_cipher_decrypt(handle, decrypted, size_decrypted, encrypted, data_len);

    // Cierra el manejador
    gcry_cipher_close(handle);

}



int main(int argc, char *argv[]) {
  // const char *username = get_username();
  // printf("Generating seed for user: %s\n", username);
  // char *seed = generateSeed(username);
  // if (seed != NULL) {
  //   generate_qr_code(username, seed);
  //   free(seed);
  // } else {
  //   printf("There was a problem generating the seed.\n");
  // }

  // return 0;

  unsigned char key[tam_buff] = {"1906"};
  unsigned char encrypted[tam_buff];
  encrypt_seed(key, sizeof(key),encrypted,sizeof(encrypted));
  print_encrypt(encrypted,sizeof(encrypted));


  unsigned char decrypted[tam_buff];
  unsigned char key2[tam_buff] = {"1906"};
  desencrypt_seed(key2, sizeof(key2),encrypted,sizeof(encrypted), decrypted, sizeof(decrypted));
  print_decrypt(decrypted);

  return 0;


}