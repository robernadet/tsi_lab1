#include <gcrypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../include/utils.h"

// Tamaño de la clave para AES-256, que utiliza una clave de 32 bytes
size_t keylen = 32;

// Función para inicializar Libgcrypt
void initialize_libgcrypt()
{
  if (!gcry_check_version(GCRYPT_VERSION))
  {
    fprintf(stderr, "Error: incorrect Libgcrypt version\n");
    exit(EXIT_FAILURE);
  }
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

// Función para generar una semilla aleatoria segura
char *generate_random_seed()
{
  // Reserva memoria para la semilla aleatoria
  char *random_seed = malloc(SEED_SIZE_RANDOM);
  if (!random_seed)
  {
    fprintf(stderr, "Error allocating memory for the seed\n");
    return NULL;
  }
  gcry_randomize(random_seed, SEED_SIZE_RANDOM, GCRY_STRONG_RANDOM);
  return random_seed;
}

// Función para derivar una clave a partir de una contraseña usando PBKDF2 y SHA-256
void derive_key_from_password(const char *password, unsigned char *key, size_t keylen)
{
  gcry_error_t err;
  const char *salt = "salt"; // Sal para la derivación de la clave
  size_t salt_len = strlen(salt);

  // Deriva la clave usando la contraseña, la sal, y el número de iteraciones especificado
  err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, salt_len, 10000, keylen, key);
  if (err)
  {
    fprintf(stderr, "Error deriving key from password: %s\n", gcry_strerror(err));
    exit(EXIT_FAILURE);
  }
}

// Función para encriptar la semilla utilizando AES-256 en modo CBC
char *encrypt_seed(const char *seed, const char *password, size_t *encrypted_len)
{
  gcry_cipher_hd_t handle;
  gcry_error_t err;
  size_t blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256); // Obtiene el tamaño del bloque para AES-256

  unsigned char key[keylen];
  derive_key_from_password(password, key, keylen); // Deriva la clave a partir de la contraseña

  unsigned char iv[blklen];
  gcry_create_nonce(iv, blklen); // Genera un vector de inicialización (IV) aleatorio

  // Calcula la longitud de la semilla rellenada (padded)
  size_t padded_seed_len = SEED_SIZE + (blklen - (SEED_SIZE % blklen));
  char *padded_seed = malloc(padded_seed_len);
  if (!padded_seed)
  {
    fprintf(stderr, "Error allocating memory for padded seed\n");
    return NULL;
  }

  // Copia la semilla original y agrega el relleno necesario
  memcpy(padded_seed, seed, SEED_SIZE);
  memset(padded_seed + SEED_SIZE, blklen - (SEED_SIZE % blklen), blklen - (SEED_SIZE % blklen));

  // Reserva memoria para almacenar la semilla encriptada (incluyendo el IV)
  char *encrypted_seed = malloc(padded_seed_len + blklen);
  if (!encrypted_seed)
  {
    fprintf(stderr, "Error allocating memory for encrypted seed\n");
    free(padded_seed);
    return NULL;
  }

  // Inicializa el contexto de cifrado con AES-256 en modo CBC
  err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
  if (err)
  {
    fprintf(stderr, "Error initializing cipher context: %s\n", gcry_strerror(err));
    free(encrypted_seed);
    free(padded_seed);
    return NULL;
  }

  // Establece la clave en el contexto de cifrado
  err = gcry_cipher_setkey(handle, key, keylen);
  if (err)
  {
    fprintf(stderr, "Error setting key: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(encrypted_seed);
    free(padded_seed);
    return NULL;
  }

  // Establece el IV en el contexto de cifrado
  err = gcry_cipher_setiv(handle, iv, blklen);
  if (err)
  {
    fprintf(stderr, "Error setting IV: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(encrypted_seed);
    free(padded_seed);
    return NULL;
  }

  // Realiza el cifrado de la semilla rellenada
  err = gcry_cipher_encrypt(handle, encrypted_seed + blklen, padded_seed_len, padded_seed, padded_seed_len);
  if (err)
  {
    fprintf(stderr, "Error encrypting seed: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(encrypted_seed);
    free(padded_seed);
    return NULL;
  }

  // Copia el IV al principio de la salida cifrada
  memcpy(encrypted_seed, iv, blklen);

  // Calcula la longitud total de la semilla cifrada (incluyendo el IV)
  *encrypted_len = padded_seed_len + blklen;
  gcry_cipher_close(handle);
  free(padded_seed);

  return encrypted_seed;
}

// Función para desencriptar la semilla utilizando AES-256 en modo CBC
char *decrypt_seed(const char *encrypted_seed, size_t encrypted_len, const char *password)
{
  gcry_cipher_hd_t handle;
  gcry_error_t err;
  size_t blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256); // Obtiene el tamaño del bloque para AES-256

  unsigned char key[keylen];
  derive_key_from_password(password, key, keylen); // Deriva la clave a partir de la contraseña

  unsigned char iv[blklen];
  memcpy(iv, encrypted_seed, blklen); // Extrae el IV desde el inicio del cifrado

  size_t padded_seed_len = encrypted_len - blklen;
  char *decrypted_seed_padded = malloc(padded_seed_len);
  if (!decrypted_seed_padded)
  {
    fprintf(stderr, "Error allocating memory for decrypted seed\n");
    return NULL;
  }

  // Inicializa el contexto de cifrado con AES-256 en modo CBC
  err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
  if (err)
  {
    fprintf(stderr, "Error initializing cipher context: %s\n", gcry_strerror(err));
    free(decrypted_seed_padded);
    return NULL;
  }

  // Establece la clave en el contexto de cifrado
  err = gcry_cipher_setkey(handle, key, keylen);
  if (err)
  {
    fprintf(stderr, "Error setting key: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(decrypted_seed_padded);
    return NULL;
  }

  // Establece el IV en el contexto de cifrado
  err = gcry_cipher_setiv(handle, iv, blklen);
  if (err)
  {
    fprintf(stderr, "Error setting IV: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(decrypted_seed_padded);
    return NULL;
  }

  // Realiza el descifrado de la semilla cifrada
  err = gcry_cipher_decrypt(handle, decrypted_seed_padded, padded_seed_len, encrypted_seed + blklen, padded_seed_len);
  if (err)
  {
    fprintf(stderr, "Error decrypting seed: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(decrypted_seed_padded);
    return NULL;
  }

  gcry_cipher_close(handle);

  // Determina el tamaño original de la semilla eliminando el relleno
  size_t padding_len = decrypted_seed_padded[padded_seed_len - 1];
  size_t seed_len = padded_seed_len - padding_len;

  // Reserva memoria para la semilla desencriptada y copia el contenido
  char *decrypted_seed = malloc(seed_len + 1); // +1 para el terminador nulo
  if (!decrypted_seed)
  {
    fprintf(stderr, "Error allocating memory for final decrypted seed\n");
    free(decrypted_seed_padded);
    return NULL;
  }

  memcpy(decrypted_seed, decrypted_seed_padded, seed_len);
  decrypted_seed[seed_len] = '\0'; // Asegura la terminación nula
  free(decrypted_seed_padded);

  return decrypted_seed;
}