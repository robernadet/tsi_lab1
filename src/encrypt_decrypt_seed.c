#include <gcrypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../include/utils.h"

void initialize_libgcrypt()
{
  if (!gcry_check_version(GCRYPT_VERSION))
  {
    fprintf(stderr, "Error: incorrect Libgcrypt version\n");
    exit(EXIT_FAILURE);
  }
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0); // Disable secure memory
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

void derive_key_from_password(const char *password, unsigned char *key, size_t keylen)
{
  gcry_error_t err;
  const char *salt = "salt";
  size_t salt_len = strlen(salt);

  // Derivar la clave de la contraseña usando PBKDF2 con SHA256
  err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, salt_len, 10000, keylen, key);
  if (err)
  {
    fprintf(stderr, "Error deriving key from password: %s\n", gcry_strerror(err));
    exit(EXIT_FAILURE);
  }
}

char *encrypt_seed(const char *seed, const char *password, size_t *encrypted_len)
{
  gcry_cipher_hd_t handle;
  gcry_error_t err;
  size_t blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
  size_t keylen = 32; // AES-256 uses a 32-byte key

  unsigned char key[keylen];
  derive_key_from_password(password, key, keylen);

  unsigned char iv[blklen];
  gcry_create_nonce(iv, blklen); // Crear un IV aleatorio

  // Calcular el tamaño del padding
  size_t padded_seed_len = SEED_SIZE + (blklen - (SEED_SIZE % blklen));
  char *padded_seed = malloc(padded_seed_len);
  if (!padded_seed)
  {
    fprintf(stderr, "Error allocating memory for padded seed\n");
    return NULL;
  }

  // Copiar la semilla original y aplicar el padding
  memcpy(padded_seed, seed, SEED_SIZE);
  memset(padded_seed + SEED_SIZE, blklen - (SEED_SIZE % blklen), blklen - (SEED_SIZE % blklen));

  // Alocar memoria para el texto cifrado (tamaño del bloque + IV)
  char *encrypted_seed = malloc(padded_seed_len + blklen);
  if (!encrypted_seed)
  {
    fprintf(stderr, "Error allocating memory for encrypted seed\n");
    free(padded_seed);
    return NULL;
  }

  // Inicializar el contexto de cifrado
  err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
  if (err)
  {
    fprintf(stderr, "Error initializing cipher context: %s\n", gcry_strerror(err));
    free(encrypted_seed);
    free(padded_seed);
    return NULL;
  }

  // Establecer la clave y el IV
  err = gcry_cipher_setkey(handle, key, keylen);
  if (err)
  {
    fprintf(stderr, "Error setting key: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(encrypted_seed);
    free(padded_seed);
    return NULL;
  }

  err = gcry_cipher_setiv(handle, iv, blklen);
  if (err)
  {
    fprintf(stderr, "Error setting IV: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(encrypted_seed);
    free(padded_seed);
    return NULL;
  }

  // Cifrar la semilla
  err = gcry_cipher_encrypt(handle, encrypted_seed + blklen, padded_seed_len, padded_seed, padded_seed_len);
  if (err)
  {
    fprintf(stderr, "Error encrypting seed: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(encrypted_seed);
    free(padded_seed);
    return NULL;
  }

  // Copiar el IV al inicio del búfer cifrado
  memcpy(encrypted_seed, iv, blklen);

  *encrypted_len = padded_seed_len + blklen;
  gcry_cipher_close(handle);
  free(padded_seed);

  return encrypted_seed;
}

char *decrypt_seed(const char *encrypted_seed, size_t encrypted_len, const char *password)
{
  gcry_cipher_hd_t handle;
  gcry_error_t err;
  size_t blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
  size_t keylen = 32; // AES-256 uses a 32-byte key

  unsigned char key[keylen];
  derive_key_from_password(password, key, keylen);

  unsigned char iv[blklen];
  memcpy(iv, encrypted_seed, blklen); // Extraer el IV del inicio

  size_t padded_seed_len = encrypted_len - blklen;
  char *decrypted_seed_padded = malloc(padded_seed_len);
  if (!decrypted_seed_padded)
  {
    fprintf(stderr, "Error allocating memory for decrypted seed\n");
    return NULL;
  }

  // Inicializar el contexto de cifrado
  err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
  if (err)
  {
    fprintf(stderr, "Error initializing cipher context: %s\n", gcry_strerror(err));
    free(decrypted_seed_padded);
    return NULL;
  }

  // Establecer la clave y el IV
  err = gcry_cipher_setkey(handle, key, keylen);
  if (err)
  {
    fprintf(stderr, "Error setting key: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(decrypted_seed_padded);
    return NULL;
  }

  err = gcry_cipher_setiv(handle, iv, blklen);
  if (err)
  {
    fprintf(stderr, "Error setting IV: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(decrypted_seed_padded);
    return NULL;
  }

  // Descifrar la semilla
  err = gcry_cipher_decrypt(handle, decrypted_seed_padded, padded_seed_len, encrypted_seed + blklen, padded_seed_len);
  if (err)
  {
    fprintf(stderr, "Error decrypting seed: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(decrypted_seed_padded);
    return NULL;
  }

  gcry_cipher_close(handle);

  // Remover el padding
  size_t padding_len = decrypted_seed_padded[padded_seed_len - 1];
  char *decrypted_seed = malloc(SEED_SIZE + 1);
  if (!decrypted_seed)
  {
    fprintf(stderr, "Error allocating memory for final decrypted seed\n");
    free(decrypted_seed_padded);
    return NULL;
  }

  memcpy(decrypted_seed, decrypted_seed_padded, SEED_SIZE);
  decrypted_seed[SEED_SIZE] = '\0'; // Asegurarse de que esté terminada en NULL
  free(decrypted_seed_padded);

  return decrypted_seed;
}

// int main(int argc, char *argv[])
// {
//   initialize_libgcrypt();

//   const char *password = "your_password_here";
//   const char *seed = "your_seed_here";

//   size_t encrypted_len;
//   char *encrypted_seed = encrypt_seed(seed, password, &encrypted_len);
//   if (encrypted_seed)
//   {
//     printf("Encrypted Seed: ");
//     for (size_t i = 0; i < encrypted_len; i++)
//     {
//       printf("%02X", (unsigned char)encrypted_seed[i]);
//     }
//     printf("\n");

//     char *decrypted_seed = decrypt_seed(encrypted_seed, encrypted_len, password);
//     if (decrypted_seed)
//     {
//       printf("Decrypted Seed: %s\n", decrypted_seed);
//       free(decrypted_seed);
//     }
//     free(encrypted_seed);
//   }

//   return 0;
// }
