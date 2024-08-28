#include <gcrypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../include/utils.h"

size_t keylen = 32; // AES-256 uses a 32-byte key

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

char *generate_random_seed()
{
  char *random_seed = malloc(SEED_SIZE_RANDOM);
  if (!random_seed)
  {
    fprintf(stderr, "Error allocating memory for the seed\n");
    return NULL;
  }
  gcry_randomize(random_seed, SEED_SIZE_RANDOM, GCRY_STRONG_RANDOM);
  return random_seed;
}

void derive_key_from_password(const char *password, unsigned char *key, size_t keylen)
{
  gcry_error_t err;
  const char *salt = "salt";
  size_t salt_len = strlen(salt);

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

  unsigned char key[keylen];
  derive_key_from_password(password, key, keylen);

  unsigned char iv[blklen];
  gcry_create_nonce(iv, blklen); // Create a random IV

  size_t padded_seed_len = SEED_SIZE + (blklen - (SEED_SIZE % blklen));
  char *padded_seed = malloc(padded_seed_len);
  if (!padded_seed)
  {
    fprintf(stderr, "Error allocating memory for padded seed\n");
    return NULL;
  }

  memcpy(padded_seed, seed, SEED_SIZE);
  memset(padded_seed + SEED_SIZE, blklen - (SEED_SIZE % blklen), blklen - (SEED_SIZE % blklen));

  char *encrypted_seed = malloc(padded_seed_len + blklen);
  if (!encrypted_seed)
  {
    fprintf(stderr, "Error allocating memory for encrypted seed\n");
    free(padded_seed);
    return NULL;
  }

  err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
  if (err)
  {
    fprintf(stderr, "Error initializing cipher context: %s\n", gcry_strerror(err));
    free(encrypted_seed);
    free(padded_seed);
    return NULL;
  }

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

  err = gcry_cipher_encrypt(handle, encrypted_seed + blklen, padded_seed_len, padded_seed, padded_seed_len);
  if (err)
  {
    fprintf(stderr, "Error encrypting seed: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(encrypted_seed);
    free(padded_seed);
    return NULL;
  }

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

  unsigned char key[keylen];
  derive_key_from_password(password, key, keylen);

  unsigned char iv[blklen];
  memcpy(iv, encrypted_seed, blklen); // Extract IV from the start

  size_t padded_seed_len = encrypted_len - blklen;
  char *decrypted_seed_padded = malloc(padded_seed_len);
  if (!decrypted_seed_padded)
  {
    fprintf(stderr, "Error allocating memory for decrypted seed\n");
    return NULL;
  }

  err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
  if (err)
  {
    fprintf(stderr, "Error initializing cipher context: %s\n", gcry_strerror(err));
    free(decrypted_seed_padded);
    return NULL;
  }

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

  err = gcry_cipher_decrypt(handle, decrypted_seed_padded, padded_seed_len, encrypted_seed + blklen, padded_seed_len);
  if (err)
  {
    fprintf(stderr, "Error decrypting seed: %s\n", gcry_strerror(err));
    gcry_cipher_close(handle);
    free(decrypted_seed_padded);
    return NULL;
  }

  gcry_cipher_close(handle);

  size_t padding_len = decrypted_seed_padded[padded_seed_len - 1];
  size_t seed_len = padded_seed_len - padding_len;
  char *decrypted_seed = malloc(seed_len + 1); // +1 for null terminator
  if (!decrypted_seed)
  {
    fprintf(stderr, "Error allocating memory for final decrypted seed\n");
    free(decrypted_seed_padded);
    return NULL;
  }

  memcpy(decrypted_seed, decrypted_seed_padded, seed_len);
  decrypted_seed[seed_len] = '\0'; // Ensure null termination
  free(decrypted_seed_padded);

  return decrypted_seed;
}