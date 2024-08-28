#ifndef ENCRYPT_DECRYPT_SEED_H
#define ENCRYPT_DECRYPT_SEED_H

// Function to initialize the libgcrypt library
void initialize_libgcrypt();

// Function to derive a key from a password
void derive_key_from_password(const char *password, unsigned char *key, size_t keylen);

// Function to encrypt a seed
char *encrypt_seed(const char *seed, const char *password, size_t *encrypted_len);

// Function to decrypt a seed
char *decrypt_seed(const char *encrypted_seed, size_t encrypted_len, const char *password);

char *generate_random_seed();

#endif // ENCRYPT_DECRYPT_SEED_H