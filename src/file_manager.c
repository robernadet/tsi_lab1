#include "../include/file_manager.h"

void saveEncryptedSeedToFile(char *encrypted_seed, size_t encrypted_len, const char *username)
{
  char filepath[256];
  snprintf(filepath, sizeof(filepath), "/home/%s/.totp_seed", username);

  umask(077); // Only owner can read/write
  FILE *file = fopen(filepath, "wb");
  if (file == NULL)
  {
    perror("Error opening the user's seed file");
    return;
  }

  if (fwrite(encrypted_seed, 1, encrypted_len, file) != encrypted_len)
  {
    perror("Error writing the seed to the user's seed file");
  }
  fclose(file);
  printf("Seed saved for user %s in %s.\n", username, filepath);
}

char *getEncryptedSeedForUser(const char *username, size_t *encrypted_len)
{
  char filepath[256];
  snprintf(filepath, sizeof(filepath), "/home/%s/.totp_seed", username);

  FILE *file = fopen(filepath, "rb");
  if (file == NULL)
  {
    perror("Error opening seed file");
    return NULL;
  }

  // Obtener el tamaño del archivo
  fseek(file, 0, SEEK_END);
  *encrypted_len = ftell(file);
  fseek(file, 0, SEEK_SET);

  char *encrypted_seed = malloc(*encrypted_len);
  if (!encrypted_seed)
  {
    perror("Error allocating memory for the seed");
    fclose(file);
    return NULL;
  }

  if (fread(encrypted_seed, 1, *encrypted_len, file) != *encrypted_len)
  {
    perror("Error reading the seed from the user's seed file");
    free(encrypted_seed);
    fclose(file);
    return NULL;
  }

  fclose(file);
  return encrypted_seed;
}