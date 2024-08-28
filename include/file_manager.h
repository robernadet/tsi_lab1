#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <stdio.h>
#include <stdlib.h>

// Function to save the encrypted seed to a file
void saveEncryptedSeedToFile(char *encrypted_seed, size_t encrypted_len, const char *username);

// Function to get the encrypted seed for a user from a file
char *getEncryptedSeedForUser(const char *username, size_t *encrypted_len);

#endif // FILE_MANAGER_H