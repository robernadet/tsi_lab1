#include "../include/file_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

// Función para guardar la semilla cifrada en un archivo en el directorio del usuario
void saveEncryptedSeedToFile(char *encrypted_seed, size_t encrypted_len, const char *username)
{
  char filepath[256];

  // Construye la ruta del archivo donde se almacenará la semilla
  snprintf(filepath, sizeof(filepath), "/home/%s/.totp_seed", username);

  // Establece una máscara de permisos que permite que solo el propietario lea/escriba el archivo
  umask(077);

  // Abre el archivo para escritura en modo binario
  FILE *file = fopen(filepath, "wb");
  if (file == NULL)
  {
    perror("Error opening the user's seed file");
    return;
  }

  // Escribe la semilla cifrada en el archivo
  if (fwrite(encrypted_seed, 1, encrypted_len, file) != encrypted_len)
  {
    perror("Error writing the seed to the user's seed file");
  }
  fclose(file);
  printf("Seed saved for user %s in %s.\n", username, filepath);
}

// Función para obtener la semilla cifrada de un archivo en el directorio del usuario
char *getEncryptedSeedForUser(const char *username, size_t *encrypted_len)
{
  char filepath[256];

  // Construye la ruta del archivo donde se encuentra la semilla cifrada
  snprintf(filepath, sizeof(filepath), "/home/%s/.totp_seed", username);

  // Abre el archivo para lectura en modo binario
  FILE *file = fopen(filepath, "rb");
  if (file == NULL)
  {
    perror("Error opening seed file");
    return NULL;
  }

  // Mueve el puntero del archivo al final para determinar el tamaño del archivo
  fseek(file, 0, SEEK_END);
  *encrypted_len = ftell(file); // Obtiene el tamaño del archivo
  fseek(file, 0, SEEK_SET);     // Regresa el puntero del archivo al inicio

  // Reserva memoria para almacenar la semilla cifrada
  char *encrypted_seed = malloc(*encrypted_len);
  if (!encrypted_seed)
  {
    // Manejo de errores en caso de que no se pueda asignar memoria
    perror("Error allocating memory for the seed");
    fclose(file);
    return NULL;
  }

  // Lee la semilla cifrada desde el archivo
  if (fread(encrypted_seed, 1, *encrypted_len, file) != *encrypted_len)
  {
    // Manejo de errores en caso de que no se pueda leer toda la semilla
    perror("Error reading the seed from the user's seed file");
    free(encrypted_seed);
    fclose(file);
    return NULL;
  }

  // Cierra el archivo después de la lectura
  fclose(file);

  // Retorna la semilla cifrada
  return encrypted_seed;
}
