#include <stdio.h>
#include <cotp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#define GLOBAL_SEED_FILE "/etc/pam_seeds.txt"

char *seed = NULL;

void createSeedFileIfNotExists() {
    FILE *file = fopen(GLOBAL_SEED_FILE, "r");
    if (file == NULL) {
        file = fopen(GLOBAL_SEED_FILE, "w");
        if (file == NULL) {
            perror("Error al crear el archivo para guardar las claves");
            return;
        }
        if (chmod(GLOBAL_SEED_FILE, S_IRUSR | S_IWUSR) != 0) {
            perror("Error al establecer permisos en el archivo");
        }
        fclose(file);
    } else {
        fclose(file);
    }
}


void saveSeed(char *base32, char *username) {
    // Asegura que el archivo de seeds existe y tiene los permisos correctos
    createSeedFileIfNotExists();

    // Establece la máscara de permisos para que el owner solo tenga permisos de r y w
    umask(066);

    // Abre el archivo global para añadir la nueva seed (modo "append")
    FILE *file = fopen(GLOBAL_SEED_FILE, "a");
    if (file == NULL) {
        perror("Error al abrir el archivo global para guardar el seed");
        return;
    }

    // Escribe la seed y el nombre de usuario en una nueva línea
    if (fprintf(file, "%s, %s\n", username, base32) < 0) {
        perror("Error al escribir el seed en el archivo global");
        fclose(file);
        return;
    }

    fclose(file);

    seed = strdup(base32);

    printf("Seed guardado para el usuario %s en el archivo global: %s\n", username, seed);
}

int generateSeed() {
  cotp_error_t err_code = NO_ERROR;

  char *base32 = base32_encode((unsigned char *)"ABCD", 4, &err_code);

  if (err_code != NO_ERROR) {
    printf("Error al generar el seed: %d\n", err_code);
    return -1;
  }

  saveSeed(base32, "ABCDE");
  return 0;
}

void showSeed()
{
  if (seed != NULL) {
    printf("El seed almacenado es: %s\n", seed);
  } else {
    printf("No hay ningún seed almacenado.\n");
  }
}

int main(int argc, char *argv[]) {
  char response;

  printf("¿Desea extender la ventana de tiempo para validar el token? (s/n): ");
  scanf(" %c", &response);
  // Implementar la lógica basada en la respuesta

  printf("¿Desea activar el rate-limiting? (s/n): ");
  scanf(" %c", &response);
  // Implementar la lógica basada en la respuesta

  int code = generateSeed();

  if (code == NO_ERROR)
  {
    showSeed();
  }
  else
  {
    printf("Hubo un problema al generar el seed.\n");
  }

  return 0;
}
