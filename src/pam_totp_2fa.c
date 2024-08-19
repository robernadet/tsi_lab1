#include "../include/pam_totp_2fa.h"
#include <stdio.h>
#include <cotp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#define GLOBAL_SEED_FILE "/etc/pam_seeds.txt"

// Función para leer la seed desde el archivo
char* getSeedForUser(const char* username) {
  FILE *file = fopen(GLOBAL_SEED_FILE, "r");
  if (file == NULL)
  {
    perror("Error al abrir el archivo de seeds");
    return NULL;
  }

  char line[256];
  char *seed = NULL;
  while (fgets(line, sizeof(line), file))
  {
    char *file_user = strtok(line, ", ");
    char *file_seed = strtok(NULL, ", \n");

    if (file_user && file_seed && strcmp(file_user, username) == 0)
    {
      seed = strdup(file_seed); // Copia la seed encontrada
      break;
    }
  }

  fclose(file);
  return seed;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  const char *user;
  int retval = pam_get_user(pamh, &user, "Username: ");

  if (retval != PAM_SUCCESS || user == NULL) {
    return PAM_AUTH_ERR;
  }

  // Leer la seed del archivo
  char* seed = getSeedForUser(user);
  if (seed == NULL) {
    return PAM_AUTH_ERR;
  }

  cotp_error_t err_code = NO_ERROR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  // Manejo de credenciales
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  // Administración de cuentas (opcional)
  return PAM_SUCCESS;
}
