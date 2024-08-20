#include "../include/pam_totp_2fa.h"
#include <stdio.h>
#include <cotp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define GLOBAL_SEED_FILE "/etc/pam_seeds.txt"
#define TIME_STEP 30       // Periodo de tiempo en segundos
#define TOLERANCE_WINDOW 1 // Ventana de tolerancia en pasos de tiempo

// Función para leer la seed desde el archivo
char *getSeedForUser(const char *username)
{
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
    char *file_user = strtok(line, ",");
    char *file_seed = strtok(NULL, "\n");

    if (file_user && file_seed && strcmp(file_user, username) == 0)
    {
      seed = strdup(file_seed); // Copia la seed encontrada
      break;
    }
  }

  fclose(file);
  return seed;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *user;
  int retval = pam_get_user(pamh, &user, "Username: ");
  if (retval != PAM_SUCCESS || user == NULL)
  {
    return PAM_AUTH_ERR;
  }

  // Leer la seed del archivo
  char *seed = getSeedForUser(user);
  if (seed == NULL)
  {
    return PAM_AUTH_ERR;
  }

  // Solicitar el código OTP al usuario
  const char *otp_input;
  retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&otp_input);
  if (retval != PAM_SUCCESS || otp_input == NULL)
  {
    free(seed);
    return PAM_AUTH_ERR;
  }

  // Validar el código OTP dentro de una ventana de tolerancia
  cotp_error_t err_code = NO_ERROR;
  char *generated_otp = NULL;
  int success = 0; // Para controlar si algún OTP coincide

  for (int i = -TOLERANCE_WINDOW; i <= TOLERANCE_WINDOW; i++)
  {
    // Usa la semilla codificada en base32 y pasa todos los parámetros requeridos
    generated_otp = get_totp_at(seed, time(NULL) + i * TIME_STEP, 6,TIME_STEP, SHA1, &err_code);
    if (err_code != NO_ERROR || generated_otp == NULL)
    {
      free(seed);
      return PAM_AUTH_ERR;
    }

    printf("otp %s /n",generated_otp);
    if (strcmp(otp_input, generated_otp) == 0)
    {
      success = 1;
      break;
    }
    free(generated_otp); // Libera el OTP generado en esta iteración si no coincide
  }

  free(seed);
  if (success)
  {
    return PAM_SUCCESS;
  }
  return PAM_AUTH_ERR;
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
