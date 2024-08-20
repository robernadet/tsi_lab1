#include "../include/pam_totp_2fa.h"
#include <stdio.h>
#include <cotp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_modules.h>

#define GLOBAL_SEED_FILE "/etc/pam_seeds.txt"
#define PERIOD 30
#define DIGITS 6

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
  struct pam_conv *conv;
  retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (retval != PAM_SUCCESS || conv == NULL)
  {
    free(seed);
    return PAM_AUTH_ERR;
  }

  struct pam_message msg[1];
  struct pam_response *resp = NULL;

  msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
  msg[0].msg = "Ingrese el código OTP: ";

  // Corregido aquí: se usa 'const struct pam_message **' para el tercer argumento
  retval = conv->conv(1, (const struct pam_message **)&msg, &resp, pamh);
  if (retval != PAM_SUCCESS || resp == NULL || resp[0].resp == NULL)
  {
    free(seed);
    return PAM_AUTH_ERR;
  }

  char otp_input[256];
  snprintf(otp_input, sizeof(otp_input), "%s", resp[0].resp);
  free(resp[0].resp);
  free(resp);

  // Generar el OTP usando el tiempo actual
  cotp_error_t err_code = NO_ERROR;
  char *generated_otp = get_totp(seed, DIGITS, PERIOD, SHA1, &err_code);

  if (err_code != NO_ERROR || generated_otp == NULL)
  {
    free(seed);
    return PAM_AUTH_ERR;
  }

  // Validar el código OTP
  int auth_status = PAM_AUTH_ERR;
  if (strcmp(otp_input, generated_otp) == 0)
  {
    auth_status = PAM_SUCCESS;
  }

  free(generated_otp);
  free(seed);
  return auth_status;
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
