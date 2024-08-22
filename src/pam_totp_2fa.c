#include "../include/pam_totp_2fa.h"
#include <stdio.h>
#include <cotp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>

#define GLOBAL_SEED_FILE "/etc/pam_seeds.txt"
#define PERIOD 30
#define DIGITS 6
#define PAM_CONST const

static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response)
{
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS || conv == NULL || conv->conv == NULL)
  {
    return PAM_CONV_ERR;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static char *request_pass(pam_handle_t *pamh, int echocode, PAM_CONST char *prompt)
{
  PAM_CONST struct pam_message msg = {.msg_style = echocode, .msg = prompt};
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;

  if (retval == PAM_SUCCESS && resp != NULL && resp->resp != NULL && *resp->resp != '\0')
  {
    ret = strdup(resp->resp);
  }
  else
  {
    pam_syslog(pamh, LOG_ERR, "No se recibió el código OTP del usuario");
  }

  if (resp)
  {
    if (!ret)
    {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}

// Función para leer la seed desde el archivo
static char *getSeedForUser(const char *username)
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
    pam_syslog(pamh, LOG_ERR, "Error al obtener el nombre de usuario");
    return PAM_AUTH_ERR;
  }

  // Leer la seed del archivo
  pam_syslog(pamh, LOG_INFO, "Leyendo la seed para el usuario: %s", user);
  char *seed = getSeedForUser(user);
  if (seed == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "No se encontró la seed para el usuario: %s", user);
    return PAM_AUTH_ERR;
  }

  pam_syslog(pamh, LOG_INFO, "Seed obtenida: %s", seed);

  // Solicitar el código OTP al usuario
  pam_syslog(pamh, LOG_INFO, "Solicitando el código OTP al usuario");
  char *otp_input = request_pass(pamh, PAM_PROMPT_ECHO_OFF, "Ingrese el código OTP: ");
  if (otp_input == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "No se pudo obtener el código OTP del usuario");
    free(seed);
    return PAM_AUTH_ERR;
  }

  // Generar el OTP usando el tiempo actual
  pam_syslog(pamh, LOG_INFO, "Generando el OTP para la comparación");
  cotp_error_t err_code = NO_ERROR;
  char *generated_otp = get_totp(seed, DIGITS, PERIOD, SHA1, &err_code);
  free(seed); // Liberar la seed después de usarla

  if (err_code != NO_ERROR || generated_otp == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Error al generar el OTP");
    free(otp_input);
    return PAM_AUTH_ERR;
  }

  // Validar el código OTP
  pam_syslog(pamh, LOG_INFO, "Validando el OTP ingresado");
  int auth_status = PAM_AUTH_ERR;
  if (strcmp(otp_input, generated_otp) == 0)
  {
    pam_syslog(pamh, LOG_INFO, "Autenticación exitosa para el usuario: %s", user);
    auth_status = PAM_SUCCESS;
  }
  else
  {
    pam_syslog(pamh, LOG_ERR, "El OTP ingresado es incorrecto");
  }

  free(otp_input);     // Liberar después de usar
  free(generated_otp); // Liberar después de usar

  return auth_status;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}
