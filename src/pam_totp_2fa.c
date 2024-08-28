#include <stdio.h>
#include <cotp.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include "../include/utils.h"
#include "../include/encrypt_decrypt_seed.h"
#include "../include/file_manager.h"

#define PAM_CONST const

// Función para manejar la conversación con el usuario a través de PAM
static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response)
{
  struct pam_conv *conv;
  // Obtiene el manejador de conversación desde el contexto PAM
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS || conv == NULL || conv->conv == NULL)
  {
    return PAM_CONV_ERR;
  }
  // Llama a la función de conversación proporcionada por PAM
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

// Función para solicitar una contraseña (u otro input) al usuario
static char *request_pass(pam_handle_t *pamh, int echocode, PAM_CONST char *prompt)
{
  PAM_CONST struct pam_message msg = {.msg_style = echocode, .msg = prompt};
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  char *ret = NULL;

  // Llama a la función converse para interactuar con el usuario
  int retval = converse(pamh, 1, &msgs, &resp);
  if (retval == PAM_SUCCESS && resp != NULL && resp->resp != NULL && *resp->resp != '\0')
  {
    // Copia la respuesta del usuario (contraseña o código OTP)
    ret = strdup(resp->resp);
  }
  else
  {
    pam_syslog(pamh, LOG_ERR, "No OTP code received from user");
  }

  // Libera la memoria utilizada para la respuesta
  if (resp)
  {
    if (!ret)
    {
      free(resp->resp);
    }
    free(resp);
  }

  return ret; // Retorna la entrada del usuario
}

// Función principal de autenticación del módulo PAM
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *user;
  // Obtiene el nombre de usuario del contexto PAM
  int retval = pam_get_user(pamh, &user, "Username: ");
  if (retval != PAM_SUCCESS || user == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Error getting username");
    return PAM_AUTH_ERR;
  }

  // Obtiene la contraseña del usuario desde el contexto PAM
  const char *password = NULL;
  retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
  if (retval != PAM_SUCCESS || password == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Error getting password");
    return PAM_AUTH_ERR;
  }

  // Lee la semilla encriptada desde el archivo del usuario
  pam_syslog(pamh, LOG_INFO, "Reading seed for user: %s", user);
  size_t encrypted_len;
  char *encrypted_seed = getEncryptedSeedForUser(user, &encrypted_len);
  if (encrypted_seed == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Seed not found for user: %s", user);
    return PAM_AUTH_ERR;
  }

  // Desencripta la semilla utilizando la contraseña del usuario
  pam_syslog(pamh, LOG_INFO, "Decrypting seed for user: %s", user);
  char *decrypted_seed = decrypt_seed(encrypted_seed, encrypted_len, password);
  if (decrypted_seed == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Error decrypting seed for user: %s", user);
    free(encrypted_seed);
    return PAM_AUTH_ERR;
  }

  // Imprime la longitud y el contenido de la semilla descifrada (para depuración)
  pam_syslog(pamh, LOG_INFO, "Decrypted seed length: %zu", strlen(decrypted_seed));
  pam_syslog(pamh, LOG_INFO, "Decrypted seed: %s", decrypted_seed);

  // Solicita el código OTP al usuario
  pam_syslog(pamh, LOG_INFO, "Requesting OTP code from user");
  char *otp_input = request_pass(pamh, PAM_PROMPT_ECHO_OFF, "Enter OTP code: ");
  if (otp_input == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Failed to get OTP code from user");
    free(encrypted_seed);
    free(decrypted_seed);
    return PAM_AUTH_ERR;
  }

  // Genera el código OTP esperado utilizando la semilla descifrada
  pam_syslog(pamh, LOG_INFO, "Generating OTP for comparison");
  cotp_error_t err_code = NO_ERROR;
  char *generated_otp = get_totp(decrypted_seed, DIGITS, PERIOD, SHA1, &err_code);

  // Libera las semillas (encriptada y desencriptada) de la memoria
  free(encrypted_seed);
  free(decrypted_seed);

  // Verifica si hubo un error generando el OTP
  if (err_code != NO_ERROR || generated_otp == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Error generating OTP");
    free(otp_input);
    return PAM_AUTH_ERR;
  }

  // Compara el OTP ingresado con el generado
  pam_syslog(pamh, LOG_INFO, "Validating entered OTP");
  int auth_status = PAM_AUTH_ERR;
  if (strcmp(otp_input, generated_otp) == 0)
  {
    pam_syslog(pamh, LOG_INFO, "Authentication successful for user: %s", user);
    auth_status = PAM_SUCCESS;
  }
  else
  {
    pam_syslog(pamh, LOG_ERR, "Incorrect OTP entered");
  }

  // Libera la memoria utilizada para el OTP ingresado y el generado
  free(otp_input);
  free(generated_otp);

  return auth_status; // Retorna el estado de la autenticación
}

// Función para establecer las credenciales (por ahora, no hace nada)
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

// Función para la gestión de la cuenta (por ahora, no hace nada)
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}
