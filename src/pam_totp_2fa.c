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
#include "../include/utils.h"
#include "../include/encrypt_decrypt_seed.h"

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
  char *ret = NULL;

  int retval = converse(pamh, 1, &msgs, &resp);
  if (retval == PAM_SUCCESS && resp != NULL && resp->resp != NULL && *resp->resp != '\0')
  {
    ret = strdup(resp->resp);
  }
  else
  {
    pam_syslog(pamh, LOG_ERR, "No OTP code received from user");
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

char *getSeedForUser(const char *username, size_t *encrypted_len)
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

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *user;
  int retval = pam_get_user(pamh, &user, "Username: ");
  if (retval != PAM_SUCCESS || user == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Error getting username");
    return PAM_AUTH_ERR;
  }

  // obtener password del user
  const char *password = NULL;
  retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "Password for seed: ");
  if (retval != PAM_SUCCESS || password == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Error getting password");
    return PAM_AUTH_ERR;
  }

  pam_syslog(pamh, LOG_INFO, "Reading seed for user: %s", user);
  size_t encrypted_len;
  char *encrypted_seed = getSeedForUser(user, &encrypted_len);
  if (encrypted_seed == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Seed not found for user: %s", user);
    return PAM_AUTH_ERR;
  }

  // decriptar seed
  pam_syslog(pamh, LOG_INFO, "Decrypting seed for user: %s", user);
  char *decrypted_seed = decrypt_seed(encrypted_seed, encrypted_len, password);
  // Imprimir la longitud de la semilla descifrada
  pam_syslog(pamh, LOG_INFO, "Decrypted seed length: %zu", strlen(decrypted_seed));
  pam_syslog(pamh, LOG_INFO, "Decrypted seed: %s", decrypted_seed);

  if (decrypted_seed == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Error decrypting seed for user: %s", user);
    free(encrypted_seed);
    return PAM_AUTH_ERR;
  }

  pam_syslog(pamh, LOG_INFO, "Requesting OTP code from user");
  char *otp_input = request_pass(pamh, PAM_PROMPT_ECHO_OFF, "Enter OTP code: ");
  if (otp_input == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Failed to get OTP code from user");
    free(encrypted_seed);
    free(decrypted_seed);
    return PAM_AUTH_ERR;
  }

  pam_syslog(pamh, LOG_INFO, "Generating OTP for comparison");
  cotp_error_t err_code = NO_ERROR;
  char *generated_otp = get_totp(decrypted_seed, DIGITS, PERIOD, SHA1, &err_code);
  free(encrypted_seed);
  free(decrypted_seed);

  if (err_code != NO_ERROR || generated_otp == NULL)
  {
    pam_syslog(pamh, LOG_ERR, "Error generating OTP");
    free(otp_input);
    return PAM_AUTH_ERR;
  }

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

  free(otp_input);
  free(generated_otp);

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