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

static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
    return PAM_CONV_ERR;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static char *request_pass(pam_handle_t *pamh, int echocode, PAM_CONST char *prompt) {
  PAM_CONST struct pam_message msg = {.msg_style = echocode, .msg = prompt};
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  char *ret = NULL;

  int retval = converse(pamh, 1, &msgs, &resp);
  if (retval == PAM_SUCCESS && resp != NULL && resp->resp != NULL && *resp->resp != '\0') {
    ret = strdup(resp->resp);
  } else {
    pam_syslog(pamh, LOG_ERR, "No OTP code received from user");
  }

  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}

static char *getSeedForUser(const char *username) {
  char filepath[256];
  snprintf(filepath, sizeof(filepath), "/home/%s/.totp_seed", username);

  FILE *file = fopen(filepath, "r");
  if (file == NULL) {
    perror("Error opening seed file");
    return NULL;
  }

  char *seed = NULL;
  size_t len = 0;
  if (getline(&seed, &len, file) == -1) {
    perror("Error reading seed from file");
    fclose(file);
    return NULL;
  }

  // Remove newline character if present
  seed[strcspn(seed, "\n")] = '\0';

  fclose(file);
  return seed;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  const char *user;
  int retval = pam_get_user(pamh, &user, "Username: ");
  if (retval != PAM_SUCCESS || user == NULL) {
    pam_syslog(pamh, LOG_ERR, "Error getting username");
    return PAM_AUTH_ERR;
  }

  pam_syslog(pamh, LOG_INFO, "Reading seed for user: %s", user);
  char *seed = getSeedForUser(user);
  if (seed == NULL) {
    pam_syslog(pamh, LOG_ERR, "Seed not found for user: %s", user);
    return PAM_AUTH_ERR;
  }

  pam_syslog(pamh, LOG_INFO, "Requesting OTP code from user");
  char *otp_input = request_pass(pamh, PAM_PROMPT_ECHO_OFF, "Enter OTP code: ");
  if (otp_input == NULL) {
    pam_syslog(pamh, LOG_ERR, "Failed to get OTP code from user");
    free(seed);
    return PAM_AUTH_ERR;
  }

  pam_syslog(pamh, LOG_INFO, "Generating OTP for comparison");
  cotp_error_t err_code = NO_ERROR;
  char *generated_otp = get_totp(seed, DIGITS, PERIOD, SHA1, &err_code);
  free(seed);

  if (err_code != NO_ERROR || generated_otp == NULL) {
    pam_syslog(pamh, LOG_ERR, "Error generating OTP");
    free(otp_input);
    return PAM_AUTH_ERR;
  }

  pam_syslog(pamh, LOG_INFO, "Validating entered OTP");
  int auth_status = PAM_AUTH_ERR;
  if (strcmp(otp_input, generated_otp) == 0) {
    pam_syslog(pamh, LOG_INFO, "Authentication successful for user: %s", user);
    auth_status = PAM_SUCCESS;
  } else {
    pam_syslog(pamh, LOG_ERR, "Incorrect OTP entered");
  }

  free(otp_input);
  free(generated_otp);

  return auth_status;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}