#ifndef PAM_TOTP_2FA
#define PAM_TOTP_2FA

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libcotp.h"

#define SECRET_KEY_FILE "/etc/security/totp_secrets"

int generate_totp_seed(char *seed);
int validate_totp_code(const char *seed, const char *input_code);

#endif /* PAM_TOTP_H */
