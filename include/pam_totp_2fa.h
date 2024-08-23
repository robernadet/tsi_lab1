#ifndef PAM_TOTP_2FA
#define PAM_TOTP_2FA

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>

#define PAM_CONST const

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);

#endif
