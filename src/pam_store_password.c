#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h> 

#define PASSWORD_KEY "user_password"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password = NULL;
    int retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);

    if (retval != PAM_SUCCESS || password == NULL) {
        pam_syslog(pamh, LOG_ERR, "No se pudo obtener la contraseña del usuario");
        return PAM_AUTH_ERR;
    }

    // Almacenar la contraseña en el contexto PAM
    retval = pam_set_data(pamh, PASSWORD_KEY, (void *)password, NULL);
    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "No se pudo almacenar la contraseña en el contexto PAM");
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}





// const char *password = NULL;
//   int retval2 = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
//   pam_syslog(pamh, LOG_INFO, "contraseña : %s", password);