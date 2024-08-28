#include <pwd.h>
#include <cotp.h>
#include <qrencode.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#include "../include/utils.h"
#include "../include/encrypt_decrypt_seed.h"
#include "../include/file_manager.h"

char *generateSeed(const char *username)
{
  initialize_libgcrypt();
  char *random_seed = generate_random_seed();
  if (!random_seed)
  {
    return NULL;
  }
  cotp_error_t err_code = NO_ERROR;
  char *base32 = base32_encode((unsigned char *)random_seed, SEED_SIZE_RANDOM, &err_code);
  free(random_seed);
  if (err_code != NO_ERROR)
  {
    printf("Error generating the seed: %d\n", err_code);
    return NULL;
  }
  return base32;
}

void generate_qr_code(const char *username, const char *base32_secret)
{
  char url[512];

  snprintf(url, sizeof(url),
           "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
           ISSUER, username, base32_secret, ISSUER, ALGORITHM, DIGITS, PERIOD);

  printf("URL to scan with Google Authenticator: %s\n", url);

  QRcode *qrcode = QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
  if (qrcode != NULL)
  {
    for (int y = 0; y < qrcode->width; y++)
    {
      for (int x = 0; x < qrcode->width; x++)
      {
        printf("%s", qrcode->data[y * qrcode->width + x] & 1 ? "██" : "  ");
      }
      printf("\n");
    }
    QRcode_free(qrcode);
  }
  else
  {
    perror("Error generating the QR code");
  }
}

const char *get_username()
{
  const char *username = getlogin();
  if (username == NULL)
  {
    struct passwd *pw = getpwuid(getuid());
    if (pw)
    {
      username = pw->pw_name;
    }
    else
    {
      perror("Could not get the username");
      exit(EXIT_FAILURE);
    }
  }
  return username;
}

// Custom conversation function to pass the password to PAM
int custom_conv(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr)
{
  struct pam_response *response;
  if (num_msg <= 0)
    return PAM_CONV_ERR;

  response = (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
  if (response == NULL)
    return PAM_CONV_ERR;

  for (int i = 0; i < num_msg; i++)
  {
    if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF)
    {
      response[i].resp = strdup((char *)appdata_ptr);
      if (response[i].resp == NULL)
      {
        free(response);
        return PAM_CONV_ERR;
      }
    }
    else
    {
      response[i].resp = NULL;
    }
    response[i].resp_retcode = 0;
  }
  *resp = response;
  return PAM_SUCCESS;
}

int authenticate_user(const char *username, const char *password)
{
  pam_handle_t *pamh = NULL;
  struct pam_conv conv = {custom_conv, (void *)password};

  int retval = pam_start("login", username, &conv, &pamh);
  if (retval != PAM_SUCCESS)
  {
    fprintf(stderr, "PAM: pam_start failed\n");
    return PAM_AUTH_ERR;
  }

  retval = pam_authenticate(pamh, 0);
  if (retval != PAM_SUCCESS)
  {
    fprintf(stderr, "PAM: pam_authenticate failed\n");
    pam_end(pamh, retval);
    return PAM_AUTH_ERR;
  }

  retval = pam_acct_mgmt(pamh, 0);
  if (retval != PAM_SUCCESS)
  {
    fprintf(stderr, "PAM: pam_acct_mgmt failed\n");
    pam_end(pamh, retval);
    return PAM_AUTH_ERR;
  }

  pam_end(pamh, retval);
  return retval == PAM_SUCCESS ? PAM_SUCCESS : PAM_AUTH_ERR;
}

int main(int argc, char *argv[])
{
  const char *username = get_username();
  char* password = getpass("Enter your password: ");

  if (authenticate_user(username, password) != PAM_SUCCESS)
  {
    printf("Authentication failed.\n");
    return EXIT_FAILURE;
  }

  printf("Password verified. Generating seed for user: %s\n", username);
  char *seed = generateSeed(username);
  //encrypted
  size_t encrypted_len;
  char *encrypted_seed = encrypt_seed(seed, password, &encrypted_len);
  saveEncryptedSeedToFile(encrypted_seed, encrypted_len, username);
  free(encrypted_seed);
  if (seed != NULL)
  {
    generate_qr_code(username, seed);
    free(seed);
  }
  else
  {
    printf("There was a problem generating the seed.\n");
  }

  return 0;
}
