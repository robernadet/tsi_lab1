#include <pwd.h>
#include <cotp.h>
#include <qrencode.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#include "../include/utils.h"
#include "../include/encrypt_decrypt_seed.h"
#include "../include/file_manager.h"

// Función para generar una semilla aleatoria y codificarla en base32
char *generateSeed(const char *username)
{
  initialize_libgcrypt();                     // Inicializa Libgcrypt para operaciones criptográficas
  char *random_seed = generate_random_seed(); // Genera una semilla aleatoria segura
  if (!random_seed)
  {
    return NULL; // Retorna NULL si no se pudo generar la semilla
  }

  cotp_error_t err_code = NO_ERROR;
  // Codifica la semilla en base32
  char *base32 = base32_encode((unsigned char *)random_seed, SEED_SIZE_RANDOM, &err_code);
  free(random_seed); // Libera la memoria de la semilla aleatoria
  if (err_code != NO_ERROR)
  {
    printf("Error generating the seed: %d\n", err_code);
    return NULL;
  }
  return base32; // Retorna la semilla codificada en base32
}

// Función para generar un código QR a partir de la semilla codificada en base32
void generate_qr_code(const char *username, const char *base32_secret)
{
  char url[512];

  // Construye la URL de otpauth para el código QR
  snprintf(url, sizeof(url),
           "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
           ISSUER, username, base32_secret, ISSUER, ALGORITHM, DIGITS, PERIOD);

  printf("URL to scan with Google Authenticator: %s\n", url);

  // Genera el código QR a partir de la URL
  QRcode *qrcode = QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
  if (qrcode != NULL)
  {
    // Imprime el código QR en la terminal
    for (int y = 0; y < qrcode->width; y++)
    {
      for (int x = 0; x < qrcode->width; x++)
      {
        printf("%s", qrcode->data[y * qrcode->width + x] & 1 ? "██" : "  ");
      }
      printf("\n");
    }
    QRcode_free(qrcode); // Libera la memoria del código QR
  }
  else
  {
    perror("Error generating the QR code"); // Manejo de error en caso de fallo al generar el código QR
  }
}

// Función para obtener el nombre de usuario actual
const char *get_username()
{
  const char *username = getlogin(); // Intenta obtener el nombre de usuario con getlogin()
  if (username == NULL)
  {
    // Si falla, obtiene el nombre de usuario a través de la estructura passwd
    struct passwd *pw = getpwuid(getuid());
    if (pw)
    {
      username = pw->pw_name;
    }
    else
    {
      perror("Could not get the username"); // Manejo de error en caso de fallo
      exit(EXIT_FAILURE);
    }
  }
  return username;
}

// Función de conversación personalizada para pasar la contraseña a PAM
int custom_conv(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr)
{
  struct pam_response *response;
  if (num_msg <= 0)
    return PAM_CONV_ERR;

  // Reserva memoria para las respuestas de PAM
  response = (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
  if (response == NULL)
    return PAM_CONV_ERR;

  // Itera sobre los mensajes y responde a los que requieren la contraseña
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
  *resp = response; // Asigna las respuestas a la estructura pam_response
  return PAM_SUCCESS;
}

// Función para autenticar al usuario utilizando PAM
int authenticate_user(const char *username, const char *password)
{
  pam_handle_t *pamh = NULL;
  struct pam_conv conv = {custom_conv, (void *)password}; // Define la estructura de conversación PAM

  int retval = pam_start("login", username, &conv, &pamh);
  if (retval != PAM_SUCCESS)
  {
    fprintf(stderr, "PAM: pam_start failed\n");
    return PAM_AUTH_ERR;
  }

  // Intenta autenticar al usuario
  retval = pam_authenticate(pamh, 0);
  if (retval != PAM_SUCCESS)
  {
    fprintf(stderr, "PAM: pam_authenticate failed\n");
    pam_end(pamh, retval);
    return PAM_AUTH_ERR;
  }

  // Verifica la gestión de la cuenta del usuario
  retval = pam_acct_mgmt(pamh, 0);
  if (retval != PAM_SUCCESS)
  {
    fprintf(stderr, "PAM: pam_acct_mgmt failed\n");
    pam_end(pamh, retval);
    return PAM_AUTH_ERR;
  }

  pam_end(pamh, retval); // Finaliza la sesión PAM
  return retval == PAM_SUCCESS ? PAM_SUCCESS : PAM_AUTH_ERR;
}

// Función principal
int main(int argc, char *argv[])
{
  const char *username = get_username();             // Obtiene el nombre de usuario actual
  char *password = getpass("Enter your password: "); // Solicita la contraseña del usuario

  // Autentica al usuario
  if (authenticate_user(username, password) != PAM_SUCCESS)
  {
    printf("Authentication failed.\n");
    return EXIT_FAILURE;
  }

  printf("Password verified. Generating seed for user: %s\n", username);
  char *seed = generateSeed(username); // Genera la semilla para el usuario

  // Encripta la semilla con la contraseña del usuario
  size_t encrypted_len;
  char *encrypted_seed = encrypt_seed(seed, password, &encrypted_len);

  // Guarda la semilla encriptada en un archivo en el directorio del usuario
  saveEncryptedSeedToFile(encrypted_seed, encrypted_len, username);
  free(encrypted_seed); // Libera la memoria de la semilla encriptada

  if (seed != NULL)
  {
    generate_qr_code(username, seed); // Genera el código QR a partir de la semilla
    free(seed);                       // Libera la memoria de la semilla
  }
  else
  {
    printf("There was a problem generating the seed.\n");
  }

  return 0;
}
