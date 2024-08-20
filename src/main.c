#include <stdio.h>
#include <cotp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <openssl/rand.h> // Asegúrate de tener la librería OpenSSL
#include <curl/curl.h>    // Necesitarás la librería cURL para generar la URL QR

#define GLOBAL_SEED_FILE "/etc/pam_seeds.txt"
#define SECRET_LENGTH 16 // Longitud del secreto en bytes
#define ISSUER "TOTP_2FA"   // Nombre de tu aplicación o servicio

void createSeedFileIfNotExists()
{
  FILE *file = fopen(GLOBAL_SEED_FILE, "r");
  if (file == NULL)
  {
    file = fopen(GLOBAL_SEED_FILE, "w");
    if (file == NULL)
    {
      perror("Error al crear el archivo para guardar las claves");
      return;
    }
    if (chmod(GLOBAL_SEED_FILE, S_IRUSR | S_IWUSR) != 0)
    {
      perror("Error al establecer permisos en el archivo");
    }
    fclose(file);
  }
  else
  {
    fclose(file);
  }
}

void saveSeed(const char *base32, const char *username)
{
  createSeedFileIfNotExists();
  umask(077);
  FILE *file = fopen(GLOBAL_SEED_FILE, "a");
  if (file == NULL)
  {
    perror("Error al abrir el archivo global para guardar el seed");
    return;
  }
  if (fprintf(file, "%s,%s\n", username, base32) < 0)
  {
    perror("Error al escribir el seed en el archivo global");
    fclose(file);
    return;
  }
  fclose(file);
  printf("Seed guardado para el usuario %s en el archivo global: %s\n", username, base32);
}

char *generate_random_secret()
{
  unsigned char buf[SECRET_LENGTH];
  if (RAND_bytes(buf, sizeof(buf)) != 1)
  {
    perror("Error al generar el secreto aleatorio");
    return NULL;
  }

  cotp_error_t err_code;
  char *base32_secret = base32_encode(buf, sizeof(buf), &err_code);

  if (err_code != NO_ERROR)
  {
    printf("Error al codificar el secreto en base32: %d\n", err_code);
    return NULL;
  }

  return base32_secret;
}

void generate_qr_code(const char *username, const char *base32_secret)
{
  char url[512];
  snprintf(url, sizeof(url), "otpauth://totp/%s?secret=%s&issuer=%s", username, base32_secret, ISSUER);

  char qr_code_url[1024];
  snprintf(qr_code_url, sizeof(qr_code_url), "https://api.qrserver.com/v1/create-qr-code/?data=%s&size=200x200", curl_easy_escape(NULL, url, 0));

  printf("Escanee el siguiente código QR con Google Authenticator:\n%s\n", qr_code_url);
}

char* generateSeed(const char *username)
{
  char *base32 = generate_random_secret();
  saveSeed(base32, username);
  free(base32);
  return base32;
}

int main(int argc, char *argv[])
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
      perror("No se pudo obtener el nombre de usuario");
      return -1;
    }
  }

  char response;

  printf("¿Desea extender la ventana de tiempo para validar el token? (s/n): ");
  scanf(" %c", &response);
  // Implementar la lógica basada en la respuesta

  printf("¿Desea activar el rate-limiting? (s/n): ");
  scanf(" %c", &response);
  // Implementar la lógica basada en la respuesta

  char* seed = generateSeed(username);
  if (seed != NULL) 
  {

    generate_qr_code(username, seed);
  }
  else
  {
    printf("Hubo un problema al generar el seed.\n");
  }

  return 0;
}
