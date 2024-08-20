#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <gcrypt.h>
#include <cotp.h>
#include <qrencode.h>

#define GLOBAL_SEED_FILE "/etc/pam_seeds.txt"
#define SEED_SIZE 20 // Longitud de la salida HMAC-SHA1 es de 20 bytes (160 bits)

// Inicializa Libgcrypt
void initialize_libgcrypt()
{
  if (!gcry_check_version(GCRYPT_VERSION))
  {
    fprintf(stderr, "Error: versión de Libgcrypt incorrecta\n");
    exit(EXIT_FAILURE);
  }

  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

// Función para generar una semilla aleatoria segura de 20 bytes
char *generate_random_seed()
{
  char *random_seed = malloc(SEED_SIZE);
  if (!random_seed)
  {
    fprintf(stderr, "Error al asignar memoria para la semilla\n");
    return NULL;
  }

  // Generar la semilla utilizando un generador criptográficamente fuerte
  gcry_randomize(random_seed, SEED_SIZE, GCRY_STRONG_RANDOM);

  return random_seed;
}

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
  // Asegura que el archivo de seeds existe y tiene los permisos correctos
  createSeedFileIfNotExists();

  // Establece la máscara de permisos para que el owner solo tenga permisos de r y w
  umask(077);

  // Abre el archivo global para añadir la nueva seed (modo "append")
  FILE *file = fopen(GLOBAL_SEED_FILE, "a");
  if (file == NULL)
  {
    perror("Error al abrir el archivo global para guardar el seed");
    return;
  }

  // Escribe la seed y el nombre de usuario en una nueva línea
  if (fprintf(file, "%s,%s\n", username, base32) < 0)
  {
    perror("Error al escribir el seed en el archivo global");
    fclose(file);
    return;
  }

  fclose(file);

  printf("Seed guardado para el usuario %s en el archivo global.\n", username);
}

char *generateSeed(const char *username)
{
  initialize_libgcrypt();

  // Generar un seed aleatorio seguro de 20 bytes
  char *random_seed = generate_random_seed();
  if (!random_seed)
  {
    return NULL;
  }

  // Convertir la semilla aleatoria a una cadena codificada en base32
  cotp_error_t err_code = NO_ERROR;
  char *base32 = base32_encode((unsigned char *)random_seed, SEED_SIZE, &err_code);

  free(random_seed); // Libera la memoria asignada para la semilla aleatoria

  if (err_code != NO_ERROR)
  {
    printf("Error al generar el seed: %d\n", err_code);
    return NULL;
  }

  saveSeed(base32, username);
  return base32;
}

void generate_qr_code(const char *username, const char *base32_secret)
{
  char url[512];
  const char *issuer = "Example"; // Cambia esto por el nombre de tu servicio
  const char *algorithm = "SHA1"; // Por defecto es SHA1, pero puedes cambiarlo
  const int digits = 6;           // El número de dígitos en el código TOTP
  const int period = 30;          // Período en segundos para TOTP

  // Formato de la URL: otpauth://TYPE/LABEL?PARAMETERS
  snprintf(url, sizeof(url),
           "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
           issuer, username, base32_secret, issuer, algorithm, digits, period);

  printf("URL para escanear con Google Authenticator: %s\n", url);

  // Generar QR code usando qrencode
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
    perror("Error al generar el código QR");
  }
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

  char *seed = generateSeed(username);
  if (seed != NULL)
  {
    generate_qr_code(username, seed);
    free(seed);
  }
  else
  {
    printf("Hubo un problema al generar el seed.\n");
  }

  return 0;
}
