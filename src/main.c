
#include <stdio.h>
#include <cotp.h>

static int generateSeed() {
  //generar codigo aleatorio y pasarlo a base32
  
}

static int showSeed() {
  //
}

int main(int argc, char *argv[]) {
  printf("¿Desea extender la ventana de tiempo para validar el token? (s/n): ");
  printf("¿Desea activar el rate-limiting? (s/n): ");
  int code = generateSeed();
  printf("El código generado es: %d\n", code);

  return 0;
}
