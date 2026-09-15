#include "sha3.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define HASH_SIZE 256

int main() {
  sha3 sha3 = {0};
  sha3_init(&sha3, HASH_SIZE);

  const char* m1 = "ab";
  const char* m2 = "c";

  sha3_sponge(&sha3, m1, strlen(m1));
  sha3_sponge(&sha3, m2, strlen(m2));

  const uint64_t* hash = sha3_squeeze(&sha3);

  for(int i = 0; i < HASH_SIZE / 8; i++) {
    printf("%02x", ((uint8_t*)hash)[i]);
  }
  printf("\n");

  sha3_deinit(&sha3);
  return 0;
}
