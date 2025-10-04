#include "sha3.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define concat2(a, b) a ## b
#define concat(a, b) concat2(a, b)

#define HASH_SIZE 256

int main() {
  sha3 sha3 = {0};
  concat(sha3_init_, HASH_SIZE)(&sha3); // trickery, expands to sha3_init_256(&sha3)

  const char* m1 = "ab";
  const char* m2 = "c";

  sha3_sponge(&sha3, m1, strlen(m1));
  sha3_sponge(&sha3, m2, strlen(m2));

  const uint64_t* hash = sha3_squeeze(sha3);

  for(int i = 0; i < HASH_SIZE / 8; i++) {
    printf("%02x", ((uint8_t*)hash)[i]);
  }
  printf("\n");

  sha3_deinit(&sha3);
  return 0;
}
