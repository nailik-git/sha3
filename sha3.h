#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stdlib.h>

typedef struct {
  uint8_t* items;
  size_t count;
  size_t capacity;
} __sha3_da;

typedef struct {
  __sha3_da* buf;
  int d;
  uint64_t* S;
  uint64_t* hash;
} sha3;

void sha3_init(sha3* sha3, const int hash_size);

void sha3_deinit(sha3* sha3);

void sha3_sponge(sha3* sha3, const void* M, const size_t size);
const uint64_t* sha3_squeeze(sha3* sha3);

#endif
