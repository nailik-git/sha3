#include <stdio.h>
#include <string.h>
#include "sha3.h"

#define SHA3_B 1600
#define SHA3_W 64
#define SHA3_L 6
#define SHA3_N_R 24

static inline int __sha3_mod(int num, int div) {
  int r = num % div;
  while(r < 0) r += div;

  return r;
}

#define SHA3_C(x) (S[x] ^ S[x + 5] ^ S[x + 10] ^ S[x + 15] ^ S[x + 20])


static const int __sha3_rot[] = {
	  1,   3,   6,  10,
	 15,  21,  28,  36,
	 45,  55,  66,  78,
	 91, 105, 120, 136,
	153, 171, 190, 210,
	231, 253, 276, 300
};

static const int __sha3_xy[][2] = {
  {1, 0}, {0, 2}, {2, 1}, {1, 2},
  {2, 3}, {3, 3}, {3, 0}, {0, 1},
  {1, 3}, {3, 1}, {1, 4}, {4, 4},
  {4, 0}, {0, 3}, {3, 4}, {4, 3},
  {3, 2}, {2, 2}, {2, 0}, {0, 4},
  {4, 2}, {2, 4}, {4, 1}, {1, 1}
};

static const int __sha3_pi[25] = {
  0, 3, 1, 4, 2,
  1, 4, 2, 0, 3,
  2, 0, 3, 1, 4,
  3, 1, 4, 2, 0,
  4, 2, 0, 3, 1
};

static const int __sha3_mod5[] = {
  4, 0, 1, 2, 3, 4, 0, 1
};

#define SHA3_D(x) (SHA3_C(__sha3_mod5[x]) ^ __builtin_rotateleft64(SHA3_C(__sha3_mod5[x + 2]), 1))

static const uint64_t __sha3_rc[] = {
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

static inline void __sha3_rnd(uint64_t* S, int i_r) {
  static uint64_t _S[25] = {0};

  // theta
  for(int x = 0; x < 5; x++) {
    for(int y = 0; y < 5; y++) {
      _S[x + 5 * y] = S[x + 5 * y] ^ SHA3_D(x);
    }
  }

  // rho
  S[0] = _S[0];
  for(int t = 0; t < 24; t++) {
    const int x = __sha3_xy[t][0];
    const int y = __sha3_xy[t][1];
    _S[x + 5 * y] = __builtin_rotateleft64(_S[x + 5 * y], __sha3_rot[t]);
  }

  // pi & chi
  for(int x = 0; x < 5; x++) {
    for(int y = 0; y < 5; y++) {
      const int m1 = __sha3_mod5[x + 2];
      const int m2 = __sha3_mod5[x + 3];

      const int pi1 = __sha3_pi[x * 5 + y];
      const int pi2 = __sha3_pi[m1 * 5 + y];
      const int pi3 = __sha3_pi[m2 * 5 + y];
      S[x + 5 * y] = _S[pi1 + 5 * x] ^ ((_S[pi2 + 5 * m1] ^ (uint64_t) -1) & _S[pi3 + 5 * m2]);
    }
  }

  // iota
  S[0] ^= __sha3_rc[i_r];
}

void __sha3_keccak(uint64_t* S) {
  for(int i = 12 + 2 * SHA3_L - SHA3_N_R; i < (12 + 2 * SHA3_L); i++) {
    __sha3_rnd(S, i);
  }
}

void __sha3_append(__sha3_da* da, const uint8_t item) {
  if(!da->capacity) {
    da->items = malloc(1600);
    da->capacity = 1600;
  }

  while(da->count + 1 >= da->capacity) {
    da->items = realloc(da->items, (da->capacity *= 2));
  }

  da->items[da->count++] = item;
}

void __sha3_append_buf(__sha3_da* da, const uint8_t* buf, const int buf_len) {
  if(!da->capacity) {
    da->items = malloc(1600);
    da->capacity = 1600;
  }

  while(da->count + buf_len >= da->capacity) {
    da->items = realloc(da->items, (da->capacity *= 2));
  }

  memcpy(da->items + da->count, buf, buf_len);
  da->count += buf_len;
}

void __sha3_init(sha3* sha3, const int d) {
  sha3->d = d;

  if(sha3->buf == NULL) sha3->buf = malloc(sizeof(__sha3_da));
  sha3->buf->count = 0;
  sha3->buf->capacity = 0;

  if(sha3->S == NULL) sha3->S = malloc(25 * sizeof(uint64_t));
  memset(sha3->S, 0, 25 * sizeof(uint64_t));

  if(sha3->hash == NULL) sha3->hash = malloc(sha3->d / sizeof(uint64_t));
  memset(sha3->S, 0, sha3->d / sizeof(uint64_t));
}

void sha3_init_224(sha3* sha3) {
  __sha3_init(sha3, 224);
}

void sha3_init_256(sha3* sha3) {
  __sha3_init(sha3, 256);
}

void sha3_init_384(sha3* sha3) {
  __sha3_init(sha3, 384);
}

void sha3_init_512(sha3* sha3) {
  __sha3_init(sha3, 512);
}

void sha3_deinit(sha3* sha3) {
  free(sha3->buf->items);
  free(sha3->buf);
  sha3->buf = NULL;

  free(sha3->S);
  sha3->S = NULL;

  free(sha3->hash);
  sha3->hash = NULL;
}

void __sha3_sponge(sha3 sha3, const int i, const int r) {
  int p_idx = i * r / 8;
  for(int j = 0; j < r / 64; j++) {
    for(int k = 0; k < 8; k++) {
      sha3.S[j] ^= ((uint64_t) sha3.buf->items[p_idx + k]) << (8 * k);
    }
    p_idx += 8;
  }
  __sha3_keccak(sha3.S);
}


void sha3_sponge(sha3* sha3, const void* M, const size_t size) {
  const int c = 2 * sha3->d;
  const int r = SHA3_B - c;

  __sha3_append_buf(sha3->buf, M, size);

  int i;
  for(i = 0; (i + 1) * r / 8 <= sha3->buf->count; i++) {
    __sha3_sponge(*sha3, i, r);
  }

  memcpy(sha3->buf->items, sha3->buf->items + i * r / 8, (sha3->buf->count -= i * r / 8));
}

void __sha3_squeeze(sha3 sha3, const int r) {
  int z_idx = 0;

  while(1) {
    int i;
    for(i = 0; i < r / 64; i++) {
      if(z_idx + i == sha3.d / 64) break;
      sha3.hash[z_idx + i] = sha3.S[i];
    }
    z_idx += i;

    if(sha3.d / 64 <= z_idx) {
      return;
    }

    __sha3_keccak(sha3.S);
  }
}

void __sha3_pad(__sha3_da* da, const int x) {
  const int bit_len = da->count * 8 - 5;
  const int j = __sha3_mod(-bit_len - 2, x);
  const int p_len = (bit_len + j + 2) / 8;

  if(da->capacity < p_len) da->items = realloc(da->items, (da->capacity *= 2));

  da->items[p_len - 1] |= 0b10000000;
  da->count = p_len;
}

const uint64_t* sha3_squeeze(sha3* sha3) {
  const int c = 2 * sha3->d;
  const int r = SHA3_B - c;

  __sha3_append(sha3->buf, 0b110);

  memset(sha3->buf->items + sha3->buf->count, 0, sha3->buf->capacity - sha3->buf->count);
  __sha3_pad(sha3->buf, r);

  int i;
  for(i = 0; (i + 1) * r / 8 <= sha3->buf->count; i++) {
    __sha3_sponge(*sha3, i, r);
  }

  memcpy(sha3->buf->items, sha3->buf->items + i * r / 8, (sha3->buf->count -= i * r / 8));

  __sha3_squeeze(*sha3, r);

  return sha3->hash;
}
