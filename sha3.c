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

static inline void __sha3_A_from_string(uint64_t* S, uint64_t A[5][5]) {
  for(int j = 0; j < 5; j++) {
    for(int i = 0; i < 5; i++) {
      A[i][j] = S[5 * j + i];
    }
  }
}

static inline void __sha3_string_from_A(uint64_t A[5][5], uint64_t* S) {
  for(int j = 0; j < 5; j++) {
    for(int i = 0; i < 5; i++) {
      S[5 * j + i] = A[i][j];
    }
  }
}

#define SHA3_C(x) (A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4])

#define SHA3_D(x) (SHA3_C(__sha3_mod(x - 1, 5)) ^ __builtin_rotateleft64(SHA3_C((x + 1) % 5), 1))

static inline void* __sha3_theta(uint64_t A[5][5]) {
  static uint64_t _A[5][5] = {0};

  for(int x = 0; x < 5; x++) {
    for(int y = 0; y < 5; y++) {
      _A[x][y] = A[x][y] ^ SHA3_D(x);
    }
  }

  for(int i = 0; i < 5; i++) {
    for(int j = 0; j < 5; j++) {
      A[i][j] = _A[i][j];
    }
  }

  return A;
}

static inline void* __sha3_rho(uint64_t A[5][5]) {
  static uint64_t _A[5][5] = {0};

  _A[0][0] = A[0][0];
  int x = 1;
  int y = 0;
  for(int t = 0; t < 24; t++) {
    _A[x][y] = __builtin_rotateleft64(A[x][y], (t + 1) * (t + 2) / 2);
    int tmpx = x;
    int tmpy = y;
    x = y;
    y = (2 * tmpx + 3 * tmpy) % 5;
  }

  for(int i = 0; i < 5; i++) {
    for(int j = 0; j < 5; j++) {
      A[i][j] = _A[i][j];
    }
  }

  return A;
}

static inline void* __sha3_pi(uint64_t A[5][5]) {
  static uint64_t _A[5][5] = {0};

  for(int x = 0; x < 5; x++) {
    for(int y = 0; y < 5; y ++) {
      _A[x][y] = A[(x + 3 * y) % 5][x];
    }
  }

  for(int i = 0; i < 5; i++) {
    for(int j = 0; j < 5; j++) {
      A[i][j] = _A[i][j];
    }
  }

  return A;
}

static inline void* __sha3_chi(uint64_t A[5][5]) {
  static uint64_t _A[5][5] = {0};

  for(int x = 0; x < 5; x++) {
    for(int y = 0; y < 5; y ++) {
      _A[x][y] = A[x][y] ^ ((A[(x + 1) % 5][y] ^ (uint64_t) -1) & A[(x + 2) % 5][y]);
    }
  }

  for(int i = 0; i < 5; i++) {
    for(int j = 0; j < 5; j++) {
      A[i][j] = _A[i][j];
    }
  }

  return A;
}

static inline uint64_t __sha3_rc(uint64_t t) {
  uint64_t R = 1;
  const uint64_t bitmask = 1 << 8;

  for(size_t i = 1; i <= t % 255; i++) {
    R <<= 1;
    R ^= (R & bitmask) >> 8;
    R ^= (R & bitmask) >> 4;
    R ^= (R & bitmask) >> 3;
    R ^= (R & bitmask) >> 2;
  }

  return R & 1;
}

static inline void* __sha3_iota(uint64_t A[5][5], int i_r) {
  uint64_t RC = 0;

  for(int j = 0; j <= SHA3_L; j++) {
    int shift = (1 << j) - 1;

    RC |= __sha3_rc(j + 7 * i_r) << shift;
  }

  A[0][0] ^= RC;

  return A;
}

#define SHA3_RND(A, i_r) __sha3_iota(__sha3_chi(__sha3_pi(__sha3_rho(__sha3_theta(A)))), i_r)

void __sha3_keccak(uint64_t* S) {
  uint64_t A[5][5] = {0};

  __sha3_A_from_string(S, A);

  for(int i = 12 + 2 * SHA3_L - SHA3_N_R; i < (12 + 2 * SHA3_L); i++) {
    SHA3_RND(A, i);
  }

  __sha3_string_from_A(A, S);
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

void __sha3_sponge(sha3 sha3, const int r) {
  const int bit_len = sha3.buf->count * 8 - 6;
  const int j = __sha3_mod(-bit_len - 2, r);
  const int n = (bit_len + j + 2) / r;

  for(int i = 0; i < n; i++) {
    int p_idx = 0;
    for(int j = 0; j < r / 64; j++) {
      for(int k = 0; k < 8; k++) {
        sha3.S[j] ^= ((uint64_t) sha3.buf->items[p_idx + k]) << (8 * k);
      }
      p_idx += 8;
    }
    __sha3_keccak(sha3.S);
  }
}

void sha3_sponge(sha3* sha3, const void* M, const size_t size) {
  // append to global thingy thing
  __sha3_append_buf(sha3->buf, M, size);

  // if long enough, perform sponging
  const int c = 2 * sha3->d;
  const int r = SHA3_B - c;
  while(sha3->buf->count >= r / 8) {
    __sha3_sponge(*sha3, r);

    // keep rest
    memcpy(sha3->buf->items, sha3->buf->items + r / 8, (sha3->buf->count -= r / 8));
  }
}

void __sha3_pad(__sha3_da* da, const int x) {
  const int bit_len = da->count * 8 - 6;
  const int j = __sha3_mod(-bit_len - 2, x);
  const int p_len = (bit_len + j + 2) / 8;

  if(da->capacity < p_len) da->items = realloc(da->items, (da->capacity *= 2));

  da->items[p_len - 1] |= 0b10000000;
  da->count = p_len;
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

const uint64_t* sha3_squeeze(sha3 sha3) {
  const int c = 2 * sha3.d;
  const int r = SHA3_B - c;

  __sha3_append(sha3.buf, 0b110);

  __sha3_pad(sha3.buf, r);

  __sha3_sponge(sha3, r);

  __sha3_squeeze(sha3, r);

  return sha3.hash;
}
