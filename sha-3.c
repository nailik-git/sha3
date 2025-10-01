#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define b 1600
#define w 64
#define l 6
#define n_r 24

#define Lane(i, j) A[i][j]

int mod(int num, int div) {
  int r = num % div;
  while(r < 0) r += div;

  return r;
}

void A_from_string(uint64_t* S, uint64_t** A) {
  for(int y = 0; y < 5; y++) {
    for(int x = 0; x < 5; x++) {
      A[x][y] = S[5 * y + x];
    }
  }
}

void string_from_A(uint64_t** A, uint64_t* S) {
  for(int j = 0; j < 5; j++) {
    for(int i = 0; i < 5; i++) {
      S[5 * j + i] = Lane(i, j);
    }
  }
}

#define C(x) (A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4])

#define D(x) (C(mod(x - 1, 5)) ^ __builtin_rotateleft64(C((x + 1) % 5), 1))

uint64_t** theta(uint64_t** A) {
  uint64_t _A[5][5] = {0};

  for(int x = 0; x < 5; x++) {
    for(int y = 0; y < 5; y++) {
      _A[x][y] = A[x][y] ^ D(x);
    }
  }

  for(int i = 0; i < 5; i++) {
    for(int j = 0; j < 5; j++) {
      A[i][j] = _A[i][j];
    }
  }

  return A;
}

uint64_t** rho(uint64_t** A) {
  uint64_t _A[5][5] = {0};

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

uint64_t** pi(uint64_t** A) {
  uint64_t _A[5][5] = {0};

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

uint64_t** chi(uint64_t** A) {
  uint64_t _A[5][5] = {0};

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

uint64_t rc(uint64_t t) {
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

uint64_t** iota(uint64_t** A, int i_r) {
  uint64_t RC = 0;

  for(int j = 0; j <= l; j++) {
    int shift = (1 << j) - 1;

    RC |= rc(j + 7 * i_r) << shift;
  }

  A[0][0] ^= RC;

  return A;
}

#define Rnd(A, i_r) iota(chi(pi(rho(theta(A)))), i_r)

uint64_t* keccak_p_1600_24(uint64_t* S) {
  uint64_t** A = malloc(sizeof(uint64_t*) * 5);
  for(int i = 0; i < 5; i++) {
    A[i] = malloc(sizeof(uint64_t) * 5);
  }

  A_from_string(S, A);


  for(int i = 12 + 2 * l - n_r; i < (12 + 2 * l); i++) {
    A = Rnd(A, i);
  }

  string_from_A(A, S);

  for(int i = 0; i < 5; i++) {
    free(A[i]);
  }
  free(A);

  return S;
}

char* pad(char* N, int x, int m) {
  int j = mod(-m - 2, x);

  char* P = calloc(m + j + 2, 1);

  memcpy(P, N, m);

  P[m] = 1;
  P[m + j + 1] = 1;

  return P;
}

uint64_t* sponge(int r, char* N, int n_len, uint64_t d) {
  char* P = pad(N, r, n_len);
  int j = mod(-n_len - 2, r);
  int n = (n_len + j + 2) / r;
  // int c = b - r;

  uint64_t* S = calloc(25, sizeof(uint64_t));

  for(int i = 0; i < n; i++) {
    int p_idx = 0;
    for(int j = 0; j < r / 64; j++) {
      for(int k = 0; k < 64; k++) {
        S[j] ^= (uint64_t) P[p_idx + k] << k;
      }
      p_idx += 64;
    }
    S = keccak_p_1600_24(S);
  }

  free(P);

  uint64_t* Z = calloc(d / 64, sizeof(uint64_t));
  size_t z_idx = 0;

  while(1) {
    int i;
    for(i = 0; i < r / 64; i++) {
      if(z_idx + i == d / 64) break;
      Z[z_idx + i] = S[i];
    }
    z_idx += i;

    if(d / 64 >= z_idx) {
      free(S);
      return Z;
    }

    S = keccak_p_1600_24(S);
  }
}

uint64_t* sha_3(int d, char* M) {
  int c = 2 * d;
  int m_len = strlen(M);
  char* N = malloc(m_len * 8 + 2);

  for(int i = 0; i < m_len; i++) {
    N[i * 8 + 7] = M[i] >> 7;
    N[i * 8 + 6] = M[i] >> 6 & 1;
    N[i * 8 + 5] = M[i] >> 5 & 1;
    N[i * 8 + 4] = M[i] >> 4 & 1;
    N[i * 8 + 3] = M[i] >> 3 & 1;
    N[i * 8 + 2] = M[i] >> 2 & 1;
    N[i * 8 + 1] = M[i] >> 1 & 1;
    N[i * 8]     = M[i] >> 0 & 1;
  }
  N[m_len * 8] = 0;
  N[m_len * 8 + 1] = 1;

  uint64_t* r = sponge(b - c, N, m_len * 8 + 2, d);
  free(N);
  return r;
}

int main() {
  char* M = "hello, world";

  uint64_t* r = sha_3(256, M);

  for(int i = 0; i < 256 / 64; i++) {
    printf("%lx", r[i]);
  }
  printf("\n");

  free(r);

  return 0;
}

