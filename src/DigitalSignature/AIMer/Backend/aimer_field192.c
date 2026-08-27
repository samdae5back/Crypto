/* SPDX-License-Identifier: MIT */

#include <stddef.h>
#include <stdint.h>

#include "aimer_field.h"
#include "aimer_poly.h"

/*
 */
void crypto_aimer_field192_mul(uint64_t *c, const uint64_t *a, const uint64_t *b)
{
  uint64_t t[3] = {0,};
  uint64_t temp[6] = {0,};

  crypto_aimer_poly64_mul(&t[0], &temp[0], a[0], b[0]);
  crypto_aimer_poly64_mul(&t[2], &t[1], a[1], b[1]);
  t[0] ^= t[1];

  crypto_aimer_poly64_mul(&temp[5], &t[1], a[2], b[2]);
  t[1] ^= t[2];

  temp[1] = t[0] ^ temp[0];
  temp[2] = t[1] ^ temp[1];
  temp[4] = temp[5] ^ t[1];
  temp[3] = temp[4] ^ t[0];

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[0] ^ a[1]), (b[0] ^ b[1]));
  temp[1] ^= t[0];
  temp[2] ^= t[1];

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[0] ^ a[2]), (b[0] ^ b[2]));
  temp[2] ^= t[0];
  temp[3] ^= t[1];

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[1] ^ a[2]), (b[1] ^ b[2]));
  temp[3] ^= t[0];
  temp[4] ^= t[1];

  t[0] = temp[3] ^ ((temp[5] >> 57) ^ (temp[5] >> 62) ^ (temp[5] >> 63));

  c[2] = temp[2] ^ temp[5];
  c[2] ^= (temp[5] << 7) | (temp[4] >> 57);
  c[2] ^= (temp[5] << 2) | (temp[4] >> 62);
  c[2] ^= (temp[5] << 1) | (temp[4] >> 63);

  c[1] = temp[1] ^ temp[4];
  c[1] ^= (temp[4] << 7) | (t[0] >> 57);
  c[1] ^= (temp[4] << 2) | (t[0] >> 62);
  c[1] ^= (temp[4] << 1) | (t[0] >> 63);

  c[0] = temp[0] ^ t[0];
  c[0] ^= (t[0] << 7);
  c[0] ^= (t[0] << 2);
  c[0] ^= (t[0] << 1);

  c[3] = 0;
}

void crypto_aimer_field192_mul_add(uint64_t *c, const uint64_t *a, const uint64_t *b)
{
  uint64_t t[3] = {0,};
  uint64_t temp[6] = {0,};

  crypto_aimer_poly64_mul(&t[0], &temp[0], a[0], b[0]);
  crypto_aimer_poly64_mul(&t[2], &t[1], a[1], b[1]);
  t[0] ^= t[1];

  crypto_aimer_poly64_mul(&temp[5], &t[1], a[2], b[2]);
  t[1] ^= t[2];

  temp[1] = t[0] ^ temp[0];
  temp[2] = t[1] ^ temp[1];
  temp[4] = temp[5] ^ t[1];
  temp[3] = temp[4] ^ t[0];

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[0] ^ a[1]), (b[0] ^ b[1]));
  temp[1] ^= t[0];
  temp[2] ^= t[1];

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[0] ^ a[2]), (b[0] ^ b[2]));
  temp[2] ^= t[0];
  temp[3] ^= t[1];

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[1] ^ a[2]), (b[1] ^ b[2]));
  temp[3] ^= t[0];
  temp[4] ^= t[1];

  t[0] = temp[3] ^ ((temp[5] >> 57) ^ (temp[5] >> 62) ^ (temp[5] >> 63));

  c[2] ^= temp[2] ^ temp[5];
  c[2] ^= (temp[5] << 7) | (temp[4] >> 57);
  c[2] ^= (temp[5] << 2) | (temp[4] >> 62);
  c[2] ^= (temp[5] << 1) | (temp[4] >> 63);

  c[1] ^= temp[1] ^ temp[4];
  c[1] ^= (temp[4] << 7) | (t[0] >> 57);
  c[1] ^= (temp[4] << 2) | (t[0] >> 62);
  c[1] ^= (temp[4] << 1) | (t[0] >> 63);

  c[0] ^= temp[0] ^ t[0];
  c[0] ^= (t[0] << 7);
  c[0] ^= (t[0] << 2);
  c[0] ^= (t[0] << 1);

  c[3] = 0;
}

void crypto_aimer_field192_sqr(uint64_t *c, const uint64_t *a)
{
  uint64_t t = 0;
  uint64_t temp[6] = {0,};

  crypto_aimer_poly64_sqr(&temp[1], &temp[0], a[0]);
  crypto_aimer_poly64_sqr(&temp[3], &temp[2], a[1]);
  crypto_aimer_poly64_sqr(&temp[5], &temp[4], a[2]);

  t = temp[3] ^ ((temp[5] >> 57) ^ (temp[5] >> 62) ^ (temp[5] >> 63));

  c[2] = temp[2] ^ temp[5];
  c[2] ^= (temp[5] << 7) | (temp[4] >> 57);
  c[2] ^= (temp[5] << 2) | (temp[4] >> 62);
  c[2] ^= (temp[5] << 1) | (temp[4] >> 63);

  c[1] = temp[1] ^ temp[4];
  c[1] ^= (temp[4] << 7) | (t >> 57);
  c[1] ^= (temp[4] << 2) | (t >> 62);
  c[1] ^= (temp[4] << 1) | (t >> 63);

  c[0] = temp[0] ^ t;
  c[0] ^= (t << 7);
  c[0] ^= (t << 2);
  c[0] ^= (t << 1);

  c[3] = 0;
}

void crypto_aimer_field192_mat_vec_mul(uint64_t *c, const uint64_t *a,
                                const uint64_t (*b)[CRYPTO_AIMER_FIELD_MAX_WORDS])
{
  const uint64_t *a_ptr = a;
  const crypto_aimer_gf *b_ptr = b;

  uint64_t temp_c0 = 0;
  uint64_t temp_c1 = 0;
  uint64_t temp_c2 = 0;
  uint64_t mask;
  size_t i;
  size_t j;
  for (i = 3; i; --i, ++a_ptr)
  {
    uint64_t index = *a_ptr;
    for (j = 64; j; j -= 4, index >>= 4, b_ptr += 4)
    {
      mask = -(index & 1);
      temp_c0 ^= (b_ptr[0][0] & mask);
      temp_c1 ^= (b_ptr[0][1] & mask);
      temp_c2 ^= (b_ptr[0][2] & mask);

      mask = -((index >> 1) & 1);
      temp_c0 ^= (b_ptr[1][0] & mask);
      temp_c1 ^= (b_ptr[1][1] & mask);
      temp_c2 ^= (b_ptr[1][2] & mask);

      mask = -((index >> 2) & 1);
      temp_c0 ^= (b_ptr[2][0] & mask);
      temp_c1 ^= (b_ptr[2][1] & mask);
      temp_c2 ^= (b_ptr[2][2] & mask);

      mask = -((index >> 3) & 1);
      temp_c0 ^= (b_ptr[3][0] & mask);
      temp_c1 ^= (b_ptr[3][1] & mask);
      temp_c2 ^= (b_ptr[3][2] & mask);
    }
  }
  c[0] = temp_c0;
  c[1] = temp_c1;
  c[2] = temp_c2;
  c[3] = 0;
}

void crypto_aimer_field192_mat_vec_mul_add(uint64_t *c, const uint64_t *a,
                                    const uint64_t (*b)[CRYPTO_AIMER_FIELD_MAX_WORDS])
{
  const uint64_t *a_ptr = a;
  const crypto_aimer_gf *b_ptr = b;

  uint64_t temp_c0 = 0;
  uint64_t temp_c1 = 0;
  uint64_t temp_c2 = 0;
  uint64_t mask;
  size_t i;
  size_t j;
  for (i = 3; i; --i, ++a_ptr)
  {
    uint64_t index = *a_ptr;
    for (j = 64; j; j -= 4, index >>= 4, b_ptr += 4)
    {
      mask = -(index & 1);
      temp_c0 ^= (b_ptr[0][0] & mask);
      temp_c1 ^= (b_ptr[0][1] & mask);
      temp_c2 ^= (b_ptr[0][2] & mask);

      mask = -((index >> 1) & 1);
      temp_c0 ^= (b_ptr[1][0] & mask);
      temp_c1 ^= (b_ptr[1][1] & mask);
      temp_c2 ^= (b_ptr[1][2] & mask);

      mask = -((index >> 2) & 1);
      temp_c0 ^= (b_ptr[2][0] & mask);
      temp_c1 ^= (b_ptr[2][1] & mask);
      temp_c2 ^= (b_ptr[2][2] & mask);

      mask = -((index >> 3) & 1);
      temp_c0 ^= (b_ptr[3][0] & mask);
      temp_c1 ^= (b_ptr[3][1] & mask);
      temp_c2 ^= (b_ptr[3][2] & mask);
    }
  }
  c[0] ^= temp_c0;
  c[1] ^= temp_c1;
  c[2] ^= temp_c2;
}
