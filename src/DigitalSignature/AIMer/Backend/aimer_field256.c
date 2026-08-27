/* SPDX-License-Identifier: MIT */

#include <stddef.h>
#include <stdint.h>

#include "aimer_field.h"
#include "aimer_poly.h"

/*
 */
void crypto_aimer_field256_mul(uint64_t *c, const uint64_t *a, const uint64_t *b)
{
  uint64_t t[4] = {0,};
  uint64_t add[4] = {0,};
  uint64_t temp[8] = {0,};

  crypto_aimer_poly64_mul(&t[0], &temp[0], a[0], b[0]);
  crypto_aimer_poly64_mul(&t[2], &t[1], a[1], b[1]);
  t[0] ^= t[1];

  crypto_aimer_poly64_mul(&t[3], &t[1], a[2], b[2]);
  t[1] ^= t[2];

  crypto_aimer_poly64_mul(&temp[7], &t[2], a[3], b[3]);
  t[2] ^= t[3];

  temp[6] = temp[7] ^ t[2];
  temp[3] = t[2] ^ t[1];
  temp[2] = t[1] ^ t[0];
  temp[1] = t[0] ^ temp[0];

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[0] ^ a[1]), (b[0] ^ b[1]));
  temp[1] ^= t[0];
  temp[2] ^= t[1];

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[2] ^ a[3]), (b[2] ^ b[3]));
  temp[3] ^= t[0];
  temp[6] ^= t[1];

  temp[5] = temp[7] ^ temp[3];
  temp[4] = temp[6] ^ temp[2];
  temp[3] ^= temp[1];
  temp[2] ^= temp[0];

  add[0] = a[0] ^ a[2];
  add[1] = a[1] ^ a[3];
  add[2] = b[0] ^ b[2];
  add[3] = b[1] ^ b[3];
  crypto_aimer_poly64_mul(&t[1], &t[0], add[0], add[2]);
  crypto_aimer_poly64_mul(&t[3], &t[2], add[1], add[3]);
  t[1] ^= t[2];
  t[2] = t[1] ^ t[3];
  t[1] ^= t[0];

  temp[2] ^= t[0];
  temp[3] ^= t[1];
  temp[4] ^= t[2];
  temp[5] ^= t[3];

  crypto_aimer_poly64_mul(&t[1], &t[0], (add[0] ^ add[1]), (add[2] ^ add[3]));
  temp[3] ^= t[0];
  temp[4] ^= t[1];

  t[0] = temp[4] ^ ((temp[7] >> 54) ^ (temp[7] >> 59) ^ (temp[7] >> 62));

  c[3] = temp[3] ^ temp[7];
  c[3] ^= (temp[7] << 10) | (temp[6] >> 54);
  c[3] ^= (temp[7] <<  5) | (temp[6] >> 59);
  c[3] ^= (temp[7] <<  2) | (temp[6] >> 62);

  c[2] = temp[2] ^ temp[6];
  c[2] ^= (temp[6] << 10) | (temp[5] >> 54);
  c[2] ^= (temp[6] <<  5) | (temp[5] >> 59);
  c[2] ^= (temp[6] <<  2) | (temp[5] >> 62);

  c[1] = temp[1] ^ temp[5];
  c[1] ^= (temp[5] << 10) | (t[0] >> 54);
  c[1] ^= (temp[5] <<  5) | (t[0] >> 59);
  c[1] ^= (temp[5] <<  2) | (t[0] >> 62);

  c[0] = temp[0] ^ t[0];
  c[0] ^= (t[0] << 10);
  c[0] ^= (t[0] <<  5);
  c[0] ^= (t[0] <<  2);
}

void crypto_aimer_field256_mul_add(uint64_t *c, const uint64_t *a, const uint64_t *b)
{
  uint64_t t[4] = {0,};
  uint64_t add[4] = {0,};
  uint64_t temp[8] = {0,};

  crypto_aimer_poly64_mul(&t[0], &temp[0], a[0], b[0]);
  crypto_aimer_poly64_mul(&t[2], &t[1], a[1], b[1]);
  t[0] ^= t[1];

  crypto_aimer_poly64_mul(&t[3], &t[1], a[2], b[2]);
  t[1] ^= t[2];

  crypto_aimer_poly64_mul(&temp[7], &t[2], a[3], b[3]);
  t[2] ^= t[3];

  temp[6] = temp[7] ^ t[2];
  temp[3] = t[2] ^ t[1];
  temp[2] = t[1] ^ t[0];
  temp[1] = t[0] ^ temp[0];

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[0] ^ a[1]), (b[0] ^ b[1]));
  temp[1] ^= t[0];
  temp[2] ^= t[1];

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[2] ^ a[3]), (b[2] ^ b[3]));
  temp[3] ^= t[0];
  temp[6] ^= t[1];

  temp[5] = temp[7] ^ temp[3];
  temp[4] = temp[6] ^ temp[2];
  temp[3] ^= temp[1];
  temp[2] ^= temp[0];

  add[0] = a[0] ^ a[2];
  add[1] = a[1] ^ a[3];
  add[2] = b[0] ^ b[2];
  add[3] = b[1] ^ b[3];
  crypto_aimer_poly64_mul(&t[1], &t[0], add[0], add[2]);
  crypto_aimer_poly64_mul(&t[3], &t[2], add[1], add[3]);
  t[1] ^= t[2];
  t[2] = t[1] ^ t[3];
  t[1] ^= t[0];

  temp[2] ^= t[0];
  temp[3] ^= t[1];
  temp[4] ^= t[2];
  temp[5] ^= t[3];

  crypto_aimer_poly64_mul(&t[1], &t[0], (add[0] ^ add[1]), (add[2] ^ add[3]));
  temp[3] ^= t[0];
  temp[4] ^= t[1];

  t[0] = temp[4] ^ ((temp[7] >> 54) ^ (temp[7] >> 59) ^ (temp[7] >> 62));

  c[3] ^= temp[3] ^ temp[7];
  c[3] ^= (temp[7] << 10) | (temp[6] >> 54);
  c[3] ^= (temp[7] <<  5) | (temp[6] >> 59);
  c[3] ^= (temp[7] <<  2) | (temp[6] >> 62);

  c[2] ^= temp[2] ^ temp[6];
  c[2] ^= (temp[6] << 10) | (temp[5] >> 54);
  c[2] ^= (temp[6] <<  5) | (temp[5] >> 59);
  c[2] ^= (temp[6] <<  2) | (temp[5] >> 62);

  c[1] ^= temp[1] ^ temp[5];
  c[1] ^= (temp[5] << 10) | (t[0] >> 54);
  c[1] ^= (temp[5] <<  5) | (t[0] >> 59);
  c[1] ^= (temp[5] <<  2) | (t[0] >> 62);

  c[0] ^= temp[0] ^ t[0];
  c[0] ^= (t[0] << 10);
  c[0] ^= (t[0] <<  5);
  c[0] ^= (t[0] <<  2);
}

void crypto_aimer_field256_sqr(uint64_t *c, const uint64_t *a)
{
  uint64_t t = 0;
  uint64_t temp[8] = {0,};

  crypto_aimer_poly64_sqr(&temp[1], &temp[0], a[0]);
  crypto_aimer_poly64_sqr(&temp[3], &temp[2], a[1]);
  crypto_aimer_poly64_sqr(&temp[5], &temp[4], a[2]);
  crypto_aimer_poly64_sqr(&temp[7], &temp[6], a[3]);

  t = temp[4] ^ ((temp[7] >> 54) ^ (temp[7] >> 59) ^ (temp[7] >> 62));

  c[3] = temp[3] ^ temp[7];
  c[3] ^= (temp[7] << 10) | (temp[6] >> 54);
  c[3] ^= (temp[7] <<  5) | (temp[6] >> 59);
  c[3] ^= (temp[7] <<  2) | (temp[6] >> 62);

  c[2] = temp[2] ^ temp[6];
  c[2] ^= (temp[6] << 10) | (temp[5] >> 54);
  c[2] ^= (temp[6] <<  5) | (temp[5] >> 59);
  c[2] ^= (temp[6] <<  2) | (temp[5] >> 62);

  c[1] = temp[1] ^ temp[5];
  c[1] ^= (temp[5] << 10) | (t >> 54);
  c[1] ^= (temp[5] <<  5) | (t >> 59);
  c[1] ^= (temp[5] <<  2) | (t >> 62);

  c[0] = temp[0] ^ t;
  c[0] ^= (t << 10);
  c[0] ^= (t <<  5);
  c[0] ^= (t <<  2);
}

void crypto_aimer_field256_mat_vec_mul(uint64_t *c, const uint64_t *a,
                                const uint64_t (*b)[CRYPTO_AIMER_FIELD_MAX_WORDS])
{
  const uint64_t *a_ptr = a;
  const crypto_aimer_gf *b_ptr = b;

  uint64_t temp_c0 = 0;
  uint64_t temp_c1 = 0;
  uint64_t temp_c2 = 0;
  uint64_t temp_c3 = 0;
  uint64_t mask;
  size_t i;
  size_t j;
  for (i = 4; i; --i, ++a_ptr)
  {
    uint64_t index = *a_ptr;
    for (j = 64; j; j -= 4, index >>= 4, b_ptr += 4)
    {
      mask = UINT64_C(0) - (index & UINT64_C(1));
      temp_c0 ^= (b_ptr[0][0] & mask);
      temp_c1 ^= (b_ptr[0][1] & mask);
      temp_c2 ^= (b_ptr[0][2] & mask);
      temp_c3 ^= (b_ptr[0][3] & mask);

      mask = UINT64_C(0) - ((index >> 1) & UINT64_C(1));
      temp_c0 ^= (b_ptr[1][0] & mask);
      temp_c1 ^= (b_ptr[1][1] & mask);
      temp_c2 ^= (b_ptr[1][2] & mask);
      temp_c3 ^= (b_ptr[1][3] & mask);

      mask = UINT64_C(0) - ((index >> 2) & UINT64_C(1));
      temp_c0 ^= (b_ptr[2][0] & mask);
      temp_c1 ^= (b_ptr[2][1] & mask);
      temp_c2 ^= (b_ptr[2][2] & mask);
      temp_c3 ^= (b_ptr[2][3] & mask);

      mask = UINT64_C(0) - ((index >> 3) & UINT64_C(1));
      temp_c0 ^= (b_ptr[3][0] & mask);
      temp_c1 ^= (b_ptr[3][1] & mask);
      temp_c2 ^= (b_ptr[3][2] & mask);
      temp_c3 ^= (b_ptr[3][3] & mask);
    }
  }
  c[0] = temp_c0;
  c[1] = temp_c1;
  c[2] = temp_c2;
  c[3] = temp_c3;
}

void crypto_aimer_field256_mat_vec_mul_add(uint64_t *c, const uint64_t *a,
                                    const uint64_t (*b)[CRYPTO_AIMER_FIELD_MAX_WORDS])
{
  const uint64_t *a_ptr = a;
  const crypto_aimer_gf *b_ptr = b;

  uint64_t temp_c0 = 0;
  uint64_t temp_c1 = 0;
  uint64_t temp_c2 = 0;
  uint64_t temp_c3 = 0;
  uint64_t mask;
  size_t i;
  size_t j;
  for (i = 4; i; --i, ++a_ptr)
  {
    uint64_t index = *a_ptr;
    for (j = 64; j; j -= 4, index >>= 4, b_ptr += 4)
    {
      mask = UINT64_C(0) - (index & UINT64_C(1));
      temp_c0 ^= (b_ptr[0][0] & mask);
      temp_c1 ^= (b_ptr[0][1] & mask);
      temp_c2 ^= (b_ptr[0][2] & mask);
      temp_c3 ^= (b_ptr[0][3] & mask);

      mask = UINT64_C(0) - ((index >> 1) & UINT64_C(1));
      temp_c0 ^= (b_ptr[1][0] & mask);
      temp_c1 ^= (b_ptr[1][1] & mask);
      temp_c2 ^= (b_ptr[1][2] & mask);
      temp_c3 ^= (b_ptr[1][3] & mask);

      mask = UINT64_C(0) - ((index >> 2) & UINT64_C(1));
      temp_c0 ^= (b_ptr[2][0] & mask);
      temp_c1 ^= (b_ptr[2][1] & mask);
      temp_c2 ^= (b_ptr[2][2] & mask);
      temp_c3 ^= (b_ptr[2][3] & mask);

      mask = UINT64_C(0) - ((index >> 3) & UINT64_C(1));
      temp_c0 ^= (b_ptr[3][0] & mask);
      temp_c1 ^= (b_ptr[3][1] & mask);
      temp_c2 ^= (b_ptr[3][2] & mask);
      temp_c3 ^= (b_ptr[3][3] & mask);
    }
  }
  c[0] ^= temp_c0;
  c[1] ^= temp_c1;
  c[2] ^= temp_c2;
  c[3] ^= temp_c3;
}
