/* SPDX-License-Identifier: MIT */

#include <stddef.h>
#include <stdint.h>

#include "aimer_field.h"
#include "aimer_poly.h"

/*
 */
void crypto_aimer_field128_mul(uint64_t *c, const uint64_t *a, const uint64_t *b)
{
  uint64_t t[2] = {0,};
  uint64_t temp[4] = {0,};

  crypto_aimer_poly64_mul(&temp[3], &temp[2], a[1], b[1]);
  crypto_aimer_poly64_mul(&temp[1], &temp[0], a[0], b[0]);

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[0] ^ a[1]), (b[0] ^ b[1]));
  temp[1] ^= t[0] ^ temp[0] ^ temp[2];
  temp[2] = t[0] ^ t[1] ^ temp[0] ^ temp[1] ^ temp[3];

  t[0] = temp[2] ^ ((temp[3] >> 57) ^ (temp[3] >> 62) ^ (temp[3] >> 63));

  c[1] = temp[1] ^ temp[3];
  c[1] ^= (temp[3] << 7) | (t[0] >> 57);
  c[1] ^= (temp[3] << 2) | (t[0] >> 62);
  c[1] ^= (temp[3] << 1) | (t[0] >> 63);

  c[0] = temp[0] ^ t[0];
  c[0] ^= (t[0] << 7);
  c[0] ^= (t[0] << 2);
  c[0] ^= (t[0] << 1);

  c[2] = 0;
  c[3] = 0;
}

void crypto_aimer_field128_mul_add(uint64_t *c, const uint64_t *a, const uint64_t *b)
{
  uint64_t t[2] = {0,};
  uint64_t temp[4] = {0,};

  crypto_aimer_poly64_mul(&temp[3], &temp[2], a[1], b[1]);
  crypto_aimer_poly64_mul(&temp[1], &temp[0], a[0], b[0]);

  crypto_aimer_poly64_mul(&t[1], &t[0], (a[0] ^ a[1]), (b[0] ^ b[1]));
  temp[1] ^= t[0] ^ temp[0] ^ temp[2];
  temp[2] = t[0] ^ t[1] ^ temp[0] ^ temp[1] ^ temp[3];

  t[0] = temp[2] ^ ((temp[3] >> 57) ^ (temp[3] >> 62) ^ (temp[3] >> 63));

  c[1] ^= temp[1] ^ temp[3];
  c[1] ^= (temp[3] << 7) | (t[0] >> 57);
  c[1] ^= (temp[3] << 2) | (t[0] >> 62);
  c[1] ^= (temp[3] << 1) | (t[0] >> 63);

  c[0] ^= temp[0] ^ t[0];
  c[0] ^= (t[0] << 7);
  c[0] ^= (t[0] << 2);
  c[0] ^= (t[0] << 1);

  c[2] = 0;
  c[3] = 0;
}

void crypto_aimer_field128_sqr(uint64_t *c, const uint64_t *a)
{
  uint64_t t = 0;
  uint64_t temp[4] = {0,};

  crypto_aimer_poly64_sqr(&temp[1], &temp[0], a[0]);
  crypto_aimer_poly64_sqr(&temp[3], &temp[2], a[1]);

  t = temp[2] ^ ((temp[3] >> 57) ^ (temp[3] >> 62) ^ (temp[3] >> 63));

  c[1] = temp[1] ^ temp[3];
  c[1] ^= (temp[3] << 7) | (t >> 57);
  c[1] ^= (temp[3] << 2) | (t >> 62);
  c[1] ^= (temp[3] << 1) | (t >> 63);

  c[0] = temp[0] ^ t;
  c[0] ^= (t << 7);
  c[0] ^= (t << 2);
  c[0] ^= (t << 1);

  c[2] = 0;
  c[3] = 0;
}

/* c = sum_i a[i] * b[i] */
void crypto_aimer_field128_mat_vec_mul(uint64_t *c, const uint64_t *a,
                                const uint64_t (*b)[CRYPTO_AIMER_FIELD_MAX_WORDS])
{
  const uint64_t *a_ptr = a;
  const crypto_aimer_gf *b_ptr = b;

  uint64_t temp_c0 = 0;
  uint64_t temp_c1 = 0;
  uint64_t mask;
  size_t i;
  size_t j;
  for (i = 2; i; --i, ++a_ptr)
  {
    uint64_t index = *a_ptr;
    for (j = 64; j; j -= 8, index >>= 8, b_ptr += 8)
    {
      mask = UINT64_C(0) - (index & UINT64_C(1));
      temp_c0 ^= (b_ptr[0][0] & mask);
      temp_c1 ^= (b_ptr[0][1] & mask);

      mask = UINT64_C(0) - ((index >> 1) & UINT64_C(1));
      temp_c0 ^= (b_ptr[1][0] & mask);
      temp_c1 ^= (b_ptr[1][1] & mask);

      mask = UINT64_C(0) - ((index >> 2) & UINT64_C(1));
      temp_c0 ^= (b_ptr[2][0] & mask);
      temp_c1 ^= (b_ptr[2][1] & mask);

      mask = UINT64_C(0) - ((index >> 3) & UINT64_C(1));
      temp_c0 ^= (b_ptr[3][0] & mask);
      temp_c1 ^= (b_ptr[3][1] & mask);

      mask = UINT64_C(0) - ((index >> 4) & UINT64_C(1));
      temp_c0 ^= (b_ptr[4][0] & mask);
      temp_c1 ^= (b_ptr[4][1] & mask);

      mask = UINT64_C(0) - ((index >> 5) & UINT64_C(1));
      temp_c0 ^= (b_ptr[5][0] & mask);
      temp_c1 ^= (b_ptr[5][1] & mask);

      mask = UINT64_C(0) - ((index >> 6) & UINT64_C(1));
      temp_c0 ^= (b_ptr[6][0] & mask);
      temp_c1 ^= (b_ptr[6][1] & mask);

      mask = UINT64_C(0) - ((index >> 7) & UINT64_C(1));
      temp_c0 ^= (b_ptr[7][0] & mask);
      temp_c1 ^= (b_ptr[7][1] & mask);
    }
  }
  c[0] = temp_c0;
  c[1] = temp_c1;
  c[2] = 0;
  c[3] = 0;
}

/* c += sum_i a[i] * b[i] */
void crypto_aimer_field128_mat_vec_mul_add(uint64_t *c, const uint64_t *a,
                                    const uint64_t (*b)[CRYPTO_AIMER_FIELD_MAX_WORDS])
{
  const uint64_t *a_ptr = a;
  const crypto_aimer_gf *b_ptr = b;

  uint64_t temp_c0 = 0;
  uint64_t temp_c1 = 0;
  uint64_t mask;
  size_t i;
  size_t j;
  for (i = 2; i; --i, ++a_ptr)
  {
    uint64_t index = *a_ptr;
    for (j = 64; j; j -= 8, index >>= 8, b_ptr += 8)
    {
      mask = UINT64_C(0) - (index & UINT64_C(1));
      temp_c0 ^= (b_ptr[0][0] & mask);
      temp_c1 ^= (b_ptr[0][1] & mask);

      mask = UINT64_C(0) - ((index >> 1) & UINT64_C(1));
      temp_c0 ^= (b_ptr[1][0] & mask);
      temp_c1 ^= (b_ptr[1][1] & mask);

      mask = UINT64_C(0) - ((index >> 2) & UINT64_C(1));
      temp_c0 ^= (b_ptr[2][0] & mask);
      temp_c1 ^= (b_ptr[2][1] & mask);

      mask = UINT64_C(0) - ((index >> 3) & UINT64_C(1));
      temp_c0 ^= (b_ptr[3][0] & mask);
      temp_c1 ^= (b_ptr[3][1] & mask);

      mask = UINT64_C(0) - ((index >> 4) & UINT64_C(1));
      temp_c0 ^= (b_ptr[4][0] & mask);
      temp_c1 ^= (b_ptr[4][1] & mask);

      mask = UINT64_C(0) - ((index >> 5) & UINT64_C(1));
      temp_c0 ^= (b_ptr[5][0] & mask);
      temp_c1 ^= (b_ptr[5][1] & mask);

      mask = UINT64_C(0) - ((index >> 6) & UINT64_C(1));
      temp_c0 ^= (b_ptr[6][0] & mask);
      temp_c1 ^= (b_ptr[6][1] & mask);

      mask = UINT64_C(0) - ((index >> 7) & UINT64_C(1));
      temp_c0 ^= (b_ptr[7][0] & mask);
      temp_c1 ^= (b_ptr[7][1] & mask);
    }
  }
  c[0] ^= temp_c0;
  c[1] ^= temp_c1;
}
