/* SPDX-License-Identifier: MIT */

#include "aimer_field.h"
#include "Util/Endian/endian_internal.h"
#include "Util/Core/secure_zero.h"

/*
 */
void crypto_aimer_field_set0(crypto_aimer_gf a)
{
  a[0] = 0;
  a[1] = 0;
  a[2] = 0;
  a[3] = 0;
}

void crypto_aimer_field_copy(crypto_aimer_gf out, const crypto_aimer_gf in)
{
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
}

void crypto_aimer_field_to_bytes(uint8_t *out, const crypto_aimer_gf in, const crypto_aimer_params *alg)
{
  size_t i;
  for (i = 0u; i < alg->field_words; ++i)
  {
    crypto_store64_le(out + (8u * i), in[i]);
  }
}

void crypto_aimer_field_from_bytes(crypto_aimer_gf out, const uint8_t *in, const crypto_aimer_params *alg)
{
  size_t i;
  crypto_aimer_field_set0(out);
  for (i = 0u; i < alg->field_words; ++i)
  {
    out[i] = crypto_load64_le(in + (8u * i));
  }
}

void crypto_aimer_field_add(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_gf b)
{
  c[0] = a[0] ^ b[0];
  c[1] = a[1] ^ b[1];
  c[2] = a[2] ^ b[2];
  c[3] = a[3] ^ b[3];
}

void crypto_aimer_field_mul(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_gf b, const crypto_aimer_params *alg)
{
  if (alg->security_bits == 128)
  {
    crypto_aimer_field128_mul(c, a, b);
  }
  else if (alg->security_bits == 192)
  {
    crypto_aimer_field192_mul(c, a, b);
  }
  else
  {
    crypto_aimer_field256_mul(c, a, b);
  }
}

void crypto_aimer_field_mul_add(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_gf b, const crypto_aimer_params *alg)
{
  if (alg->security_bits == 128)
  {
    crypto_aimer_field128_mul_add(c, a, b);
  }
  else if (alg->security_bits == 192)
  {
    crypto_aimer_field192_mul_add(c, a, b);
  }
  else
  {
    crypto_aimer_field256_mul_add(c, a, b);
  }
}

void crypto_aimer_field_sqr(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_params *alg)
{
  if (alg->security_bits == 128)
  {
    crypto_aimer_field128_sqr(c, a);
  }
  else if (alg->security_bits == 192)
  {
    crypto_aimer_field192_sqr(c, a);
  }
  else
  {
    crypto_aimer_field256_sqr(c, a);
  }
}

void crypto_aimer_field_exp(crypto_aimer_gf out, const crypto_aimer_gf in, const uint64_t *exp, const crypto_aimer_params *alg)
{
  crypto_aimer_gf temp;
  size_t i;
  size_t j;

  crypto_aimer_field_copy(temp, in);
  crypto_aimer_field_set0(out);
  out[0] = 1;
  for (i = 0; i < alg->field_words; i++)
  {
    uint64_t e = exp[i];
    for (j = 0; j < 64; j++, e >>= 1)
    {
      if (e & 1)
      {
        crypto_aimer_field_mul(out, out, temp, alg);
      }
      crypto_aimer_field_sqr(temp, temp, alg);
    }
  }
  crypto_zeroize(temp, sizeof(temp));
}

void crypto_aimer_field_mat_vec_mul(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_gf *b, const crypto_aimer_params *alg)
{
  if (alg->security_bits == 128)
  {
    crypto_aimer_field128_mat_vec_mul(c, a, b);
  }
  else if (alg->security_bits == 192)
  {
    crypto_aimer_field192_mat_vec_mul(c, a, b);
  }
  else
  {
    crypto_aimer_field256_mat_vec_mul(c, a, b);
  }
}

void crypto_aimer_field_mat_vec_mul_add(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_gf *b, const crypto_aimer_params *alg)
{
  if (alg->security_bits == 128)
  {
    crypto_aimer_field128_mat_vec_mul_add(c, a, b);
  }
  else if (alg->security_bits == 192)
  {
    crypto_aimer_field192_mat_vec_mul_add(c, a, b);
  }
  else
  {
    crypto_aimer_field256_mat_vec_mul_add(c, a, b);
  }
}
