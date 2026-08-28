/* SPDX-License-Identifier: MIT */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "aimer_aim2.h"
#include "aimer_field.h"
#include "aimer_hash.h"
#include "Util/Core/secure_zero.h"


const crypto_aimer_gf crypto_aimer_aim2_constants_128[CRYPTO_AIMER_MAX_INPUT_SBOXES] = {
  {0x13198a2e03707344ULL, 0x243f6a8885a308d3ULL, 0, 0},
  {0x082efa98ec4e6c89ULL, 0xa4093822299f31d0ULL, 0, 0},
};

const uint64_t crypto_aimer_aim2_sbox_exponents_128[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1][CRYPTO_AIMER_FIELD_MAX_WORDS] = {
  {0x6b6b6d6dadadb5b5ULL, 0xb6b6d6d6dadb5b5bULL, 0, 0},
  {0x6d6db6d6db6b6db5ULL, 0xb6db5b6dadb6dadbULL, 0, 0},
  {7, 0, 0, 0}
};

const size_t crypto_aimer_aim2_exponents_128[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1] = {49, 91, 3};

const crypto_aimer_gf crypto_aimer_aim2_constants_192[CRYPTO_AIMER_MAX_INPUT_SBOXES] = {
  {0xc0ac29b7c97c50ddULL, 0xbe5466cf34e90c6cULL, 0x452821e638d01377ULL, 0},
  {0xd1310ba698dfb5acULL, 0x9216d5d98979fb1bULL, 0x3f84d5b5b5470917ULL, 0},
};

const uint64_t crypto_aimer_aim2_sbox_exponents_192[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1][CRYPTO_AIMER_FIELD_MAX_WORDS] = {
  {0xd6ad6b56b5ab5ad5ULL, 0x6ad6b56b5ab5ad5aULL, 0xad6b56b5ab5ad5adULL, 0},
  {0x7776eeeeeeeeeeedULL, 0xbbbbbbbb77777777ULL, 0xddddddddddddbbbbULL, 0},
  {31, 0, 0, 0}
};

const size_t crypto_aimer_aim2_exponents_192[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1] = {17, 47, 5};

const crypto_aimer_gf crypto_aimer_aim2_constants_256[CRYPTO_AIMER_MAX_INPUT_SBOXES] = {
  {0x24a19947b3916cf7ULL, 0xba7c9045f12c7f99ULL, 0xb8e1afed6a267e96ULL, 0x2ffd72dbd01adfb7ULL},
  {0x0d95748f728eb658ULL, 0xa458fea3f4933d7eULL, 0x636920d871574e69ULL, 0x0801f2e2858efc16ULL},
  {0xc5d1b023286085f0ULL, 0x9c30d5392af26013ULL, 0x7b54a41dc25a59b5ULL, 0x718bcd5882154aeeULL}
};

const uint64_t crypto_aimer_aim2_sbox_exponents_256[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1][CRYPTO_AIMER_FIELD_MAX_WORDS] = {
  {0xdadb5b6b6d6dadb5ULL, 0x6b6d6dadb5b6b6d6ULL, 0xadb5b6b6d6dadb5bULL, 0xb6d6dadb5b6b6d6dULL},
  {0x1112224444889111ULL, 0x8891112224444889ULL, 0x4448889112222444ULL, 0x2224448889112222ULL},
  {0xeddbb76eddbb76edULL, 0x76eddbb76eddbb76ULL, 0xbb76eddbb76eddbbULL, 0xddbb76eddbb76eddULL},
  {7, 0, 0, 0}
};

const size_t crypto_aimer_aim2_exponents_256[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1] = {11, 141, 7, 3};

static const crypto_aimer_gf *crypto_aimer_aim2_constants_for_alg(const crypto_aimer_params *alg)
{
  if (alg->security_bits == 128)
  {
    return crypto_aimer_aim2_constants_128;
  }
  if (alg->security_bits == 192)
  {
    return crypto_aimer_aim2_constants_192;
  }
  return crypto_aimer_aim2_constants_256;
}
static const uint64_t (*crypto_aimer_aim2_sbox_exponents_for_alg(const crypto_aimer_params *alg))[CRYPTO_AIMER_FIELD_MAX_WORDS]
{
  if (alg->security_bits == 128)
  {
    return crypto_aimer_aim2_sbox_exponents_128;
  }
  if (alg->security_bits == 192)
  {
    return crypto_aimer_aim2_sbox_exponents_192;
  }
  return crypto_aimer_aim2_sbox_exponents_256;
}

static const size_t *crypto_aimer_aim2_exponents_for_alg(const crypto_aimer_params *alg)
{
  if (alg->security_bits == 128)
  {
    return crypto_aimer_aim2_exponents_128;
  }
  if (alg->security_bits == 192)
  {
    return crypto_aimer_aim2_exponents_192;
  }
  return crypto_aimer_aim2_exponents_256;
}

static crypto_aimer_gf *matrix_cell(crypto_aimer_gf *matrix, size_t ell, size_t row,
                       const crypto_aimer_params *alg)
{
  return &matrix[(ell * alg->field_bits) + row];
}

static const crypto_aimer_gf *matrix_cell_const(const crypto_aimer_gf *matrix, size_t ell, size_t row,
                                   const crypto_aimer_params *alg)
{
  return &matrix[(ell * alg->field_bits) + row];
}

static void generate_matrices_L_and_U(crypto_aimer_gf *matrix_L, crypto_aimer_gf *matrix_U, crypto_aimer_gf vector_b,
                                      const uint8_t *iv,
                                      const crypto_aimer_params *alg)
{
  uint8_t buf[CRYPTO_AIMER_MAX_FIELD_BYTES];
  uint64_t ormask;
  uint64_t lmask;
  uint64_t umask;
  crypto_aimer_hash_context ctx;
  crypto_aimer_gf temp = {0,};
  size_t ell;
  size_t row;

  crypto_aimer_hash_init(&ctx, alg);
  crypto_aimer_hash_absorb(&ctx, iv, alg->iv_bytes);
  crypto_aimer_hash_finalize(&ctx, alg);

  for (ell = 0; ell < alg->input_sboxes; ell++)
  {
    for (row = 0; row < alg->field_bits; row++)
    {
      size_t inter;
      size_t col_word;

      crypto_aimer_hash_squeeze(&ctx, buf, alg->field_bytes, alg);
      crypto_aimer_field_from_bytes(temp, buf, alg);

      ormask = ((uint64_t)1) << (row % 64);
      lmask = ((uint64_t)-1) << (row % 64);
      umask = ~lmask;

      inter = row / 64;
      for (col_word = 0; col_word < inter; col_word++)
      {
        (*matrix_cell(matrix_L, ell, row, alg))[col_word] = 0;
        (*matrix_cell(matrix_U, ell, row, alg))[col_word] = temp[col_word];
      }
      (*matrix_cell(matrix_L, ell, row, alg))[inter] =
        (temp[inter] & lmask) | ormask;
      (*matrix_cell(matrix_U, ell, row, alg))[inter] =
        (temp[inter] & umask) | ormask;
      for (col_word = inter + 1; col_word < alg->field_words; col_word++)
      {
        (*matrix_cell(matrix_L, ell, row, alg))[col_word] = temp[col_word];
        (*matrix_cell(matrix_U, ell, row, alg))[col_word] = 0;
      }
    }
  }

  crypto_aimer_hash_squeeze(&ctx, buf, alg->field_bytes, alg);
  crypto_aimer_field_from_bytes(vector_b, buf, alg);
  crypto_aimer_hash_clear(&ctx);
}

LiberaCError crypto_aimer_aim2_generate_linear(
    crypto_aimer_gf *matrix_A, crypto_aimer_gf vector_b,
    const uint8_t *iv, const crypto_aimer_params *alg)
{
  const size_t matrix_cells = alg->multiplications * alg->field_bits;
  const size_t matrix_bytes = matrix_cells * sizeof(crypto_aimer_gf);
  crypto_aimer_gf *matrices = malloc(2u * matrix_bytes);
  crypto_aimer_gf *matrix_L;
  crypto_aimer_gf *matrix_U;
  size_t ell;
  size_t i;

  if (matrices == NULL)
    return LIBERAC_ERROR_ALLOCATION_FAILED;
  matrix_L = matrices;
  matrix_U = matrices + matrix_cells;
  generate_matrices_L_and_U(matrix_L, matrix_U, vector_b, iv, alg);

  for (ell = 0; ell < alg->input_sboxes; ell++)
  {
    for (i = 0; i < alg->field_bits; i++)
    {
      crypto_aimer_field_mat_vec_mul(*matrix_cell(matrix_A, ell, i, alg),
                     *matrix_cell_const((const crypto_aimer_gf *)matrix_U, ell, i, alg),
                     matrix_cell_const((const crypto_aimer_gf *)matrix_L, ell, 0, alg), alg);
    }
  }

  crypto_zeroize(matrices, 2u * matrix_bytes);
  free(matrices);
  return LIBERAC_SUCCESS;
}

LiberaCError crypto_aimer_aim2(
    uint8_t *ct, const uint8_t *pt, const uint8_t *iv,
    const crypto_aimer_params *alg)
{
  const size_t matrix_cells = alg->multiplications * alg->field_bits;
  const size_t matrix_bytes = matrix_cells * sizeof(crypto_aimer_gf);
  crypto_aimer_gf *matrices = malloc(2u * matrix_bytes);
  crypto_aimer_gf *matrix_L;
  crypto_aimer_gf *matrix_U;
  crypto_aimer_gf vector_b = {0,};
  crypto_aimer_gf state[CRYPTO_AIMER_MAX_INPUT_SBOXES];
  crypto_aimer_gf pt_gf = {0,};
  crypto_aimer_gf ct_gf = {0,};
  const crypto_aimer_gf *constants = crypto_aimer_aim2_constants_for_alg(alg);
  const uint64_t (*sbox_exponents)[CRYPTO_AIMER_FIELD_MAX_WORDS] =
    crypto_aimer_aim2_sbox_exponents_for_alg(alg);
  size_t i;

  if (matrices == NULL)
    return LIBERAC_ERROR_ALLOCATION_FAILED;
  matrix_L = matrices;
  matrix_U = matrices + matrix_cells;
  crypto_aimer_field_from_bytes(pt_gf, pt, alg);
  generate_matrices_L_and_U(matrix_L, matrix_U, vector_b, iv, alg);

  for (i = 0; i < alg->multiplications; i++)
  {
    crypto_aimer_field_add(state[i], pt_gf, constants[i]);
    crypto_aimer_field_exp(state[i], state[i], sbox_exponents[i], alg);
    crypto_aimer_field_mat_vec_mul(state[i], state[i], matrix_cell_const((const crypto_aimer_gf *)matrix_U, i, 0, alg), alg);
    crypto_aimer_field_mat_vec_mul(state[i], state[i], matrix_cell_const((const crypto_aimer_gf *)matrix_L, i, 0, alg), alg);
  }

  for (i = 1; i < alg->multiplications; i++)
  {
    crypto_aimer_field_add(state[0], state[0], state[i]);
  }
  crypto_aimer_field_add(state[0], state[0], vector_b);
  crypto_aimer_field_exp(state[0], state[0], sbox_exponents[alg->multiplications], alg);
  crypto_aimer_field_add(ct_gf, state[0], pt_gf);
  crypto_aimer_field_to_bytes(ct, ct_gf, alg);

  crypto_zeroize(matrices, 2u * matrix_bytes);
  free(matrices);
  crypto_zeroize(vector_b, sizeof(vector_b));
  crypto_zeroize(state, sizeof(state));
  crypto_zeroize(pt_gf, sizeof(pt_gf));
  crypto_zeroize(ct_gf, sizeof(ct_gf));
  return LIBERAC_SUCCESS;
}

void crypto_aimer_aim2_sbox_outputs(crypto_aimer_gf *sbox_outputs, const crypto_aimer_gf pt, const crypto_aimer_params *alg)
{
  const crypto_aimer_gf *constants = crypto_aimer_aim2_constants_for_alg(alg);
  const uint64_t (*sbox_exponents)[CRYPTO_AIMER_FIELD_MAX_WORDS] =
    crypto_aimer_aim2_sbox_exponents_for_alg(alg);
  size_t i;

  for (i = 0; i < alg->multiplications; i++)
  {
    crypto_aimer_field_add(sbox_outputs[i], pt, constants[i]);
    crypto_aimer_field_exp(sbox_outputs[i], sbox_outputs[i], sbox_exponents[i], alg);
  }
}

void crypto_aimer_aim2_mpc(crypto_aimer_mult_check *mult_chk, const crypto_aimer_gf *matrix_A, const crypto_aimer_gf ct_gf,
              const crypto_aimer_params *alg)
{
  const size_t *exponents = crypto_aimer_aim2_exponents_for_alg(alg);
  const crypto_aimer_gf *constants = crypto_aimer_aim2_constants_for_alg(alg);
  size_t ell;
  size_t i;

  for (ell = 0; ell < alg->multiplications; ell++)
  {
    crypto_aimer_field_sqr(mult_chk->z_shares[ell], mult_chk->x_shares[ell], alg);
    for (i = 1; i < exponents[ell]; i++)
    {
      crypto_aimer_field_sqr(mult_chk->z_shares[ell], mult_chk->z_shares[ell], alg);
    }
    crypto_aimer_field_mul_add(mult_chk->z_shares[ell], mult_chk->x_shares[ell], constants[ell], alg);
    crypto_aimer_field_mat_vec_mul_add(mult_chk->x_shares[alg->multiplications],
                       mult_chk->x_shares[ell],
                       (const crypto_aimer_gf *)matrix_cell_const(matrix_A, ell, 0, alg), alg);
  }

  crypto_aimer_field_sqr(mult_chk->z_shares[alg->multiplications], mult_chk->x_shares[alg->multiplications], alg);
  for (i = 1; i < exponents[alg->multiplications]; i++)
  {
    crypto_aimer_field_sqr(mult_chk->z_shares[alg->multiplications], mult_chk->z_shares[alg->multiplications], alg);
  }
  crypto_aimer_field_mul_add(mult_chk->z_shares[alg->multiplications], mult_chk->x_shares[alg->multiplications], ct_gf, alg);
}
