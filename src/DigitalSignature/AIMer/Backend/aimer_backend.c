/* SPDX-License-Identifier: MIT */

#include <stdlib.h>
#include <string.h>

#include "aimer_backend.h"
#include "aimer_aim2.h"
#include "aimer_field.h"
#include "aimer_tree.h"
#include "aimer_hash.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"

typedef struct crypto_aimer_tape {
  crypto_aimer_gf pt_share;
  crypto_aimer_gf t_shares[CRYPTO_AIMER_MAX_INPUT_SBOXES];
  crypto_aimer_gf a_share;
  crypto_aimer_gf c_share;
} crypto_aimer_tape;

static size_t aimer_proof_size(const crypto_aimer_params *alg)
{
  return (alg->log_parties * alg->seed_bytes) +
         alg->commit_bytes +
         ((alg->multiplications + 3U) * alg->field_bytes);
}

static uint8_t *signature_salt(uint8_t *sig)
{
  return sig;
}

static const uint8_t *signature_salt_const(const uint8_t *sig)
{
  return sig;
}

static uint8_t *signature_h1(uint8_t *sig, const crypto_aimer_params *alg)
{
  return sig + alg->salt_bytes;
}

static const uint8_t *signature_h1_const(const uint8_t *sig,
                                         const crypto_aimer_params *alg)
{
  return sig + alg->salt_bytes;
}

static uint8_t *signature_h2(uint8_t *sig, const crypto_aimer_params *alg)
{
  return signature_h1(sig, alg) + alg->commit_bytes;
}

static const uint8_t *signature_h2_const(const uint8_t *sig,
                                         const crypto_aimer_params *alg)
{
  return signature_h1_const(sig, alg) + alg->commit_bytes;
}

static uint8_t *signature_proof(uint8_t *sig, size_t rep,
                                const crypto_aimer_params *alg)
{
  return signature_h2(sig, alg) + alg->commit_bytes +
         (rep * aimer_proof_size(alg));
}

static const uint8_t *signature_proof_const(const uint8_t *sig, size_t rep,
                                            const crypto_aimer_params *alg)
{
  return signature_h2_const(sig, alg) + alg->commit_bytes +
         (rep * aimer_proof_size(alg));
}

static uint8_t *proof_reveal_path(uint8_t *proof)
{
  return proof;
}

static const uint8_t *proof_reveal_path_const(const uint8_t *proof)
{
  return proof;
}

static uint8_t *proof_missing_commitment(uint8_t *proof,
                                         const crypto_aimer_params *alg)
{
  return proof + (alg->log_parties * alg->seed_bytes);
}

static const uint8_t *proof_missing_commitment_const(const uint8_t *proof,
                                                     const crypto_aimer_params *alg)
{
  return proof + (alg->log_parties * alg->seed_bytes);
}

static uint8_t *proof_delta_pt(uint8_t *proof, const crypto_aimer_params *alg)
{
  return proof_missing_commitment(proof, alg) + alg->commit_bytes;
}

static const uint8_t *proof_delta_pt_const(const uint8_t *proof,
                                           const crypto_aimer_params *alg)
{
  return proof_missing_commitment_const(proof, alg) + alg->commit_bytes;
}

static uint8_t *proof_delta_ts(uint8_t *proof, size_t ell,
                               const crypto_aimer_params *alg)
{
  return proof_delta_pt(proof, alg) + ((ell + 1U) * alg->field_bytes);
}

static const uint8_t *proof_delta_ts_const(const uint8_t *proof, size_t ell,
                                           const crypto_aimer_params *alg)
{
  return proof_delta_pt_const(proof, alg) +
         ((ell + 1U) * alg->field_bytes);
}

static uint8_t *proof_delta_c(uint8_t *proof, const crypto_aimer_params *alg)
{
  return proof_delta_ts(proof, alg->multiplications, alg);
}

static const uint8_t *proof_delta_c_const(const uint8_t *proof,
                                          const crypto_aimer_params *alg)
{
  return proof_delta_ts_const(proof, alg->multiplications, alg);
}

static uint8_t *proof_missing_alpha(uint8_t *proof, const crypto_aimer_params *alg)
{
  return proof_delta_c(proof, alg) + alg->field_bytes;
}

static const uint8_t *proof_missing_alpha_const(const uint8_t *proof,
                                                const crypto_aimer_params *alg)
{
  return proof_delta_c_const(proof, alg) + alg->field_bytes;
}

static uint8_t *nodes_rep(uint8_t *nodes, size_t rep, const crypto_aimer_params *alg)
{
  return nodes + (rep * ((2U * alg->parties - 1U) * alg->seed_bytes));
}

static uint8_t *commit_cell(uint8_t *commits, size_t rep, size_t party,
                            const crypto_aimer_params *alg)
{
  return commits + (((rep * alg->parties) + party) * alg->commit_bytes);
}

static void squeeze_gf(crypto_aimer_hash_context *ctx, crypto_aimer_gf out, const crypto_aimer_params *alg)
{
  uint8_t buf[CRYPTO_AIMER_MAX_FIELD_BYTES];

  crypto_aimer_field_set0(out);
  crypto_aimer_hash_squeeze(ctx, buf, alg->field_bytes, alg);
  crypto_aimer_field_from_bytes(out, buf, alg);
  crypto_zeroize(buf, sizeof(buf));
}

static void squeeze_tape(crypto_aimer_hash_context *ctx, crypto_aimer_tape *tape,
                         const crypto_aimer_params *alg)
{
  size_t i;

  squeeze_gf(ctx, tape->pt_share, alg);
  for (i = 0; i < alg->multiplications; i++)
  {
    squeeze_gf(ctx, tape->t_shares[i], alg);
  }
  squeeze_gf(ctx, tape->a_share, alg);
  squeeze_gf(ctx, tape->c_share, alg);
}

static void squeeze_gfs(crypto_aimer_hash_context *ctx, crypto_aimer_gf *out, size_t count,
                        const crypto_aimer_params *alg)
{
  size_t i;

  for (i = 0; i < count; i++)
  {
    squeeze_gf(ctx, out[i], alg);
  }
}

static void absorb_gfs(crypto_aimer_hash_context *ctx, const crypto_aimer_gf *in, size_t count,
                       const crypto_aimer_params *alg)
{
  uint8_t buf[CRYPTO_AIMER_MAX_FIELD_BYTES];
  size_t i;

  for (i = 0; i < count; i++)
  {
    crypto_aimer_field_to_bytes(buf, in[i], alg);
    crypto_aimer_hash_absorb(ctx, buf, alg->field_bytes);
  }
  crypto_zeroize(buf, sizeof(buf));
}

static void commit_and_expand_tape(crypto_aimer_tape *tape, uint8_t *commit,
                                   const uint8_t *salt, size_t rep,
                                   size_t party, const uint8_t *seed,
                                   const crypto_aimer_params *alg)
{
  uint8_t rep_byte = (uint8_t)rep;
  uint8_t party_byte = (uint8_t)party;
  crypto_aimer_hash_context ctx;

  crypto_aimer_hash_init_prefix(&ctx, alg, CRYPTO_AIMER_HASH_PREFIX_5);
  crypto_aimer_hash_absorb(&ctx, salt, alg->salt_bytes);
  crypto_aimer_hash_absorb(&ctx, &rep_byte, sizeof(rep_byte));
  crypto_aimer_hash_absorb(&ctx, &party_byte, sizeof(party_byte));
  crypto_aimer_hash_absorb(&ctx, seed, alg->seed_bytes);
  crypto_aimer_hash_finalize(&ctx, alg);

  crypto_aimer_hash_squeeze(&ctx, commit, alg->commit_bytes, alg);
  squeeze_tape(&ctx, tape, alg);
  crypto_aimer_hash_clear(&ctx);
}

static CryptoError run_phase_1(uint8_t *sig, uint8_t *commits, uint8_t *nodes,
                        crypto_aimer_mult_check (*mult_chk)[CRYPTO_AIMER_MAX_PARTIES],
                        crypto_aimer_gf (*alpha_v_shares)[2][CRYPTO_AIMER_MAX_PARTIES],
                        const uint8_t *sk, const uint8_t *rnd,
                        const uint8_t *m, size_t mlen,
                        const uint8_t *pre, size_t prelen,
                        const crypto_aimer_params *alg)
{
  crypto_aimer_gf pt_gf = {0,};
  crypto_aimer_gf ct_gf = {0,};
  crypto_aimer_gf sbox_outputs[CRYPTO_AIMER_MAX_INPUT_SBOXES];
  crypto_aimer_gf *matrix_A;
  crypto_aimer_gf vector_b = {0,};
  crypto_aimer_hash_context ctx;
  uint8_t mu[CRYPTO_AIMER_MAX_COMMIT_BYTES];
  uint8_t root_seeds[CRYPTO_AIMER_MAX_REPETITIONS][CRYPTO_AIMER_MAX_SEED_BYTES];
  size_t rep;
  size_t party;
  size_t i;

  memset(root_seeds, 0, sizeof(root_seeds));

  crypto_aimer_field_from_bytes(pt_gf, sk, alg);
  crypto_aimer_field_from_bytes(ct_gf, sk + alg->field_bytes + alg->iv_bytes, alg);

  crypto_aimer_hash_init_prefix(&ctx, alg, alg->hash_prefix_0);
  crypto_aimer_hash_absorb(&ctx, sk + alg->field_bytes,
                alg->iv_bytes + alg->field_bytes);
  crypto_aimer_hash_absorb(&ctx, pre, prelen);
  crypto_aimer_hash_absorb(&ctx, m, mlen);
  crypto_aimer_hash_finalize(&ctx, alg);
  crypto_aimer_hash_squeeze(&ctx, mu, alg->commit_bytes, alg);
  crypto_aimer_hash_clear(&ctx);

  crypto_aimer_aim2_sbox_outputs(sbox_outputs, pt_gf, alg);

  matrix_A = malloc(sizeof(crypto_aimer_gf) * alg->multiplications * alg->field_bits);
  if (matrix_A == NULL)
  {
    crypto_zeroize(pt_gf, sizeof(pt_gf));
    crypto_zeroize(ct_gf, sizeof(ct_gf));
    crypto_zeroize(sbox_outputs, sizeof(sbox_outputs));
    crypto_zeroize(vector_b, sizeof(vector_b));
    crypto_zeroize(mu, sizeof(mu));
    crypto_zeroize(root_seeds, sizeof(root_seeds));
    return CRYPTO_ERROR_ALLOCATION_FAILED;
  }
  {
    const CryptoError matrix_error = crypto_aimer_aim2_generate_linear(
      matrix_A, vector_b, sk + alg->field_bytes, alg);
    if (matrix_error != CRYPTO_SUCCESS)
    {
      crypto_zeroize(matrix_A,
                     sizeof(crypto_aimer_gf) * alg->multiplications *
                       alg->field_bits);
      free(matrix_A);
      crypto_zeroize(pt_gf, sizeof(pt_gf));
      crypto_zeroize(ct_gf, sizeof(ct_gf));
      crypto_zeroize(sbox_outputs, sizeof(sbox_outputs));
      crypto_zeroize(vector_b, sizeof(vector_b));
      crypto_zeroize(mu, sizeof(mu));
      crypto_zeroize(root_seeds, sizeof(root_seeds));
      return matrix_error;
    }
  }

  crypto_aimer_hash_init_prefix(&ctx, alg, CRYPTO_AIMER_HASH_PREFIX_3);
  crypto_aimer_hash_absorb(&ctx, sk, alg->field_bytes);
  crypto_aimer_hash_absorb(&ctx, mu, alg->commit_bytes);
  crypto_aimer_hash_absorb(&ctx, rnd, alg->security_bytes);
  crypto_aimer_hash_finalize(&ctx, alg);
  crypto_aimer_hash_squeeze(&ctx, signature_salt(sig), alg->salt_bytes, alg);
  for (rep = 0; rep < alg->repetitions; rep++)
  {
    crypto_aimer_hash_squeeze(&ctx, root_seeds[rep], alg->seed_bytes, alg);
  }
  crypto_aimer_hash_clear(&ctx);

  crypto_aimer_hash_init_prefix(&ctx, alg, CRYPTO_AIMER_HASH_PREFIX_1);
  crypto_aimer_hash_absorb(&ctx, mu, alg->commit_bytes);
  crypto_aimer_hash_absorb(&ctx, signature_salt(sig), alg->salt_bytes);

  for (rep = 0; rep < alg->repetitions; rep++)
  {
    crypto_aimer_tape delta;
    crypto_aimer_tape tape;
    uint8_t *proof = signature_proof(sig, rep, alg);

    crypto_aimer_expand_tree(nodes_rep(nodes, rep, alg), signature_salt(sig), rep,
                root_seeds[rep], alg);
    memset(&delta, 0, sizeof(delta));

    for (party = 0; party < alg->parties; party++)
    {
      commit_and_expand_tape(&tape, commit_cell(commits, rep, party, alg),
                             signature_salt(sig), rep, party,
                             nodes_rep(nodes, rep, alg) +
                               ((party + alg->parties - 1U) * alg->seed_bytes),
                             alg);

      crypto_aimer_field_add(delta.pt_share, delta.pt_share, tape.pt_share);
      for (i = 0; i < alg->multiplications; i++)
      {
        crypto_aimer_field_add(delta.t_shares[i], delta.t_shares[i], tape.t_shares[i]);
      }
      crypto_aimer_field_add(delta.a_share, delta.a_share, tape.a_share);
      crypto_aimer_field_add(delta.c_share, delta.c_share, tape.c_share);
      crypto_aimer_field_set0(mult_chk[rep][party].x_shares[alg->multiplications]);

      if (party == alg->parties - 1U)
      {
        crypto_aimer_field_add(delta.pt_share, delta.pt_share, pt_gf);
        crypto_aimer_field_to_bytes(proof_delta_pt(proof, alg), delta.pt_share, alg);
        crypto_aimer_field_add(tape.pt_share, delta.pt_share, tape.pt_share);

        for (i = 0; i < alg->multiplications; i++)
        {
          crypto_aimer_field_add(delta.t_shares[i], delta.t_shares[i], sbox_outputs[i]);
          crypto_aimer_field_to_bytes(proof_delta_ts(proof, i, alg), delta.t_shares[i], alg);
          crypto_aimer_field_add(tape.t_shares[i], delta.t_shares[i], tape.t_shares[i]);
        }

        crypto_aimer_field_mul_add(delta.c_share, pt_gf, delta.a_share, alg);
        crypto_aimer_field_to_bytes(proof_delta_c(proof, alg), delta.c_share, alg);
        crypto_aimer_field_add(tape.c_share, delta.c_share, tape.c_share);

        crypto_aimer_field_copy(mult_chk[rep][party].x_shares[alg->multiplications], vector_b);
      }

      crypto_aimer_field_copy(mult_chk[rep][party].pt_share, tape.pt_share);
      for (i = 0; i < alg->multiplications; i++)
      {
        crypto_aimer_field_copy(mult_chk[rep][party].x_shares[i], tape.t_shares[i]);
      }
      crypto_aimer_field_copy(alpha_v_shares[rep][0][party], tape.a_share);
      crypto_aimer_field_copy(alpha_v_shares[rep][1][party], tape.c_share);

      crypto_aimer_aim2_mpc(&mult_chk[rep][party], (const crypto_aimer_gf *)matrix_A, ct_gf, alg);
    }

    crypto_aimer_hash_absorb(&ctx, commit_cell(commits, rep, 0, alg),
                  alg->commit_bytes * alg->parties);
    crypto_aimer_hash_absorb(&ctx, proof_delta_pt(proof, alg),
                  alg->field_bytes * (alg->multiplications + 2U));
    crypto_zeroize(&delta, sizeof(delta));
    crypto_zeroize(&tape, sizeof(tape));
  }

  crypto_aimer_hash_finalize(&ctx, alg);
  crypto_aimer_hash_squeeze(&ctx, signature_h1(sig, alg), alg->commit_bytes, alg);
  crypto_aimer_hash_clear(&ctx);

  crypto_zeroize(matrix_A,
                 sizeof(crypto_aimer_gf) * alg->multiplications * alg->field_bits);
  free(matrix_A);
  crypto_zeroize(pt_gf, sizeof(pt_gf));
  crypto_zeroize(ct_gf, sizeof(ct_gf));
  crypto_zeroize(sbox_outputs, sizeof(sbox_outputs));
  crypto_zeroize(vector_b, sizeof(vector_b));
  crypto_zeroize(mu, sizeof(mu));
  crypto_zeroize(root_seeds, sizeof(root_seeds));
  return CRYPTO_SUCCESS;
}

static void run_phase_2_and_3(uint8_t *sig,
                              crypto_aimer_gf (*alpha_v_shares)[2][CRYPTO_AIMER_MAX_PARTIES],
                              const crypto_aimer_mult_check (*mult_chk)[CRYPTO_AIMER_MAX_PARTIES],
                              const crypto_aimer_params *alg)
{
  crypto_aimer_gf epsilons[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1];
  crypto_aimer_gf alpha = {0,};
  crypto_aimer_hash_context ctx_e;
  crypto_aimer_hash_context ctx;
  size_t rep;
  size_t party;
  size_t ell;

  crypto_aimer_hash_init(&ctx_e, alg);
  crypto_aimer_hash_absorb(&ctx_e, signature_h1(sig, alg), alg->commit_bytes);
  crypto_aimer_hash_finalize(&ctx_e, alg);

  crypto_aimer_hash_init_prefix(&ctx, alg, CRYPTO_AIMER_HASH_PREFIX_2);
  crypto_aimer_hash_absorb(&ctx, signature_h1(sig, alg), alg->commit_bytes);
  crypto_aimer_hash_absorb(&ctx, signature_salt(sig), alg->salt_bytes);

  for (rep = 0; rep < alg->repetitions; rep++)
  {
    crypto_aimer_field_set0(alpha);
    squeeze_gfs(&ctx_e, epsilons, alg->multiplications + 1U, alg);

    for (party = 0; party < alg->parties; party++)
    {
      for (ell = 0; ell < alg->multiplications + 1U; ell++)
      {
        crypto_aimer_field_mul_add(alpha_v_shares[rep][0][party],
                   mult_chk[rep][party].x_shares[ell], epsilons[ell], alg);
        crypto_aimer_field_mul_add(alpha_v_shares[rep][1][party],
                   mult_chk[rep][party].z_shares[ell], epsilons[ell], alg);
      }
      crypto_aimer_field_add(alpha, alpha, alpha_v_shares[rep][0][party]);
    }

    for (party = 0; party < alg->parties; party++)
    {
      crypto_aimer_field_mul_add(alpha_v_shares[rep][1][party],
                 mult_chk[rep][party].pt_share, alpha, alg);
    }
    absorb_gfs(&ctx, (const crypto_aimer_gf *)alpha_v_shares[rep][0], alg->parties, alg);
    absorb_gfs(&ctx, (const crypto_aimer_gf *)alpha_v_shares[rep][1], alg->parties, alg);
  }

  crypto_aimer_hash_finalize(&ctx, alg);
  crypto_aimer_hash_squeeze(&ctx, signature_h2(sig, alg), alg->commit_bytes, alg);
  crypto_aimer_hash_clear(&ctx);
  crypto_aimer_hash_clear(&ctx_e);
  crypto_zeroize(epsilons, sizeof(epsilons));
  crypto_zeroize(alpha, sizeof(alpha));
}

CryptoError crypto_aimer_backend_keypair(uint8_t *pk, uint8_t *sk,
                            const uint8_t *pt, const uint8_t *iv,
                            const crypto_aimer_params *alg)
{
  if (pk == NULL || sk == NULL || pt == NULL || iv == NULL || alg == NULL)
    return CRYPTO_ERROR_INVALID_ARGUMENT;

  {
    const CryptoError error =
      crypto_aimer_aim2(pk + alg->iv_bytes, pt, iv, alg);
    if (error != CRYPTO_SUCCESS)
      return error;
  }

  memcpy(pk, iv, alg->iv_bytes);
  memcpy(sk, pt, alg->field_bytes);
  memcpy(sk + alg->field_bytes, pk,
         alg->iv_bytes + alg->field_bytes);

  return CRYPTO_SUCCESS;
}

CryptoError crypto_aimer_backend_sign(uint8_t *sig,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *pre, size_t prelen,
                              const uint8_t *rnd,
                              const uint8_t *sk,
                              const crypto_aimer_params *alg)
{
  uint8_t *nodes;
  uint8_t *commits;
  crypto_aimer_mult_check (*mult_chk)[CRYPTO_AIMER_MAX_PARTIES];
  crypto_aimer_gf (*alpha_v_shares)[2][CRYPTO_AIMER_MAX_PARTIES];
  uint8_t indices[CRYPTO_AIMER_MAX_REPETITIONS];
  crypto_aimer_hash_context ctx;
  size_t rep;
  size_t nodes_bytes;
  size_t commits_bytes;
  size_t mult_checks_bytes;
  size_t alpha_shares_bytes;
  CryptoError error = CRYPTO_ERROR_ALLOCATION_FAILED;

  if (sig == NULL || (!m && mlen != 0u) || (!pre && prelen != 0u) ||
      rnd == NULL || sk == NULL || alg == NULL)
    return CRYPTO_ERROR_INVALID_ARGUMENT;

  nodes_bytes = alg->repetitions * (2U * alg->parties - 1U) * alg->seed_bytes;
  commits_bytes = alg->repetitions * alg->parties * alg->commit_bytes;
  mult_checks_bytes = alg->repetitions * sizeof(*mult_chk);
  alpha_shares_bytes = alg->repetitions * sizeof(*alpha_v_shares);
  nodes = malloc(nodes_bytes);
  commits = malloc(commits_bytes);
  mult_chk = calloc(alg->repetitions, sizeof(*mult_chk));
  alpha_v_shares = calloc(alg->repetitions, sizeof(*alpha_v_shares));
  if (nodes == NULL || commits == NULL || mult_chk == NULL ||
      alpha_v_shares == NULL)
    goto cleanup;

  error = run_phase_1(sig, commits, nodes, mult_chk, alpha_v_shares, sk, rnd,
                      m, mlen, pre, prelen, alg);
  if (error != CRYPTO_SUCCESS)
    goto cleanup;
  run_phase_2_and_3(sig, alpha_v_shares,
                    (const crypto_aimer_mult_check (*)[CRYPTO_AIMER_MAX_PARTIES])mult_chk, alg);

  crypto_aimer_hash_init(&ctx, alg);
  crypto_aimer_hash_absorb(&ctx, signature_h2(sig, alg), alg->commit_bytes);
  crypto_aimer_hash_finalize(&ctx, alg);
  crypto_aimer_hash_squeeze(&ctx, indices, alg->repetitions, alg);
  crypto_aimer_hash_clear(&ctx);

  for (rep = 0; rep < alg->repetitions; rep++)
  {
    uint8_t *proof = signature_proof(sig, rep, alg);
    size_t i_bar = indices[rep] & ((1U << alg->log_parties) - 1U);

    crypto_aimer_reveal_all_but(proof_reveal_path(proof), nodes_rep(nodes, rep, alg), i_bar, alg);
    memcpy(proof_missing_commitment(proof, alg),
           commit_cell(commits, rep, i_bar, alg), alg->commit_bytes);
    crypto_aimer_field_to_bytes(proof_missing_alpha(proof, alg), alpha_v_shares[rep][0][i_bar], alg);
  }

  error = CRYPTO_SUCCESS;

cleanup:
  crypto_aimer_hash_clear(&ctx);
  crypto_zeroize(indices, sizeof(indices));
  crypto_zeroize(nodes, nodes != NULL ? nodes_bytes : 0u);
  crypto_zeroize(commits, commits != NULL ? commits_bytes : 0u);
  crypto_zeroize(mult_chk, mult_chk != NULL ? mult_checks_bytes : 0u);
  crypto_zeroize(alpha_v_shares,
                 alpha_v_shares != NULL ? alpha_shares_bytes : 0u);
  free(nodes);
  free(commits);
  free(mult_chk);
  free(alpha_v_shares);

  return error;
}

CryptoError crypto_aimer_backend_verify(const uint8_t *sig, size_t siglen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *pre, size_t prelen,
                           const uint8_t *pk,
                           const crypto_aimer_params *alg)
{
  crypto_aimer_gf ct_gf = {0,};
  crypto_aimer_gf vector_b = {0,};
  crypto_aimer_gf *matrix_A;
  crypto_aimer_hash_context ctx_e;
  crypto_aimer_hash_context ctx_h1;
  crypto_aimer_hash_context ctx_h2;
  uint8_t mu[CRYPTO_AIMER_MAX_COMMIT_BYTES];
  uint8_t h_1_prime[CRYPTO_AIMER_MAX_COMMIT_BYTES];
  uint8_t h_2_prime[CRYPTO_AIMER_MAX_COMMIT_BYTES];
  uint8_t indices[CRYPTO_AIMER_MAX_REPETITIONS];
  uint8_t *nodes;
  crypto_aimer_gf *pt_shares;
  crypto_aimer_gf *alpha_shares;
  crypto_aimer_gf *v_shares;
  size_t rep;
  size_t party;
  size_t ell;
  size_t matrix_bytes;
  size_t nodes_bytes;
  size_t shares_bytes;
  CryptoError error = CRYPTO_ERROR_SIGNATURE_INVALID;

  if (sig == NULL || (!m && mlen != 0u) || (!pre && prelen != 0u) ||
      pk == NULL || alg == NULL)
    return CRYPTO_ERROR_INVALID_ARGUMENT;

  if (siglen != alg->signature_bytes)
  {
    return CRYPTO_ERROR_SIGNATURE_INVALID;
  }

  matrix_bytes = sizeof(crypto_aimer_gf) * alg->multiplications * alg->field_bits;
  nodes_bytes = (2U * alg->parties - 2U) * alg->seed_bytes;
  shares_bytes = alg->parties * sizeof(crypto_aimer_gf);
  matrix_A = malloc(matrix_bytes);
  nodes = malloc(nodes_bytes);
  pt_shares = calloc(alg->parties, sizeof(crypto_aimer_gf));
  alpha_shares = calloc(alg->parties, sizeof(crypto_aimer_gf));
  v_shares = calloc(alg->parties, sizeof(crypto_aimer_gf));
  if (matrix_A == NULL || nodes == NULL || pt_shares == NULL ||
      alpha_shares == NULL || v_shares == NULL)
  {
    error = CRYPTO_ERROR_ALLOCATION_FAILED;
    goto cleanup;
  }

  crypto_aimer_field_from_bytes(ct_gf, pk + alg->iv_bytes, alg);

  {
    const CryptoError matrix_error =
      crypto_aimer_aim2_generate_linear(matrix_A, vector_b, pk, alg);
    if (matrix_error != CRYPTO_SUCCESS)
    {
      error = matrix_error;
      goto cleanup;
    }
  }

  crypto_aimer_hash_init(&ctx_e, alg);
  crypto_aimer_hash_absorb(&ctx_e, signature_h2_const(sig, alg), alg->commit_bytes);
  crypto_aimer_hash_finalize(&ctx_e, alg);
  crypto_aimer_hash_squeeze(&ctx_e, indices, alg->repetitions, alg);
  for (rep = 0; rep < alg->repetitions; rep++)
  {
    indices[rep] &= (uint8_t)((1U << alg->log_parties) - 1U);
  }

  crypto_aimer_hash_clear(&ctx_e);
  crypto_aimer_hash_init(&ctx_e, alg);
  crypto_aimer_hash_absorb(&ctx_e, signature_h1_const(sig, alg), alg->commit_bytes);
  crypto_aimer_hash_finalize(&ctx_e, alg);

  crypto_aimer_hash_init_prefix(&ctx_h1, alg, alg->hash_prefix_0);
  crypto_aimer_hash_absorb(&ctx_h1, pk, alg->iv_bytes + alg->field_bytes);
  crypto_aimer_hash_absorb(&ctx_h1, pre, prelen);
  crypto_aimer_hash_absorb(&ctx_h1, m, mlen);
  crypto_aimer_hash_finalize(&ctx_h1, alg);
  crypto_aimer_hash_squeeze(&ctx_h1, mu, alg->commit_bytes, alg);
  crypto_aimer_hash_clear(&ctx_h1);

  crypto_aimer_hash_init_prefix(&ctx_h1, alg, CRYPTO_AIMER_HASH_PREFIX_1);
  crypto_aimer_hash_absorb(&ctx_h1, mu, alg->commit_bytes);
  crypto_aimer_hash_absorb(&ctx_h1, signature_salt_const(sig), alg->salt_bytes);

  crypto_aimer_hash_init_prefix(&ctx_h2, alg, CRYPTO_AIMER_HASH_PREFIX_2);
  crypto_aimer_hash_absorb(&ctx_h2, signature_h1_const(sig, alg), alg->commit_bytes);
  crypto_aimer_hash_absorb(&ctx_h2, signature_salt_const(sig), alg->salt_bytes);

  for (rep = 0; rep < alg->repetitions; rep++)
  {
    const uint8_t *proof = signature_proof_const(sig, rep, alg);
    crypto_aimer_gf epsilons[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1];
    crypto_aimer_gf alpha = {0,};
    size_t i_bar = indices[rep];
    crypto_aimer_tape tape;
    crypto_aimer_mult_check mult_chk;
    uint8_t commit[CRYPTO_AIMER_MAX_COMMIT_BYTES];
    crypto_aimer_gf temp = {0,};

    crypto_aimer_reconstruct_tree(nodes, signature_salt_const(sig), proof_reveal_path_const(proof),
                     rep, i_bar, alg);
    squeeze_gfs(&ctx_e, epsilons, alg->multiplications + 1U, alg);

    crypto_aimer_field_set0(alpha);
    for (party = 0; party < alg->parties; party++)
    {
      if (party == i_bar)
      {
        crypto_aimer_hash_absorb(&ctx_h1, proof_missing_commitment_const(proof, alg),
                      alg->commit_bytes);
        crypto_aimer_field_from_bytes(alpha_shares[i_bar], proof_missing_alpha_const(proof, alg), alg);
        crypto_aimer_field_add(alpha, alpha, alpha_shares[i_bar]);
        continue;
      }

      commit_and_expand_tape(&tape, commit, signature_salt_const(sig), rep, party,
                             nodes + ((alg->parties + party - 2U) * alg->seed_bytes),
                             alg);
      crypto_aimer_hash_absorb(&ctx_h1, commit, alg->commit_bytes);

      memset(&mult_chk, 0, sizeof(mult_chk));
      if (party == alg->parties - 1U)
      {
        crypto_aimer_field_from_bytes(temp, proof_delta_pt_const(proof, alg), alg);
        crypto_aimer_field_add(tape.pt_share, tape.pt_share, temp);

        for (ell = 0; ell < alg->multiplications; ell++)
        {
          crypto_aimer_field_from_bytes(temp, proof_delta_ts_const(proof, ell, alg), alg);
          crypto_aimer_field_add(tape.t_shares[ell], tape.t_shares[ell], temp);
        }

        crypto_aimer_field_from_bytes(temp, proof_delta_c_const(proof, alg), alg);
        crypto_aimer_field_add(tape.c_share, tape.c_share, temp);

        crypto_aimer_field_copy(mult_chk.x_shares[alg->multiplications], vector_b);
      }

      for (ell = 0; ell < alg->multiplications; ell++)
      {
        crypto_aimer_field_copy(mult_chk.x_shares[ell], tape.t_shares[ell]);
      }
      crypto_aimer_field_copy(pt_shares[party], tape.pt_share);
      crypto_aimer_field_copy(alpha_shares[party], tape.a_share);
      crypto_aimer_field_copy(v_shares[party], tape.c_share);
      crypto_aimer_aim2_mpc(&mult_chk, (const crypto_aimer_gf *)matrix_A, ct_gf, alg);

      for (ell = 0; ell < alg->multiplications + 1U; ell++)
      {
        crypto_aimer_field_mul_add(alpha_shares[party], mult_chk.x_shares[ell], epsilons[ell], alg);
        crypto_aimer_field_mul_add(v_shares[party], mult_chk.z_shares[ell], epsilons[ell], alg);
      }
      crypto_aimer_field_add(alpha, alpha, alpha_shares[party]);
    }

    crypto_aimer_field_set0(v_shares[i_bar]);
    for (party = 0; party < alg->parties; party++)
    {
      if (party == i_bar)
      {
        continue;
      }

      crypto_aimer_field_mul_add(v_shares[party], pt_shares[party], alpha, alg);
      crypto_aimer_field_add(v_shares[i_bar], v_shares[i_bar], v_shares[party]);
    }

    absorb_gfs(&ctx_h2, (const crypto_aimer_gf *)alpha_shares, alg->parties, alg);
    absorb_gfs(&ctx_h2, (const crypto_aimer_gf *)v_shares, alg->parties, alg);
    crypto_aimer_hash_absorb(&ctx_h1, proof_delta_pt_const(proof, alg),
                  alg->field_bytes * (alg->multiplications + 2U));
  }

  crypto_aimer_hash_clear(&ctx_e);

  crypto_aimer_hash_finalize(&ctx_h1, alg);
  crypto_aimer_hash_squeeze(&ctx_h1, h_1_prime, alg->commit_bytes, alg);
  crypto_aimer_hash_clear(&ctx_h1);

  crypto_aimer_hash_finalize(&ctx_h2, alg);
  crypto_aimer_hash_squeeze(&ctx_h2, h_2_prime, alg->commit_bytes, alg);
  crypto_aimer_hash_clear(&ctx_h2);

  {
    const int h1_matches = crypto_constant_time_equal(
        h_1_prime, signature_h1_const(sig, alg), alg->commit_bytes);
    const int h2_matches = crypto_constant_time_equal(
        h_2_prime, signature_h2_const(sig, alg), alg->commit_bytes);

    if ((h1_matches & h2_matches) != 0)
    {
      error = CRYPTO_SUCCESS;
    }
  }

cleanup:
  crypto_aimer_hash_clear(&ctx_e);
  crypto_aimer_hash_clear(&ctx_h1);
  crypto_aimer_hash_clear(&ctx_h2);
  crypto_zeroize(ct_gf, sizeof(ct_gf));
  crypto_zeroize(vector_b, sizeof(vector_b));
  crypto_zeroize(mu, sizeof(mu));
  crypto_zeroize(h_1_prime, sizeof(h_1_prime));
  crypto_zeroize(h_2_prime, sizeof(h_2_prime));
  crypto_zeroize(indices, sizeof(indices));
  crypto_zeroize(matrix_A, matrix_A != NULL ? matrix_bytes : 0u);
  crypto_zeroize(nodes, nodes != NULL ? nodes_bytes : 0u);
  crypto_zeroize(pt_shares, pt_shares != NULL ? shares_bytes : 0u);
  crypto_zeroize(alpha_shares, alpha_shares != NULL ? shares_bytes : 0u);
  crypto_zeroize(v_shares, v_shares != NULL ? shares_bytes : 0u);
  free(matrix_A);
  free(nodes);
  free(pt_shares);
  free(alpha_shares);
  free(v_shares);
  return error;
}
