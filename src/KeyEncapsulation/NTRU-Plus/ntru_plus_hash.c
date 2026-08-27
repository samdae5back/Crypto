/*
 * NTRU+ domain-separated hashes.
 * Derived from the NTRU+ reference implementation.
 * SPDX-License-Identifier: MIT
 */

#include "ntru_plus_hash.h"

#include "HashFunction/SHA3/sha3_internal.h"

static void crypto_ntru_plus_hash_with_domain(
    uint8_t *output, size_t output_length,
    uint8_t domain, const uint8_t *input, size_t input_length)
{
    crypto_sha3_context context;

    crypto_shake256_init(&context);
    crypto_sha3_update(&context, &domain, 1u);
    crypto_sha3_update(&context, input, input_length);
    crypto_sha3_finalize(&context);
    crypto_sha3_squeeze(&context, output, output_length);
    crypto_sha3_clear(&context);
}

void crypto_ntru_plus_hash_f(
    uint8_t output[CRYPTO_NTRU_PLUS_SEED_BYTES], const uint8_t *input,
    const crypto_ntru_plus_parameters *parameters)
{
    crypto_ntru_plus_hash_with_domain(
        output, CRYPTO_NTRU_PLUS_SEED_BYTES, 0x00u,
        input, parameters->polynomial_bytes);
}

void crypto_ntru_plus_hash_g(
    uint8_t *output, const uint8_t *input,
    const crypto_ntru_plus_parameters *parameters)
{
    crypto_ntru_plus_hash_with_domain(
        output, parameters->n / 4u, 0x01u,
        input, parameters->polynomial_bytes);
}

void crypto_ntru_plus_hash_h(
    uint8_t *output, const uint8_t *input,
    const crypto_ntru_plus_parameters *parameters)
{
    crypto_ntru_plus_hash_with_domain(
        output, CRYPTO_NTRU_PLUS_SHARED_SECRET_BYTES + parameters->n / 4u,
        0x02u, input,
        parameters->n / 8u + CRYPTO_NTRU_PLUS_SEED_BYTES);
}
