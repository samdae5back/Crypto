/*
 * Runtime-parameter NTRU+ key encapsulation.
 * Derived from the NTRU+ reference implementation.
 * SPDX-License-Identifier: MIT
 */

#include "ntru_plus_internal.h"

#include <stdint.h>
#include <string.h>

#include "ntru_plus_hash.h"
#include "ntru_plus_parameter.h"
#include "ntru_plus_poly.h"
#include "HashFunction/SHA3/sha3_internal.h"
#include "RandomNumberGeneration/KAT/pqc_kat_rng_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/PQC/pqc_internal.h"

static const crypto_ntru_plus_parameters crypto_ntru_plus_parameter_sets[] = {
    {
        LIBERAC_ALG_NTRU_PLUS_768,
        CRYPTO_NTRU_PLUS_768_N,
        CRYPTO_NTRU_PLUS_768_BASE_DEGREE,
        CRYPTO_NTRU_PLUS_768_POLYNOMIAL_BYTES,
        LIBERAC_NTRU_PLUS_768_PUBLIC_KEY_BYTES,
        LIBERAC_NTRU_PLUS_768_PRIVATE_KEY_BYTES,
        LIBERAC_NTRU_PLUS_768_CIPHERTEXT_BYTES
    },
    {
        LIBERAC_ALG_NTRU_PLUS_864,
        CRYPTO_NTRU_PLUS_864_N,
        CRYPTO_NTRU_PLUS_864_BASE_DEGREE,
        CRYPTO_NTRU_PLUS_864_POLYNOMIAL_BYTES,
        LIBERAC_NTRU_PLUS_864_PUBLIC_KEY_BYTES,
        LIBERAC_NTRU_PLUS_864_PRIVATE_KEY_BYTES,
        LIBERAC_NTRU_PLUS_864_CIPHERTEXT_BYTES
    },
    {
        LIBERAC_ALG_NTRU_PLUS_1152,
        CRYPTO_NTRU_PLUS_1152_N,
        CRYPTO_NTRU_PLUS_1152_BASE_DEGREE,
        CRYPTO_NTRU_PLUS_1152_POLYNOMIAL_BYTES,
        LIBERAC_NTRU_PLUS_1152_PUBLIC_KEY_BYTES,
        LIBERAC_NTRU_PLUS_1152_PRIVATE_KEY_BYTES,
        LIBERAC_NTRU_PLUS_1152_CIPHERTEXT_BYTES
    }
};

const crypto_ntru_plus_parameters *crypto_ntru_plus_parameters_for(LiberaCAlgID alg)
{
    size_t i;

    for (i = 0u;
         i < sizeof(crypto_ntru_plus_parameter_sets) /
             sizeof(crypto_ntru_plus_parameter_sets[0]);
         ++i) {
        if (crypto_ntru_plus_parameter_sets[i].alg == alg)
            return &crypto_ntru_plus_parameter_sets[i];
    }

    return NULL;
}

static int crypto_ntru_plus_generate_f(
    crypto_ntru_plus_poly *f, crypto_ntru_plus_poly *f_inverse,
    uint8_t *workspace, const uint8_t coins[CRYPTO_NTRU_PLUS_SEED_BYTES],
    const crypto_ntru_plus_parameters *parameters)
{
    crypto_shake256(
        workspace, parameters->n / 4u,
        coins, CRYPTO_NTRU_PLUS_SEED_BYTES);
    crypto_ntru_plus_poly_cbd1(f, workspace, parameters);
    crypto_ntru_plus_poly_triple(f, f, parameters);
    f->coeffs[0] = (int16_t)(f->coeffs[0] + 1);
    crypto_ntru_plus_poly_ntt(f, f, parameters);
    return crypto_ntru_plus_poly_baseinv(f_inverse, f, parameters);
}

static int crypto_ntru_plus_generate_g(
    crypto_ntru_plus_poly *g, crypto_ntru_plus_poly *g_inverse,
    uint8_t *workspace, const uint8_t coins[CRYPTO_NTRU_PLUS_SEED_BYTES],
    const crypto_ntru_plus_parameters *parameters)
{
    crypto_shake256(
        workspace, parameters->n / 4u,
        coins, CRYPTO_NTRU_PLUS_SEED_BYTES);
    crypto_ntru_plus_poly_cbd1(g, workspace, parameters);
    crypto_ntru_plus_poly_triple(g, g, parameters);
    crypto_ntru_plus_poly_ntt(g, g, parameters);
    return crypto_ntru_plus_poly_baseinv(g_inverse, g, parameters);
}

static void crypto_ntru_plus_encode_keypair(
    uint8_t *public_key, uint8_t *private_key,
    const crypto_ntru_plus_poly *f,
    const crypto_ntru_plus_poly *f_inverse,
    const crypto_ntru_plus_poly *g,
    const crypto_ntru_plus_poly *g_inverse,
    const crypto_ntru_plus_parameters *parameters)
{
    crypto_ntru_plus_poly h;
    crypto_ntru_plus_poly h_inverse;

    crypto_ntru_plus_poly_basemul(&h, g, f_inverse, parameters);
    crypto_ntru_plus_poly_basemul(&h_inverse, f, g_inverse, parameters);

    crypto_ntru_plus_poly_tobytes(public_key, &h, parameters);
    crypto_ntru_plus_poly_tobytes(private_key, f, parameters);
    crypto_ntru_plus_poly_tobytes(
        private_key + parameters->polynomial_bytes, &h_inverse, parameters);
    crypto_ntru_plus_hash_f(
        private_key + 2u * parameters->polynomial_bytes,
        public_key, parameters);

    crypto_zeroize(&h, sizeof(h));
    crypto_zeroize(&h_inverse, sizeof(h_inverse));
}

static LiberaCError crypto_ntru_plus_encaps_derandomized(
    uint8_t *ciphertext,
    uint8_t shared_secret[LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES],
    const uint8_t *public_key, const uint8_t *coins,
    const crypto_ntru_plus_parameters *parameters)
{
    uint8_t message[CRYPTO_NTRU_PLUS_MAX_N / 8u +
                    CRYPTO_NTRU_PLUS_SEED_BYTES];
    uint8_t hash_output[LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES +
                        CRYPTO_NTRU_PLUS_MAX_N / 4u];
    uint8_t encoded_r[CRYPTO_NTRU_PLUS_MAX_POLYNOMIAL_BYTES];
    crypto_ntru_plus_poly ciphertext_poly;
    crypto_ntru_plus_poly public_key_poly;
    crypto_ntru_plus_poly r;
    crypto_ntru_plus_poly encoded_message;
    LiberaCError result = LIBERAC_SUCCESS;

    if (crypto_ntru_plus_poly_frombytes(
            &public_key_poly, public_key, parameters) != 0) {
        result = LIBERAC_ERROR_INVALID_KEY;
        goto cleanup;
    }

    memcpy(message, coins, parameters->n / 8u);
    crypto_ntru_plus_hash_f(
        message + parameters->n / 8u, public_key, parameters);
    crypto_ntru_plus_hash_h(hash_output, message, parameters);

    crypto_ntru_plus_poly_cbd1(
        &r, hash_output + LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES, parameters);
    crypto_ntru_plus_poly_ntt(&r, &r, parameters);
    crypto_ntru_plus_poly_tobytes(encoded_r, &r, parameters);
    crypto_ntru_plus_hash_g(encoded_r, encoded_r, parameters);
    crypto_ntru_plus_poly_sotp_encode(
        &encoded_message, message, encoded_r, parameters);
    crypto_ntru_plus_poly_ntt(
        &encoded_message, &encoded_message, parameters);
    crypto_ntru_plus_poly_basemul_add(
        &ciphertext_poly, &public_key_poly, &r, &encoded_message, parameters);
    crypto_ntru_plus_poly_tobytes(
        ciphertext, &ciphertext_poly, parameters);
    memcpy(
        shared_secret, hash_output,
        LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES);

cleanup:
    if (result != LIBERAC_SUCCESS) {
        crypto_zeroize(ciphertext, parameters->ciphertext_bytes);
        crypto_zeroize(
            shared_secret, LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES);
    }
    crypto_zeroize(message, sizeof(message));
    crypto_zeroize(hash_output, sizeof(hash_output));
    crypto_zeroize(encoded_r, sizeof(encoded_r));
    crypto_zeroize(&ciphertext_poly, sizeof(ciphertext_poly));
    crypto_zeroize(&public_key_poly, sizeof(public_key_poly));
    crypto_zeroize(&r, sizeof(r));
    crypto_zeroize(&encoded_message, sizeof(encoded_message));
    return result;
}

size_t crypto_ntru_plus_public_key_size_internal(LiberaCAlgID alg)
{
    const crypto_ntru_plus_parameters *parameters =
        crypto_ntru_plus_parameters_for(alg);
    return parameters != NULL ? parameters->public_key_bytes : 0u;
}

size_t crypto_ntru_plus_private_key_size_internal(LiberaCAlgID alg)
{
    const crypto_ntru_plus_parameters *parameters =
        crypto_ntru_plus_parameters_for(alg);
    return parameters != NULL ? parameters->private_key_bytes : 0u;
}

size_t crypto_ntru_plus_ciphertext_size_internal(LiberaCAlgID alg)
{
    const crypto_ntru_plus_parameters *parameters =
        crypto_ntru_plus_parameters_for(alg);
    return parameters != NULL ? parameters->ciphertext_bytes : 0u;
}

LiberaCError crypto_ntru_plus_keygen_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length)
{
    const crypto_ntru_plus_parameters *parameters =
        crypto_ntru_plus_parameters_for(alg);
    uint8_t coins[CRYPTO_NTRU_PLUS_SEED_BYTES];
    uint8_t workspace[CRYPTO_NTRU_PLUS_MAX_N / 4u];
    crypto_ntru_plus_poly f;
    crypto_ntru_plus_poly f_inverse;
    crypto_ntru_plus_poly g;
    crypto_ntru_plus_poly g_inverse;
    LiberaCError result = LIBERAC_SUCCESS;

    if (parameters == NULL)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (public_key == NULL || private_key == NULL)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (public_key_length < parameters->public_key_bytes ||
        private_key_length < parameters->private_key_bytes)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (crypto_ranges_overlap(
            public_key, parameters->public_key_bytes,
            private_key, parameters->private_key_bytes))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    do {
        result = crypto_pqc_random_bytes_internal(coins, sizeof(coins));
        if (result != LIBERAC_SUCCESS)
            goto cleanup;
    } while (crypto_ntru_plus_generate_f(
        &f, &f_inverse, workspace, coins, parameters) != 0);

    do {
        result = crypto_pqc_random_bytes_internal(coins, sizeof(coins));
        if (result != LIBERAC_SUCCESS)
            goto cleanup;
    } while (crypto_ntru_plus_generate_g(
        &g, &g_inverse, workspace, coins, parameters) != 0);

    crypto_ntru_plus_encode_keypair(
        public_key, private_key,
        &f, &f_inverse, &g, &g_inverse, parameters);

cleanup:
    if (result != LIBERAC_SUCCESS) {
        crypto_zeroize(public_key, parameters->public_key_bytes);
        crypto_zeroize(private_key, parameters->private_key_bytes);
    }
    crypto_zeroize(coins, sizeof(coins));
    crypto_zeroize(workspace, sizeof(workspace));
    crypto_zeroize(&f, sizeof(f));
    crypto_zeroize(&f_inverse, sizeof(f_inverse));
    crypto_zeroize(&g, sizeof(g));
    crypto_zeroize(&g_inverse, sizeof(g_inverse));
    return result;
}

LiberaCError crypto_ntru_plus_encaps_internal(
    LiberaCAlgID alg,
    const uint8_t *public_key, size_t public_key_length,
    uint8_t shared_secret[LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES],
    uint8_t *ciphertext, size_t ciphertext_length)
{
    const crypto_ntru_plus_parameters *parameters =
        crypto_ntru_plus_parameters_for(alg);
    uint8_t coins[CRYPTO_NTRU_PLUS_MAX_N / 8u];
    LiberaCError result;

    if (parameters == NULL)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (public_key == NULL || shared_secret == NULL || ciphertext == NULL)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (public_key_length < parameters->public_key_bytes ||
        ciphertext_length < parameters->ciphertext_bytes)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (crypto_ranges_overlap(
            public_key, parameters->public_key_bytes,
            shared_secret, LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES) ||
        crypto_ranges_overlap(
            public_key, parameters->public_key_bytes,
            ciphertext, parameters->ciphertext_bytes) ||
        crypto_ranges_overlap(
            shared_secret, LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES,
            ciphertext, parameters->ciphertext_bytes))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    result = crypto_pqc_random_bytes_internal(coins, parameters->n / 8u);
    if (result == LIBERAC_SUCCESS) {
        result = crypto_ntru_plus_encaps_derandomized(
            ciphertext, shared_secret, public_key, coins, parameters);
    } else {
        crypto_zeroize(ciphertext, parameters->ciphertext_bytes);
        crypto_zeroize(
            shared_secret, LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES);
    }

    crypto_zeroize(coins, sizeof(coins));
    return result;
}

LiberaCError crypto_ntru_plus_decaps_internal(
    LiberaCAlgID alg,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t shared_secret[LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES])
{
    const crypto_ntru_plus_parameters *parameters =
        crypto_ntru_plus_parameters_for(alg);
    uint8_t message[CRYPTO_NTRU_PLUS_MAX_N / 8u +
                    CRYPTO_NTRU_PLUS_SEED_BYTES];
    uint8_t encoded_r[CRYPTO_NTRU_PLUS_MAX_POLYNOMIAL_BYTES];
    uint8_t regenerated_r[CRYPTO_NTRU_PLUS_MAX_POLYNOMIAL_BYTES];
    uint8_t hash_output[LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES +
                        CRYPTO_NTRU_PLUS_MAX_N / 4u];
    crypto_ntru_plus_poly ciphertext_poly;
    crypto_ntru_plus_poly f;
    crypto_ntru_plus_poly h_inverse;
    crypto_ntru_plus_poly r;
    crypto_ntru_plus_poly recovered_r;
    crypto_ntru_plus_poly message_poly;
    crypto_ntru_plus_poly transformed_message;
    LiberaCError result = LIBERAC_SUCCESS;
    int fail;

    if (parameters == NULL)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (private_key == NULL || ciphertext == NULL || shared_secret == NULL)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (private_key_length < parameters->private_key_bytes ||
        ciphertext_length < parameters->ciphertext_bytes)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (crypto_ranges_overlap(
            private_key, parameters->private_key_bytes,
            shared_secret, LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES) ||
        crypto_ranges_overlap(
            ciphertext, parameters->ciphertext_bytes,
            shared_secret, LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    if (crypto_ntru_plus_poly_frombytes(
            &f, private_key, parameters) != 0 ||
        crypto_ntru_plus_poly_frombytes(
            &h_inverse,
            private_key + parameters->polynomial_bytes,
            parameters) != 0) {
        result = LIBERAC_ERROR_INVALID_KEY;
        goto cleanup;
    }
    if (crypto_ntru_plus_poly_frombytes(
            &ciphertext_poly, ciphertext, parameters) != 0) {
        result = LIBERAC_ERROR_AUTHENTICATION_FAILED;
        goto cleanup;
    }

    crypto_ntru_plus_poly_basemul(
        &message_poly, &ciphertext_poly, &f, parameters);
    crypto_ntru_plus_poly_invntt(
        &message_poly, &message_poly, parameters);
    crypto_ntru_plus_poly_crepmod3(
        &message_poly, &message_poly, parameters);

    crypto_ntru_plus_poly_ntt(
        &transformed_message, &message_poly, parameters);
    crypto_ntru_plus_poly_sub(
        &ciphertext_poly, &ciphertext_poly,
        &transformed_message, parameters);
    crypto_ntru_plus_poly_basemul(
        &recovered_r, &ciphertext_poly, &h_inverse, parameters);

    crypto_ntru_plus_poly_tobytes(encoded_r, &recovered_r, parameters);
    crypto_ntru_plus_hash_g(regenerated_r, encoded_r, parameters);
    fail = crypto_ntru_plus_poly_sotp_decode(
        message, &message_poly, regenerated_r, parameters);

    memcpy(
        message + parameters->n / 8u,
        private_key + 2u * parameters->polynomial_bytes,
        CRYPTO_NTRU_PLUS_SEED_BYTES);
    crypto_ntru_plus_hash_h(hash_output, message, parameters);

    crypto_ntru_plus_poly_cbd1(
        &r, hash_output + LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES, parameters);
    crypto_ntru_plus_poly_ntt(&r, &r, parameters);
    crypto_ntru_plus_poly_tobytes(regenerated_r, &r, parameters);
    fail |= crypto_pqc_verify(
        encoded_r, regenerated_r, parameters->polynomial_bytes);

    if (fail != 0) {
        result = LIBERAC_ERROR_AUTHENTICATION_FAILED;
        goto cleanup;
    }
    memcpy(
        shared_secret, hash_output,
        LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES);

cleanup:
    if (result != LIBERAC_SUCCESS)
        crypto_zeroize(
            shared_secret, LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES);
    crypto_zeroize(message, sizeof(message));
    crypto_zeroize(encoded_r, sizeof(encoded_r));
    crypto_zeroize(regenerated_r, sizeof(regenerated_r));
    crypto_zeroize(hash_output, sizeof(hash_output));
    crypto_zeroize(&ciphertext_poly, sizeof(ciphertext_poly));
    crypto_zeroize(&f, sizeof(f));
    crypto_zeroize(&h_inverse, sizeof(h_inverse));
    crypto_zeroize(&r, sizeof(r));
    crypto_zeroize(&recovered_r, sizeof(recovered_r));
    crypto_zeroize(&message_poly, sizeof(message_poly));
    crypto_zeroize(&transformed_message, sizeof(transformed_message));
    return result;
}
