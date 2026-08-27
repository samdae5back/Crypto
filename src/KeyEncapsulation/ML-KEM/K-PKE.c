/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdlib.h>
#include <string.h>

#include "K-PKE.h"
#include "NTT_.h"
#include "auxiliary.h"
#include "hash.h"
#include "parameter.h"
#include "Util/Core/secure_zero.h"

enum { MLKEM_MAX_PRF_BYTES = 64 * 3 };

typedef struct {
    unsigned char byte_buffer[MLKEM_MAX_PRF_BYTES];
    int matrix[MLKEM_MAX_K][MLKEM_MAX_K][MLKEM_N];
    int secret[MLKEM_MAX_K][MLKEM_N];
    int error[MLKEM_MAX_K][MLKEM_N];
    int secret_ntt[MLKEM_MAX_K][MLKEM_N];
    int error_ntt[MLKEM_MAX_K][MLKEM_N];
    int public_ntt[MLKEM_MAX_K][MLKEM_N];
    int polynomial[MLKEM_N];
} mlkem_keygen_workspace;

typedef struct {
    unsigned char byte_buffer[MLKEM_MAX_PRF_BYTES];
    int public_ntt[MLKEM_MAX_K][MLKEM_N];
    int matrix[MLKEM_MAX_K][MLKEM_MAX_K][MLKEM_N];
    int secret[MLKEM_MAX_K][MLKEM_N];
    int error[MLKEM_MAX_K][MLKEM_N];
    int secret_ntt[MLKEM_MAX_K][MLKEM_N];
    int ciphertext_vector[MLKEM_MAX_K][MLKEM_N];
    int ciphertext_vector_ntt[MLKEM_MAX_K][MLKEM_N];
    int scalar_error[MLKEM_N];
    int message_polynomial[MLKEM_N];
    int ciphertext_scalar[MLKEM_N];
    int ciphertext_scalar_ntt[MLKEM_N];
    int polynomial[MLKEM_N];
} mlkem_encrypt_workspace;

typedef struct {
    int ciphertext_vector[MLKEM_MAX_K][MLKEM_N];
    int private_ntt[MLKEM_MAX_K][MLKEM_N];
    int ciphertext_vector_ntt[MLKEM_MAX_K][MLKEM_N];
    int ciphertext_scalar[MLKEM_N];
    int message_polynomial[MLKEM_N];
    int polynomial[MLKEM_N];
    int polynomial_ntt[MLKEM_N];
} mlkem_decrypt_workspace;

static int mlkem_parameters_valid(void) {
    return mlkem_active_parameters != NULL && k >= 2 &&
           k <= MLKEM_MAX_K && (n_1 == 2 || n_1 == 3) && n_2 == 2 &&
           (d_u == 10 || d_u == 11) && (d_v == 4 || d_v == 5);
}

static void mlkem_workspace_free(void *workspace, size_t workspace_size) {
    if (!workspace) return;
    crypto_zeroize(workspace, workspace_size);
    free(workspace);
}

CryptoError K_PKE_KeyGen(const unsigned char *seed, unsigned char *public_key,
                         unsigned char *private_key) {
    mlkem_keygen_workspace *workspace = NULL;
    unsigned char rho[32] = { 0 };
    unsigned char sigma[32] = { 0 };
    unsigned char nonce = 0u;
    const int *zetas;
    CryptoError result = CRYPTO_ERROR_INTERNAL;
    int i;
    int j;
    int coefficient;

    if (!seed || !public_key || !private_key || !mlkem_parameters_valid())
        return CRYPTO_ERROR_INTERNAL;

    workspace = (mlkem_keygen_workspace *)calloc(1u, sizeof(*workspace));
    if (!workspace) return CRYPTO_ERROR_ALLOCATION_FAILED;

    memcpy(workspace->byte_buffer, seed, 32u);
    workspace->byte_buffer[32] = (unsigned char)k;
    G(workspace->byte_buffer, 33u, rho, sigma);

    for (i = 0; i < k; ++i) {
        for (j = 0; j < k; ++j) {
            memcpy(workspace->byte_buffer, rho, 32u);
            workspace->byte_buffer[32] = (unsigned char)j;
            workspace->byte_buffer[33] = (unsigned char)i;
            if (SampleNTT(workspace->byte_buffer, workspace->matrix[i][j],
                          34u) != 0)
                goto cleanup;
        }
    }

    for (i = 0; i < k; ++i) {
        if (PRF((size_t)n_1, sigma, nonce++, workspace->byte_buffer) != 0 ||
            SamplePolyCBD(workspace->byte_buffer, workspace->secret[i],
                          64u * (size_t)n_1) != 0)
            goto cleanup;
    }
    for (i = 0; i < k; ++i) {
        if (PRF((size_t)n_1, sigma, nonce++, workspace->byte_buffer) != 0 ||
            SamplePolyCBD(workspace->byte_buffer, workspace->error[i],
                          64u * (size_t)n_1) != 0)
            goto cleanup;
    }

    zetas = GenZeta();
    if (!zetas) goto cleanup;
    for (i = 0; i < k; ++i) {
        NTT(workspace->secret[i], workspace->secret_ntt[i], zetas);
        NTT(workspace->error[i], workspace->error_ntt[i], zetas);
    }

    for (i = 0; i < k; ++i) {
        memcpy(workspace->public_ntt[i], workspace->error_ntt[i],
               sizeof(workspace->public_ntt[i]));
        for (j = 0; j < k; ++j) {
            Multiply_NTT(workspace->matrix[i][j], workspace->secret_ntt[j],
                         workspace->polynomial, zetas);
            for (coefficient = 0; coefficient < MLKEM_N; ++coefficient) {
                workspace->public_ntt[i][coefficient] =
                    (workspace->public_ntt[i][coefficient] +
                     workspace->polynomial[coefficient]) % MLKEM_Q;
            }
        }
    }

    for (i = 0; i < k; ++i) {
        if (ByteEncode(workspace->public_ntt[i], 12u,
                       public_key + (size_t)i * 384u) != 0 ||
            ByteEncode(workspace->secret_ntt[i], 12u,
                       private_key + (size_t)i * 384u) != 0)
            goto cleanup;
    }
    memcpy(public_key + (size_t)k * 384u, rho, sizeof(rho));
    result = CRYPTO_SUCCESS;

cleanup:
    crypto_zeroize(rho, sizeof(rho));
    crypto_zeroize(sigma, sizeof(sigma));
    mlkem_workspace_free(workspace, sizeof(*workspace));
    return result;
}

CryptoError K_PKE_Enc(const unsigned char *public_key,
                      const unsigned char *message,
                      const unsigned char *randomness,
                      unsigned char *ciphertext) {
    mlkem_encrypt_workspace *workspace = NULL;
    unsigned char rho[32] = { 0 };
    unsigned char nonce = 0u;
    const int *zetas;
    CryptoError result = CRYPTO_ERROR_INTERNAL;
    int i;
    int j;
    int coefficient;

    if (!public_key || !message || !randomness || !ciphertext ||
        !mlkem_parameters_valid())
        return CRYPTO_ERROR_INTERNAL;

    workspace = (mlkem_encrypt_workspace *)calloc(1u, sizeof(*workspace));
    if (!workspace) return CRYPTO_ERROR_ALLOCATION_FAILED;

    for (i = 0; i < k; ++i) {
        if (ByteDecode(public_key + (size_t)i * 384u, 12u,
                       workspace->public_ntt[i]) != 0)
            goto cleanup;
    }
    memcpy(rho, public_key + (size_t)k * 384u, sizeof(rho));

    for (i = 0; i < k; ++i) {
        for (j = 0; j < k; ++j) {
            memcpy(workspace->byte_buffer, rho, 32u);
            workspace->byte_buffer[32] = (unsigned char)j;
            workspace->byte_buffer[33] = (unsigned char)i;
            if (SampleNTT(workspace->byte_buffer, workspace->matrix[i][j],
                          34u) != 0)
                goto cleanup;
        }
    }

    for (i = 0; i < k; ++i) {
        if (PRF((size_t)n_1, randomness, nonce++, workspace->byte_buffer) != 0 ||
            SamplePolyCBD(workspace->byte_buffer, workspace->secret[i],
                          64u * (size_t)n_1) != 0)
            goto cleanup;
    }
    for (i = 0; i < k; ++i) {
        if (PRF((size_t)n_2, randomness, nonce++, workspace->byte_buffer) != 0 ||
            SamplePolyCBD(workspace->byte_buffer, workspace->error[i],
                          64u * (size_t)n_2) != 0)
            goto cleanup;
    }
    if (PRF((size_t)n_2, randomness, nonce, workspace->byte_buffer) != 0 ||
        SamplePolyCBD(workspace->byte_buffer, workspace->scalar_error,
                      64u * (size_t)n_2) != 0)
        goto cleanup;

    zetas = GenZeta();
    if (!zetas) goto cleanup;
    for (i = 0; i < k; ++i)
        NTT(workspace->secret[i], workspace->secret_ntt[i], zetas);

    for (i = 0; i < k; ++i) {
        for (j = 0; j < k; ++j) {
            Multiply_NTT(workspace->matrix[j][i], workspace->secret_ntt[j],
                         workspace->polynomial, zetas);
            for (coefficient = 0; coefficient < MLKEM_N; ++coefficient) {
                workspace->ciphertext_vector_ntt[i][coefficient] =
                    (workspace->ciphertext_vector_ntt[i][coefficient] +
                     workspace->polynomial[coefficient]) % MLKEM_Q;
            }
        }
        NTT_inv(workspace->ciphertext_vector_ntt[i],
                workspace->ciphertext_vector[i], zetas);
        for (coefficient = 0; coefficient < MLKEM_N; ++coefficient) {
            workspace->ciphertext_vector[i][coefficient] =
                (workspace->ciphertext_vector[i][coefficient] +
                 workspace->error[i][coefficient]) % MLKEM_Q;
        }
    }

    if (ByteDecode(message, 1u, workspace->polynomial) != 0 ||
        Decomp(workspace->polynomial, 1, workspace->message_polynomial,
               MLKEM_N) != 0)
        goto cleanup;

    for (i = 0; i < k; ++i) {
        Multiply_NTT(workspace->public_ntt[i], workspace->secret_ntt[i],
                     workspace->polynomial, zetas);
        for (coefficient = 0; coefficient < MLKEM_N; ++coefficient) {
            workspace->ciphertext_scalar_ntt[coefficient] =
                (workspace->ciphertext_scalar_ntt[coefficient] +
                 workspace->polynomial[coefficient]) % MLKEM_Q;
        }
    }
    NTT_inv(workspace->ciphertext_scalar_ntt,
            workspace->ciphertext_scalar, zetas);
    for (coefficient = 0; coefficient < MLKEM_N; ++coefficient) {
        workspace->ciphertext_scalar[coefficient] =
            (workspace->ciphertext_scalar[coefficient] +
             workspace->scalar_error[coefficient] +
             workspace->message_polynomial[coefficient]) % MLKEM_Q;
    }

    for (i = 0; i < k; ++i) {
        if (Comp(workspace->ciphertext_vector[i], d_u,
                 workspace->polynomial, MLKEM_N) != 0 ||
            ByteEncode(workspace->polynomial, (size_t)d_u,
                       ciphertext + (size_t)i * 32u * (size_t)d_u) != 0)
            goto cleanup;
    }
    if (Comp(workspace->ciphertext_scalar, d_v, workspace->polynomial,
             MLKEM_N) != 0 ||
        ByteEncode(workspace->polynomial, (size_t)d_v,
                   ciphertext + (size_t)k * 32u * (size_t)d_u) != 0)
        goto cleanup;
    result = CRYPTO_SUCCESS;

cleanup:
    crypto_zeroize(rho, sizeof(rho));
    mlkem_workspace_free(workspace, sizeof(*workspace));
    return result;
}

CryptoError K_PKE_Dec(const unsigned char *private_key,
                      const unsigned char *ciphertext,
                      unsigned char *message) {
    mlkem_decrypt_workspace *workspace = NULL;
    const int *zetas;
    CryptoError result = CRYPTO_ERROR_INTERNAL;
    int i;
    int coefficient;

    if (!private_key || !ciphertext || !message || !mlkem_parameters_valid())
        return CRYPTO_ERROR_INTERNAL;

    workspace = (mlkem_decrypt_workspace *)calloc(1u, sizeof(*workspace));
    if (!workspace) return CRYPTO_ERROR_ALLOCATION_FAILED;

    for (i = 0; i < k; ++i) {
        if (ByteDecode(ciphertext + (size_t)i * 32u * (size_t)d_u,
                       (size_t)d_u, workspace->polynomial) != 0 ||
            Decomp(workspace->polynomial, d_u,
                   workspace->ciphertext_vector[i], MLKEM_N) != 0)
            goto cleanup;
    }
    if (ByteDecode(ciphertext + (size_t)k * 32u * (size_t)d_u,
                   (size_t)d_v, workspace->polynomial) != 0 ||
        Decomp(workspace->polynomial, d_v, workspace->ciphertext_scalar,
               MLKEM_N) != 0)
        goto cleanup;

    for (i = 0; i < k; ++i) {
        if (ByteDecode(private_key + (size_t)i * 384u, 12u,
                       workspace->private_ntt[i]) != 0)
            goto cleanup;
    }

    zetas = GenZeta();
    if (!zetas) goto cleanup;
    for (i = 0; i < k; ++i)
        NTT(workspace->ciphertext_vector[i],
            workspace->ciphertext_vector_ntt[i], zetas);

    for (i = 0; i < k; ++i) {
        Multiply_NTT(workspace->private_ntt[i],
                     workspace->ciphertext_vector_ntt[i],
                     workspace->polynomial_ntt, zetas);
        NTT_inv(workspace->polynomial_ntt, workspace->polynomial, zetas);
        for (coefficient = 0; coefficient < MLKEM_N; ++coefficient) {
            workspace->message_polynomial[coefficient] =
                (workspace->message_polynomial[coefficient] +
                 workspace->polynomial[coefficient]) % MLKEM_Q;
        }
    }
    for (coefficient = 0; coefficient < MLKEM_N; ++coefficient) {
        workspace->message_polynomial[coefficient] =
            (workspace->ciphertext_scalar[coefficient] -
             workspace->message_polynomial[coefficient] + MLKEM_Q) % MLKEM_Q;
    }

    if (Comp(workspace->message_polynomial, 1, workspace->polynomial,
             MLKEM_N) != 0 ||
        ByteEncode(workspace->polynomial, 1u, message) != 0)
        goto cleanup;
    result = CRYPTO_SUCCESS;

cleanup:
    mlkem_workspace_free(workspace, sizeof(*workspace));
    return result;
}
