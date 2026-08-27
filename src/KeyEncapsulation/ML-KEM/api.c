#include "api_internal.h"
#include "parameter.h"
#include "ML-KEM.h"

MLKEM_THREAD_LOCAL const mlkem_parameters *mlkem_active_parameters;

const mlkem_parameters *mlkem_parameters_for(AlgID alg) {
    size_t i;
    for (i = 0; i < sizeof(MLKEM_PARAMETER_SETS) / sizeof(MLKEM_PARAMETER_SETS[0]); ++i)
        if (MLKEM_PARAMETER_SETS[i].alg == alg) return &MLKEM_PARAMETER_SETS[i];
    return NULL;
}

size_t crypto_ml_kem_public_key_size_internal(AlgID alg) {
    switch (alg) {
        case ALG_ML_KEM_512: return CRYPTO_ML_KEM_512_PUBLIC_KEY_BYTES;
        case ALG_ML_KEM_768: return CRYPTO_ML_KEM_768_PUBLIC_KEY_BYTES;
        case ALG_ML_KEM_1024: return CRYPTO_ML_KEM_1024_PUBLIC_KEY_BYTES;
        default: return 0;
    }
}

size_t crypto_ml_kem_private_key_size_internal(AlgID alg) {
    switch (alg) {
        case ALG_ML_KEM_512: return CRYPTO_ML_KEM_512_PRIVATE_KEY_BYTES;
        case ALG_ML_KEM_768: return CRYPTO_ML_KEM_768_PRIVATE_KEY_BYTES;
        case ALG_ML_KEM_1024: return CRYPTO_ML_KEM_1024_PRIVATE_KEY_BYTES;
        default: return 0;
    }
}

size_t crypto_ml_kem_ciphertext_size_internal(AlgID alg) {
    switch (alg) {
        case ALG_ML_KEM_512: return CRYPTO_ML_KEM_512_CIPHERTEXT_BYTES;
        case ALG_ML_KEM_768: return CRYPTO_ML_KEM_768_CIPHERTEXT_BYTES;
        case ALG_ML_KEM_1024: return CRYPTO_ML_KEM_1024_CIPHERTEXT_BYTES;
        default: return 0;
    }
}

CryptoError crypto_ml_kem_keygen_internal(AlgID alg, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len) {
    size_t need_pk = crypto_ml_kem_public_key_size_internal(alg);
    size_t need_sk = crypto_ml_kem_private_key_size_internal(alg);
    if (!need_pk || !need_sk) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!pk || !sk) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (pk_len < need_pk || sk_len < need_sk) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    mlkem_active_parameters = mlkem_parameters_for(alg);
    ML_KEM_KeyGen(pk, sk);
    return CRYPTO_SUCCESS;
}

CryptoError crypto_ml_kem_encaps_internal(AlgID alg, const uint8_t *pk, size_t pk_len, uint8_t ss[CRYPTO_ML_KEM_SHARED_SECRET_BYTES], uint8_t *ct, size_t ct_len) {
    size_t need_pk = crypto_ml_kem_public_key_size_internal(alg);
    size_t need_ct = crypto_ml_kem_ciphertext_size_internal(alg);
    if (!need_pk || !need_ct) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!pk || !ss || !ct) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (pk_len < need_pk || ct_len < need_ct) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    mlkem_active_parameters = mlkem_parameters_for(alg);
    ML_KEM_Encaps((unsigned char *)pk, ss, ct);
    return CRYPTO_SUCCESS;
}

CryptoError crypto_ml_kem_decaps_internal(AlgID alg, const uint8_t *sk, size_t sk_len, const uint8_t *ct, size_t ct_len, uint8_t ss[CRYPTO_ML_KEM_SHARED_SECRET_BYTES]) {
    size_t need_sk = crypto_ml_kem_private_key_size_internal(alg);
    size_t need_ct = crypto_ml_kem_ciphertext_size_internal(alg);
    if (!need_sk || !need_ct) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!sk || !ct || !ss) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (sk_len < need_sk || ct_len < need_ct) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    mlkem_active_parameters = mlkem_parameters_for(alg);
    ML_KEM_Decaps((unsigned char *)sk, (unsigned char *)ct, ss);
    return CRYPTO_SUCCESS;
}
