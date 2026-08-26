#include "ML_KEM.h"
#include "parameter.h"
#include "ML-KEM.h"

MLKEM_THREAD_LOCAL const mlkem_parameters *mlkem_active_parameters;

const mlkem_parameters *mlkem_parameters_for(AlgID alg) {
    size_t i;
    for (i = 0; i < sizeof(MLKEM_PARAMETER_SETS) / sizeof(MLKEM_PARAMETER_SETS[0]); ++i)
        if (MLKEM_PARAMETER_SETS[i].alg == alg) return &MLKEM_PARAMETER_SETS[i];
    return NULL;
}

size_t CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(AlgID alg) {
    switch (alg) {
        case ALG_ML_KEM_512: return ML_KEM_512_PUBLIC_KEY_BYTES;
        case ALG_ML_KEM_768: return ML_KEM_768_PUBLIC_KEY_BYTES;
        case ALG_ML_KEM_1024: return ML_KEM_1024_PUBLIC_KEY_BYTES;
        default: return 0;
    }
}

size_t CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(AlgID alg) {
    switch (alg) {
        case ALG_ML_KEM_512: return ML_KEM_512_PRIVATE_KEY_BYTES;
        case ALG_ML_KEM_768: return ML_KEM_768_PRIVATE_KEY_BYTES;
        case ALG_ML_KEM_1024: return ML_KEM_1024_PRIVATE_KEY_BYTES;
        default: return 0;
    }
}

size_t CRYPTO_ML_KEM_CIPHERTEXT_SIZE(AlgID alg) {
    switch (alg) {
        case ALG_ML_KEM_512: return ML_KEM_512_CIPHERTEXT_BYTES;
        case ALG_ML_KEM_768: return ML_KEM_768_CIPHERTEXT_BYTES;
        case ALG_ML_KEM_1024: return ML_KEM_1024_CIPHERTEXT_BYTES;
        default: return 0;
    }
}

CryptoError CRYPTO_ML_KEM_KEYGEN(AlgID alg, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len) {
    size_t need_pk = CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(alg);
    size_t need_sk = CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(alg);
    if (!need_pk || !need_sk) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!pk || !sk) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (pk_len < need_pk || sk_len < need_sk) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    mlkem_active_parameters = mlkem_parameters_for(alg);
    ML_KEM_KeyGen(pk, sk);
    return CRYPTO_SUCCESS;
}

CryptoError CRYPTO_ML_KEM_ENCAPS(AlgID alg, const uint8_t *pk, size_t pk_len, uint8_t ss[ML_KEM_SHARED_SECRET_BYTES], uint8_t *ct, size_t ct_len) {
    size_t need_pk = CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(alg);
    size_t need_ct = CRYPTO_ML_KEM_CIPHERTEXT_SIZE(alg);
    if (!need_pk || !need_ct) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!pk || !ss || !ct) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (pk_len < need_pk || ct_len < need_ct) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    mlkem_active_parameters = mlkem_parameters_for(alg);
    ML_KEM_Encaps((unsigned char *)pk, ss, ct);
    return CRYPTO_SUCCESS;
}

CryptoError CRYPTO_ML_KEM_DECAPS(AlgID alg, const uint8_t *sk, size_t sk_len, const uint8_t *ct, size_t ct_len, uint8_t ss[ML_KEM_SHARED_SECRET_BYTES]) {
    size_t need_sk = CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(alg);
    size_t need_ct = CRYPTO_ML_KEM_CIPHERTEXT_SIZE(alg);
    if (!need_sk || !need_ct) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!sk || !ct || !ss) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (sk_len < need_sk || ct_len < need_ct) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    mlkem_active_parameters = mlkem_parameters_for(alg);
    ML_KEM_Decaps((unsigned char *)sk, (unsigned char *)ct, ss);
    return CRYPTO_SUCCESS;
}
