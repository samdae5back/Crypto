#include "ML_KEM.h"

void ML_KEM_KeyGen_512(unsigned char *ek, unsigned char *dk);
void ML_KEM_Encaps_512(unsigned char *ek, unsigned char *ss, unsigned char *ct);
void ML_KEM_Decaps_512(unsigned char *dk, unsigned char *ct, unsigned char *ss);
void ML_KEM_KeyGen_768(unsigned char *ek, unsigned char *dk);
void ML_KEM_Encaps_768(unsigned char *ek, unsigned char *ss, unsigned char *ct);
void ML_KEM_Decaps_768(unsigned char *dk, unsigned char *ct, unsigned char *ss);
void ML_KEM_KeyGen_1024(unsigned char *ek, unsigned char *dk);
void ML_KEM_Encaps_1024(unsigned char *ek, unsigned char *ss, unsigned char *ct);
void ML_KEM_Decaps_1024(unsigned char *dk, unsigned char *ct, unsigned char *ss);

size_t ML_KEM_PUBLIC_KEY_SIZE(AlgID alg) {
    switch (alg) {
        case ALG_ML_KEM_512: return ML_KEM_512_PUBLIC_KEY_BYTES;
        case ALG_ML_KEM_768: return ML_KEM_768_PUBLIC_KEY_BYTES;
        case ALG_ML_KEM_1024: return ML_KEM_1024_PUBLIC_KEY_BYTES;
        default: return 0;
    }
}

size_t ML_KEM_PRIVATE_KEY_SIZE(AlgID alg) {
    switch (alg) {
        case ALG_ML_KEM_512: return ML_KEM_512_PRIVATE_KEY_BYTES;
        case ALG_ML_KEM_768: return ML_KEM_768_PRIVATE_KEY_BYTES;
        case ALG_ML_KEM_1024: return ML_KEM_1024_PRIVATE_KEY_BYTES;
        default: return 0;
    }
}

size_t ML_KEM_CIPHERTEXT_SIZE(AlgID alg) {
    switch (alg) {
        case ALG_ML_KEM_512: return ML_KEM_512_CIPHERTEXT_BYTES;
        case ALG_ML_KEM_768: return ML_KEM_768_CIPHERTEXT_BYTES;
        case ALG_ML_KEM_1024: return ML_KEM_1024_CIPHERTEXT_BYTES;
        default: return 0;
    }
}

CryptoError ML_KEM_KEYGEN(AlgID alg, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len) {
    size_t need_pk = ML_KEM_PUBLIC_KEY_SIZE(alg);
    size_t need_sk = ML_KEM_PRIVATE_KEY_SIZE(alg);
    if (!need_pk || !need_sk) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!pk || !sk) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (pk_len < need_pk || sk_len < need_sk) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    switch (alg) {
        case ALG_ML_KEM_512: ML_KEM_KeyGen_512(pk, sk); break;
        case ALG_ML_KEM_768: ML_KEM_KeyGen_768(pk, sk); break;
        case ALG_ML_KEM_1024: ML_KEM_KeyGen_1024(pk, sk); break;
        default: return CRYPTO_ERROR_INVALID_ALG_ID;
    }
    return CRYPTO_SUCCESS;
}

CryptoError ML_KEM_ENCAPS(AlgID alg, const uint8_t *pk, size_t pk_len, uint8_t ss[ML_KEM_SHARED_SECRET_BYTES], uint8_t *ct, size_t ct_len) {
    size_t need_pk = ML_KEM_PUBLIC_KEY_SIZE(alg);
    size_t need_ct = ML_KEM_CIPHERTEXT_SIZE(alg);
    if (!need_pk || !need_ct) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!pk || !ss || !ct) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (pk_len < need_pk || ct_len < need_ct) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    switch (alg) {
        case ALG_ML_KEM_512: ML_KEM_Encaps_512((unsigned char *)pk, ss, ct); break;
        case ALG_ML_KEM_768: ML_KEM_Encaps_768((unsigned char *)pk, ss, ct); break;
        case ALG_ML_KEM_1024: ML_KEM_Encaps_1024((unsigned char *)pk, ss, ct); break;
        default: return CRYPTO_ERROR_INVALID_ALG_ID;
    }
    return CRYPTO_SUCCESS;
}

CryptoError ML_KEM_DECAPS(AlgID alg, const uint8_t *sk, size_t sk_len, const uint8_t *ct, size_t ct_len, uint8_t ss[ML_KEM_SHARED_SECRET_BYTES]) {
    size_t need_sk = ML_KEM_PRIVATE_KEY_SIZE(alg);
    size_t need_ct = ML_KEM_CIPHERTEXT_SIZE(alg);
    if (!need_sk || !need_ct) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!sk || !ct || !ss) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (sk_len < need_sk || ct_len < need_ct) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    switch (alg) {
        case ALG_ML_KEM_512: ML_KEM_Decaps_512((unsigned char *)sk, (unsigned char *)ct, ss); break;
        case ALG_ML_KEM_768: ML_KEM_Decaps_768((unsigned char *)sk, (unsigned char *)ct, ss); break;
        case ALG_ML_KEM_1024: ML_KEM_Decaps_1024((unsigned char *)sk, (unsigned char *)ct, ss); break;
        default: return CRYPTO_ERROR_INVALID_ALG_ID;
    }
    return CRYPTO_SUCCESS;
}
