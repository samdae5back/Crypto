#include "Crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_ml_dsa_variant(AlgID alg) {
    static const uint8_t message[] = {'p','q','-','s','i','g'};
    static const uint8_t context[] = {'t','e','s','t'};
    size_t pk_len = CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(alg);
    size_t sk_len = CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(alg);
    size_t sig_len = CRYPTO_ML_DSA_SIGNATURE_SIZE(alg);
    uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
    int failed = 1;

    if (!pk_len || !sk_len || !sig_len) return 1;
    pk = (uint8_t *)malloc(pk_len);
    sk = (uint8_t *)malloc(sk_len);
    sig = (uint8_t *)malloc(sig_len);
    if (!pk || !sk || !sig) goto done;

    if (CRYPTO_ML_DSA_KEYGEN(pk, pk_len, sk, sk_len, alg) != CRYPTO_SUCCESS) goto done;
    if (CRYPTO_ML_DSA_SIGN(sk, sk_len, message, sizeof(message), context, sizeof(context),
                           sig, sig_len, alg) != CRYPTO_SUCCESS) goto done;
    if (CRYPTO_ML_DSA_VERIFY(pk, pk_len, message, sizeof(message), context, sizeof(context),
                             sig, sig_len, alg) != CRYPTO_SUCCESS) goto done;

    sig[0] ^= 1u;
    if (CRYPTO_ML_DSA_VERIFY(pk, pk_len, message, sizeof(message), context, sizeof(context),
                             sig, sig_len, alg) != CRYPTO_ERROR_SIGNATURE_INVALID) goto done;
    sig[0] ^= 1u;
    failed = 0;

done:
    if (sk) memset(sk, 0, sk_len);
    if (sig) memset(sig, 0, sig_len);
    free(pk); free(sk); free(sig);
    return failed;
}

static int test_slh_dsa_variant(AlgID alg) {
    static const uint8_t message[] = {'p','q','-','s','i','g'};
    static const uint8_t context[] = {'t','e','s','t'};
    size_t pk_len = CRYPTO_SLH_DSA_PUBLIC_KEY_SIZE(alg);
    size_t sk_len = CRYPTO_SLH_DSA_PRIVATE_KEY_SIZE(alg);
    size_t sig_len = CRYPTO_SLH_DSA_SIGNATURE_SIZE(alg);
    uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
    int failed = 1;

    if (!pk_len || !sk_len || !sig_len) return 1;
    pk = (uint8_t *)malloc(pk_len);
    sk = (uint8_t *)malloc(sk_len);
    sig = (uint8_t *)malloc(sig_len);
    if (!pk || !sk || !sig) goto done;

    if (CRYPTO_SLH_DSA_KEYGEN(pk, pk_len, sk, sk_len, alg) != CRYPTO_SUCCESS) goto done;
    if (CRYPTO_SLH_DSA_SIGN(sk, sk_len, message, sizeof(message), context, sizeof(context),
                            sig, sig_len, alg) != CRYPTO_SUCCESS) goto done;
    if (CRYPTO_SLH_DSA_VERIFY(pk, pk_len, message, sizeof(message), context, sizeof(context),
                              sig, sig_len, alg) != CRYPTO_SUCCESS) goto done;

    sig[0] ^= 1u;
    if (CRYPTO_SLH_DSA_VERIFY(pk, pk_len, message, sizeof(message), context, sizeof(context),
                              sig, sig_len, alg) != CRYPTO_ERROR_SIGNATURE_INVALID) goto done;
    sig[0] ^= 1u;
    failed = 0;

done:
    if (sk) memset(sk, 0, sk_len);
    if (sig) memset(sig, 0, sig_len);
    free(pk); free(sk); free(sig);
    return failed;
}

static int test_sizes(void) {
    if (CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(ALG_ML_DSA_44) != CRYPTO_ML_DSA_44_PUBLIC_KEY_BYTES ||
        CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(ALG_ML_DSA_44) != CRYPTO_ML_DSA_44_PRIVATE_KEY_BYTES ||
        CRYPTO_ML_DSA_SIGNATURE_SIZE(ALG_ML_DSA_44) != CRYPTO_ML_DSA_44_SIGNATURE_BYTES) return 1;
    if (CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(ALG_ML_DSA_65) != CRYPTO_ML_DSA_65_PUBLIC_KEY_BYTES ||
        CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(ALG_ML_DSA_65) != CRYPTO_ML_DSA_65_PRIVATE_KEY_BYTES ||
        CRYPTO_ML_DSA_SIGNATURE_SIZE(ALG_ML_DSA_65) != CRYPTO_ML_DSA_65_SIGNATURE_BYTES) return 1;
    if (CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(ALG_ML_DSA_87) != CRYPTO_ML_DSA_87_PUBLIC_KEY_BYTES ||
        CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(ALG_ML_DSA_87) != CRYPTO_ML_DSA_87_PRIVATE_KEY_BYTES ||
        CRYPTO_ML_DSA_SIGNATURE_SIZE(ALG_ML_DSA_87) != CRYPTO_ML_DSA_87_SIGNATURE_BYTES) return 1;

    if (CRYPTO_SLH_DSA_PUBLIC_KEY_SIZE(ALG_SLH_DSA_SHA2_128S) != CRYPTO_SLH_DSA_128_PUBLIC_KEY_BYTES ||
        CRYPTO_SLH_DSA_PRIVATE_KEY_SIZE(ALG_SLH_DSA_SHA2_128S) != CRYPTO_SLH_DSA_128_PRIVATE_KEY_BYTES ||
        CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHA2_128S) != CRYPTO_SLH_DSA_128S_SIGNATURE_BYTES) return 1;
    if (CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHA2_128F) != CRYPTO_SLH_DSA_128F_SIGNATURE_BYTES) return 1;
    if (CRYPTO_SLH_DSA_PUBLIC_KEY_SIZE(ALG_SLH_DSA_SHA2_192S) != CRYPTO_SLH_DSA_192_PUBLIC_KEY_BYTES ||
        CRYPTO_SLH_DSA_PRIVATE_KEY_SIZE(ALG_SLH_DSA_SHA2_192S) != CRYPTO_SLH_DSA_192_PRIVATE_KEY_BYTES ||
        CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHA2_192S) != CRYPTO_SLH_DSA_192S_SIGNATURE_BYTES) return 1;
    if (CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHA2_192F) != CRYPTO_SLH_DSA_192F_SIGNATURE_BYTES) return 1;
    if (CRYPTO_SLH_DSA_PUBLIC_KEY_SIZE(ALG_SLH_DSA_SHA2_256S) != CRYPTO_SLH_DSA_256_PUBLIC_KEY_BYTES ||
        CRYPTO_SLH_DSA_PRIVATE_KEY_SIZE(ALG_SLH_DSA_SHA2_256S) != CRYPTO_SLH_DSA_256_PRIVATE_KEY_BYTES ||
        CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHA2_256S) != CRYPTO_SLH_DSA_256S_SIGNATURE_BYTES) return 1;
    if (CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHA2_256F) != CRYPTO_SLH_DSA_256F_SIGNATURE_BYTES) return 1;

    if (CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHAKE_128S) != CRYPTO_SLH_DSA_128S_SIGNATURE_BYTES ||
        CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHAKE_128F) != CRYPTO_SLH_DSA_128F_SIGNATURE_BYTES ||
        CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHAKE_192S) != CRYPTO_SLH_DSA_192S_SIGNATURE_BYTES ||
        CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHAKE_192F) != CRYPTO_SLH_DSA_192F_SIGNATURE_BYTES ||
        CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHAKE_256S) != CRYPTO_SLH_DSA_256S_SIGNATURE_BYTES ||
        CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_SLH_DSA_SHAKE_256F) != CRYPTO_SLH_DSA_256F_SIGNATURE_BYTES) return 1;

    if (CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(ALG_RSA_RAW) != 0u ||
        CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG_ML_DSA_44) != 0u) return 1;
    return 0;
}

int main(void) {
    static const AlgID ml_dsa[] = {
        ALG_ML_DSA_44, ALG_ML_DSA_65, ALG_ML_DSA_87
    };
    static const AlgID slh_dsa[] = {
        ALG_SLH_DSA_SHAKE_128S, ALG_SLH_DSA_SHAKE_128F,
        ALG_SLH_DSA_SHA2_128S, ALG_SLH_DSA_SHA2_128F,
        ALG_SLH_DSA_SHA2_192S, ALG_SLH_DSA_SHA2_192F,
        ALG_SLH_DSA_SHA2_256S, ALG_SLH_DSA_SHA2_256F,
        ALG_SLH_DSA_SHAKE_192S, ALG_SLH_DSA_SHAKE_192F,
        ALG_SLH_DSA_SHAKE_256S, ALG_SLH_DSA_SHAKE_256F
    };
    size_t i;

    if (test_sizes()) {
        fprintf(stderr, "PQ signature size table test failed\n");
        return 1;
    }
    for (i = 0u; i < sizeof(ml_dsa) / sizeof(ml_dsa[0]); ++i) {
        if (test_ml_dsa_variant(ml_dsa[i])) {
            fprintf(stderr, "ML-DSA algorithm %d roundtrip failed\n", (int)ml_dsa[i]);
            return 1;
        }
    }
    for (i = 0u; i < sizeof(slh_dsa) / sizeof(slh_dsa[0]); ++i) {
        if (test_slh_dsa_variant(slh_dsa[i])) {
            fprintf(stderr, "SLH-DSA algorithm %d roundtrip failed\n", (int)slh_dsa[i]);
            return 1;
        }
    }
    puts("all PQ signature variants passed");
    return 0;
}
