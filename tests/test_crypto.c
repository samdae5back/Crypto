#include "CRYPTO.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_hash(void) {
    static const uint8_t expected[32] = {
        0x3a,0x98,0x5d,0xa7,0x4f,0xe2,0x25,0xb2,0x04,0x5c,0x17,0x2d,0x6b,0xd3,0x90,0xbd,
        0x85,0x5f,0x08,0x6e,0x3e,0x9d,0x52,0x5b,0x46,0xbf,0xe2,0x45,0x11,0x43,0x15,0x32
    };
    uint8_t out[32];
    const uint8_t abc[3] = {'a','b','c'};
    if (HASH(ALG_HASH_SHA3_256, abc, sizeof(abc), out, sizeof(out)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(out, expected, sizeof(out)) != 0) return 1;
    if (HASH((AlgID)0x7fffffff, abc, sizeof(abc), out, sizeof(out)) != CRYPTO_ERROR_INVALID_ALG_ID) return 1;
    return 0;
}

static int test_endian(void) {
    uint8_t b[8];
    ENDIAN_STORE64_BE(b, UINT64_C(0x0123456789abcdef));
    if (ENDIAN_LOAD64_BE(b) != UINT64_C(0x0123456789abcdef)) return 1;
    ENDIAN_STORE64_LE(b, UINT64_C(0x0123456789abcdef));
    if (ENDIAN_LOAD64_LE(b) != UINT64_C(0x0123456789abcdef)) return 1;
    return 0;
}

static int test_bignum(void) {
    static const uint8_t input[] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t output[sizeof(input)];
    BIGNUM n;
    BIGNUM_INIT(&n);
    if (BIGNUM_FROM_BYTES_BE(&n, input, sizeof(input)) != CRYPTO_SUCCESS) return 1;
    if (BIGNUM_TO_BYTES_BE(&n, output, sizeof(output)) != CRYPTO_SUCCESS) { BIGNUM_FREE(&n); return 1; }
    BIGNUM_FREE(&n);
    return memcmp(input, output, sizeof(input)) != 0;
}

static int test_ntt(void) {
    NTT_PLAN plan;
    uint32_t a[8] = {1,2,3,4,5,6,7,8};
    uint32_t original[8];
    memcpy(original, a, sizeof(a));
    if (NTT_PLAN_INIT(&plan, 8u, 17u, 3u) != CRYPTO_SUCCESS) return 1;
    if (NTT_FORWARD(&plan, a) != CRYPTO_SUCCESS) return 1;
    if (NTT_INVERSE(&plan, a) != CRYPTO_SUCCESS) return 1;
    return memcmp(a, original, sizeof(a)) != 0;
}

static int test_rsa(void) {
    RSA_PUBLIC_KEY pub;
    RSA_PRIVATE_KEY priv;
    BIGNUM m, c, d;
    int failed = 1;
    RSA_PUBLIC_KEY_INIT(&pub); RSA_PRIVATE_KEY_INIT(&priv);
    BIGNUM_INIT(&m); BIGNUM_INIT(&c); BIGNUM_INIT(&d);
    if (RSA_KEYGEN(ALG_RSA_RAW, &pub, &priv, 256u, 12u) != CRYPTO_SUCCESS) goto done;
    if (BIGNUM_SET_U64(&m, 42u) != CRYPTO_SUCCESS) goto done;
    if (RSA_ENCRYPT(ALG_RSA_RAW, &c, &m, &pub) != CRYPTO_SUCCESS) goto done;
    if (RSA_DECRYPT(ALG_RSA_RAW, &d, &c, &priv) != CRYPTO_SUCCESS) goto done;
    if (BIGNUM_COMPARE(&m, &d) != 0) goto done;
    if (RSA_ENCRYPT(ALG_ML_KEM_512, &c, &m, &pub) != CRYPTO_ERROR_INVALID_ALG_ID) goto done;
    failed = 0;
done:
    BIGNUM_FREE(&m); BIGNUM_FREE(&c); BIGNUM_FREE(&d);
    RSA_PUBLIC_KEY_FREE(&pub); RSA_PRIVATE_KEY_FREE(&priv);
    return failed;
}

static int test_mlkem_variant(AlgID alg) {
    size_t pk_len = ML_KEM_PUBLIC_KEY_SIZE(alg);
    size_t sk_len = ML_KEM_PRIVATE_KEY_SIZE(alg);
    size_t ct_len = ML_KEM_CIPHERTEXT_SIZE(alg);
    uint8_t *pk = NULL, *sk = NULL, *ct = NULL;
    uint8_t ss1[ML_KEM_SHARED_SECRET_BYTES], ss2[ML_KEM_SHARED_SECRET_BYTES];
    int failed = 1;
    if (!pk_len || !sk_len || !ct_len) return 1;
    pk = (uint8_t *)malloc(pk_len); sk = (uint8_t *)malloc(sk_len); ct = (uint8_t *)malloc(ct_len);
    if (!pk || !sk || !ct) goto done;
    if (ML_KEM_KEYGEN(alg, pk, pk_len, sk, sk_len) != CRYPTO_SUCCESS) goto done;
    if (ML_KEM_ENCAPS(alg, pk, pk_len, ss1, ct, ct_len) != CRYPTO_SUCCESS) goto done;
    if (ML_KEM_DECAPS(alg, sk, sk_len, ct, ct_len, ss2) != CRYPTO_SUCCESS) goto done;
    if (memcmp(ss1, ss2, sizeof(ss1)) != 0) goto done;
    failed = 0;
done:
    free(pk); free(sk); free(ct);
    return failed;
}

int main(void) {
    const AlgID mlkem[] = {ALG_ML_KEM_512, ALG_ML_KEM_768, ALG_ML_KEM_1024};
    size_t i;
    if (test_hash()) { fprintf(stderr, "hash test failed\n"); return 1; }
    if (test_endian()) { fprintf(stderr, "endian test failed\n"); return 1; }
    if (test_bignum()) { fprintf(stderr, "bignum test failed\n"); return 1; }
    if (test_ntt()) { fprintf(stderr, "ntt test failed\n"); return 1; }
    if (test_rsa()) { fprintf(stderr, "rsa test failed\n"); return 1; }
    for (i = 0; i < sizeof(mlkem)/sizeof(mlkem[0]); ++i) {
        if (test_mlkem_variant(mlkem[i])) {
            fprintf(stderr, "%s test failed\n", ALGID_NAME(mlkem[i]));
            return 1;
        }
    }
    puts("all tests passed");
    return 0;
}
