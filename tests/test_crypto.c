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
    if (CRYPTO_HASH(ALG_HASH_SHA3_256, abc, sizeof(abc), out, sizeof(out)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(out, expected, sizeof(out)) != 0) return 1;
    if (CRYPTO_HASH((AlgID)0x7fffffff, abc, sizeof(abc), out, sizeof(out)) != CRYPTO_ERROR_INVALID_ALG_ID) return 1;
    return 0;
}

static int test_aes(void) {
    static const uint8_t pt[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t key128[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t key192[24] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    };
    static const uint8_t key256[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t ct128[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };
    static const uint8_t ct192[16] = {
        0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91
    };
    static const uint8_t ct256[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89
    };
    static const uint8_t mode_key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t mode_pt[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const uint8_t cbc_ct[16] = {
        0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d
    };
    static const uint8_t ctr[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    static const uint8_t ctr_ct[16] = {
        0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce
    };
    AES_CONTEXT ctx;
    uint8_t out[16], dec[16];

    if (CRYPTO_AES_KEY_SIZE(ALG_AES_128) != 16u || CRYPTO_AES_KEY_SIZE(ALG_AES_192) != 24u || CRYPTO_AES_KEY_SIZE(ALG_AES_256) != 32u) return 1;
    if (CRYPTO_AES_KEY_SIZE(ALG_RSA_RAW) != 0u) return 1;

    if (CRYPTO_AES_CONTEXT_INIT(&ctx, ALG_AES_128, key128, sizeof(key128)) != CRYPTO_SUCCESS) return 1;
    if (CRYPTO_AES_ENCRYPT_BLOCK(&ctx, pt, out) != CRYPTO_SUCCESS || memcmp(out, ct128, sizeof(out)) != 0) { CRYPTO_AES_CONTEXT_CLEAR(&ctx); return 1; }
    if (CRYPTO_AES_DECRYPT_BLOCK(&ctx, out, dec) != CRYPTO_SUCCESS || memcmp(dec, pt, sizeof(dec)) != 0) { CRYPTO_AES_CONTEXT_CLEAR(&ctx); return 1; }
    CRYPTO_AES_CONTEXT_CLEAR(&ctx);

    if (CRYPTO_AES_ECB_ENCRYPT(ALG_AES_192, key192, sizeof(key192), pt, sizeof(pt), out, sizeof(out)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(out, ct192, sizeof(out)) != 0) return 1;
    if (CRYPTO_AES_ECB_DECRYPT(ALG_AES_192, key192, sizeof(key192), out, sizeof(out), dec, sizeof(dec)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(dec, pt, sizeof(dec)) != 0) return 1;

    if (CRYPTO_AES_CONTEXT_INIT(&ctx, ALG_AES_256, key256, sizeof(key256)) != CRYPTO_SUCCESS) return 1;
    if (CRYPTO_AES_ENCRYPT_BLOCK(&ctx, pt, out) != CRYPTO_SUCCESS || memcmp(out, ct256, sizeof(out)) != 0) { CRYPTO_AES_CONTEXT_CLEAR(&ctx); return 1; }
    CRYPTO_AES_CONTEXT_CLEAR(&ctx);

    if (CRYPTO_AES_CBC_ENCRYPT(ALG_AES_128, mode_key, sizeof(mode_key), iv, mode_pt, sizeof(mode_pt), out, sizeof(out)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(out, cbc_ct, sizeof(out)) != 0) return 1;
    if (CRYPTO_AES_CBC_DECRYPT(ALG_AES_128, mode_key, sizeof(mode_key), iv, out, sizeof(out), dec, sizeof(dec)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(dec, mode_pt, sizeof(dec)) != 0) return 1;

    if (CRYPTO_AES_CTR_CRYPT(ALG_AES_128, mode_key, sizeof(mode_key), ctr, mode_pt, sizeof(mode_pt), out, sizeof(out)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(out, ctr_ct, sizeof(out)) != 0) return 1;
    if (CRYPTO_AES_CTR_CRYPT(ALG_AES_128, mode_key, sizeof(mode_key), ctr, out, sizeof(out), dec, sizeof(dec)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(dec, mode_pt, sizeof(dec)) != 0) return 1;

    if (CRYPTO_AES_CONTEXT_INIT(&ctx, ALG_AES_128, key128, sizeof(key128) - 1u) != CRYPTO_ERROR_INVALID_KEY) return 1;
    if (CRYPTO_AES_CONTEXT_INIT(&ctx, ALG_RSA_RAW, key128, sizeof(key128)) != CRYPTO_ERROR_INVALID_ALG_ID) return 1;
    if (CRYPTO_AES_ECB_ENCRYPT(ALG_AES_128, key128, sizeof(key128), pt, sizeof(pt), out, sizeof(out) - 1u) != CRYPTO_ERROR_BUFFER_TOO_SMALL) return 1;
    if (CRYPTO_AES_CBC_ENCRYPT(ALG_AES_128, key128, sizeof(key128), iv, pt, sizeof(pt) - 1u, out, sizeof(out)) != CRYPTO_ERROR_INVALID_ARGUMENT) return 1;
    return 0;
}

static int test_aes_aead(void) {
    static const uint8_t gcm_key[16] = {0};
    static const uint8_t gcm_iv[12] = {0};
    static const uint8_t gcm_pt[16] = {0};
    static const uint8_t gcm_ct_expected[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
    };
    static const uint8_t gcm_tag_expected[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
    };
    static const uint8_t ccm_key[16] = {
        0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf
    };
    static const uint8_t ccm_nonce[13] = {
        0x00,0x00,0x00,0x03,0x02,0x01,0x00,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5
    };
    static const uint8_t ccm_aad[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
    static const uint8_t ccm_pt[23] = {
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,
        0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e
    };
    static const uint8_t ccm_ct_expected[23] = {
        0x58,0x8c,0x97,0x9a,0x61,0xc6,0x63,0xd2,0xf0,0x66,0xd0,0xc2,
        0xc0,0xf9,0x89,0x80,0x6d,0x5f,0x6b,0x61,0xda,0xc3,0x84
    };
    static const uint8_t ccm_tag_expected[8] = {0x17,0xe8,0xd1,0x2c,0xfd,0xf9,0x26,0xe0};
    uint8_t ct[32], pt[32], tag[16], bad_tag[16];
    size_t i;

    if (CRYPTO_AES_GCM_ENCRYPT(ALG_AES_128, gcm_key, sizeof(gcm_key), gcm_iv, sizeof(gcm_iv),
                        NULL, 0u, gcm_pt, sizeof(gcm_pt), ct, sizeof(ct), tag, sizeof(tag)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(ct, gcm_ct_expected, sizeof(gcm_ct_expected)) != 0 || memcmp(tag, gcm_tag_expected, sizeof(tag)) != 0) return 1;
    if (CRYPTO_AES_GCM_DECRYPT(ALG_AES_128, gcm_key, sizeof(gcm_key), gcm_iv, sizeof(gcm_iv),
                        NULL, 0u, ct, sizeof(gcm_pt), tag, sizeof(tag), pt, sizeof(pt)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(pt, gcm_pt, sizeof(gcm_pt)) != 0) return 1;
    memcpy(bad_tag, tag, sizeof(tag)); bad_tag[0] ^= 1u; memset(pt, 0xa5, sizeof(gcm_pt));
    if (CRYPTO_AES_GCM_DECRYPT(ALG_AES_128, gcm_key, sizeof(gcm_key), gcm_iv, sizeof(gcm_iv),
                        NULL, 0u, ct, sizeof(gcm_pt), bad_tag, sizeof(tag), pt, sizeof(pt)) != CRYPTO_ERROR_AUTHENTICATION_FAILED) return 1;
    for (i = 0; i < sizeof(gcm_pt); ++i) if (pt[i] != 0u) return 1;

    if (CRYPTO_AES_CCM_ENCRYPT(ALG_AES_128, ccm_key, sizeof(ccm_key), ccm_nonce, sizeof(ccm_nonce),
                        ccm_aad, sizeof(ccm_aad), ccm_pt, sizeof(ccm_pt), ct, sizeof(ct), tag, 8u) != CRYPTO_SUCCESS) return 1;
    if (memcmp(ct, ccm_ct_expected, sizeof(ccm_ct_expected)) != 0 || memcmp(tag, ccm_tag_expected, 8u) != 0) return 1;
    if (CRYPTO_AES_CCM_DECRYPT(ALG_AES_128, ccm_key, sizeof(ccm_key), ccm_nonce, sizeof(ccm_nonce),
                        ccm_aad, sizeof(ccm_aad), ct, sizeof(ccm_pt), tag, 8u, pt, sizeof(pt)) != CRYPTO_SUCCESS) return 1;
    if (memcmp(pt, ccm_pt, sizeof(ccm_pt)) != 0) return 1;
    memcpy(bad_tag, tag, 8u); bad_tag[7] ^= 1u; memset(pt, 0xa5, sizeof(ccm_pt));
    if (CRYPTO_AES_CCM_DECRYPT(ALG_AES_128, ccm_key, sizeof(ccm_key), ccm_nonce, sizeof(ccm_nonce),
                        ccm_aad, sizeof(ccm_aad), ct, sizeof(ccm_pt), bad_tag, 8u, pt, sizeof(pt)) != CRYPTO_ERROR_AUTHENTICATION_FAILED) return 1;
    for (i = 0; i < sizeof(ccm_pt); ++i) if (pt[i] != 0u) return 1;

    if (CRYPTO_AES_CCM_ENCRYPT(ALG_AES_128, ccm_key, sizeof(ccm_key), ccm_nonce, 6u,
                        NULL, 0u, NULL, 0u, ct, sizeof(ct), tag, 8u) != CRYPTO_ERROR_INVALID_ARGUMENT) return 1;
    if (CRYPTO_AES_CCM_ENCRYPT(ALG_AES_128, ccm_key, sizeof(ccm_key), ccm_nonce, sizeof(ccm_nonce),
                        NULL, 0u, NULL, 0u, ct, sizeof(ct), tag, 5u) != CRYPTO_ERROR_INVALID_ARGUMENT) return 1;
    return 0;
}

static int test_bignum(void) {
    static const uint8_t input[] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t output[sizeof(input)];
    BIGNUM n;
    CRYPTO_BIGNUM_INIT(&n);
    if (CRYPTO_BIGNUM_FROM_BYTES_BE(&n, input, sizeof(input)) != CRYPTO_SUCCESS) return 1;
    if (CRYPTO_BIGNUM_TO_BYTES_BE(&n, output, sizeof(output)) != CRYPTO_SUCCESS) { CRYPTO_BIGNUM_FREE(&n); return 1; }
    CRYPTO_BIGNUM_FREE(&n);
    return memcmp(input, output, sizeof(input)) != 0;
}

static int test_rsa(void) {
    static const uint8_t value[] = {42u};
    uint8_t decoded[sizeof(value)];
    RSA_PUBLIC_KEY pub;
    RSA_PRIVATE_KEY priv;
    BIGNUM m, c, d;
    int failed = 1;
    CRYPTO_RSA_PUBLIC_KEY_INIT(&pub); CRYPTO_RSA_PRIVATE_KEY_INIT(&priv);
    CRYPTO_BIGNUM_INIT(&m); CRYPTO_BIGNUM_INIT(&c); CRYPTO_BIGNUM_INIT(&d);
    if (CRYPTO_RSA_KEYGEN(ALG_RSA_RAW, &pub, &priv, 256u, 12u) != CRYPTO_SUCCESS) goto done;
    if (CRYPTO_BIGNUM_FROM_BYTES_BE(&m, value, sizeof(value)) != CRYPTO_SUCCESS) goto done;
    if (CRYPTO_RSA_ENCRYPT(ALG_RSA_RAW, &c, &m, &pub) != CRYPTO_SUCCESS) goto done;
    if (CRYPTO_RSA_DECRYPT(ALG_RSA_RAW, &d, &c, &priv) != CRYPTO_SUCCESS) goto done;
    if (CRYPTO_BIGNUM_TO_BYTES_BE(&d, decoded, sizeof(decoded)) != CRYPTO_SUCCESS) goto done;
    if (memcmp(value, decoded, sizeof(value)) != 0) goto done;
    if (CRYPTO_RSA_ENCRYPT(ALG_ML_KEM_512, &c, &m, &pub) != CRYPTO_ERROR_INVALID_ALG_ID) goto done;
    failed = 0;
done:
    CRYPTO_BIGNUM_FREE(&m); CRYPTO_BIGNUM_FREE(&c); CRYPTO_BIGNUM_FREE(&d);
    CRYPTO_RSA_PUBLIC_KEY_FREE(&pub); CRYPTO_RSA_PRIVATE_KEY_FREE(&priv);
    return failed;
}

static int test_mlkem_variant(AlgID alg) {
    size_t pk_len = CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(alg);
    size_t sk_len = CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(alg);
    size_t ct_len = CRYPTO_ML_KEM_CIPHERTEXT_SIZE(alg);
    uint8_t *pk = NULL, *sk = NULL, *ct = NULL;
    uint8_t ss1[ML_KEM_SHARED_SECRET_BYTES], ss2[ML_KEM_SHARED_SECRET_BYTES];
    int failed = 1;
    if (!pk_len || !sk_len || !ct_len) return 1;
    pk = (uint8_t *)malloc(pk_len); sk = (uint8_t *)malloc(sk_len); ct = (uint8_t *)malloc(ct_len);
    if (!pk || !sk || !ct) goto done;
    if (CRYPTO_ML_KEM_KEYGEN(alg, pk, pk_len, sk, sk_len) != CRYPTO_SUCCESS) goto done;
    if (CRYPTO_ML_KEM_ENCAPS(alg, pk, pk_len, ss1, ct, ct_len) != CRYPTO_SUCCESS) goto done;
    if (CRYPTO_ML_KEM_DECAPS(alg, sk, sk_len, ct, ct_len, ss2) != CRYPTO_SUCCESS) goto done;
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
    if (test_aes()) { fprintf(stderr, "aes test failed\n"); return 1; }
    if (test_aes_aead()) { fprintf(stderr, "aes aead test failed\n"); return 1; }
    if (test_bignum()) { fprintf(stderr, "bignum test failed\n"); return 1; }
    if (test_rsa()) { fprintf(stderr, "rsa test failed\n"); return 1; }
    for (i = 0; i < sizeof(mlkem)/sizeof(mlkem[0]); ++i) {
        if (test_mlkem_variant(mlkem[i])) {
            fprintf(stderr, "ML-KEM algorithm %d test failed\n", (int)mlkem[i]);
            return 1;
        }
    }
    puts("all tests passed");
    return 0;
}
