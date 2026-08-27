#include "Crypto.h"

#include <stdio.h>
#include <string.h>

static int all_zero(const void *ptr, size_t length) {
    const uint8_t *p = (const uint8_t *)ptr;
    size_t i;
    for (i = 0u; i < length; ++i) {
        if (p[i] != 0u) return 0;
    }
    return 1;
}

static int test_nist_aes256_no_df(void) {
    static const uint8_t entropy[48] = {
        0xdf,0x5d,0x73,0xfa,0xa4,0x68,0x64,0x9e,0xdd,0xa3,0x3b,0x5c,0xca,0x79,0xb0,0xb0,
        0x56,0x00,0x41,0x9c,0xcb,0x7a,0x87,0x9d,0xdf,0xec,0x9d,0xb3,0x2e,0xe4,0x94,0xe5,
        0x53,0x1b,0x51,0xde,0x16,0xa3,0x0f,0x76,0x92,0x62,0x47,0x4c,0x73,0xbe,0xc0,0x10
    };
    static const uint8_t key_after_instantiate[32] = {
        0x8c,0x52,0xf9,0x01,0x63,0x2d,0x52,0x27,0x74,0xc0,0x8f,0xad,0x0e,0xb2,0xc3,0x3b,
        0x98,0xa7,0x01,0xa1,0x86,0x1a,0xec,0xf3,0xd8,0xa2,0x58,0x60,0x94,0x17,0x09,0xfd
    };
    static const uint8_t v_after_instantiate[16] = {
        0x21,0x7b,0x52,0x14,0x21,0x05,0x25,0x02,0x43,0xc0,0xb2,0xc2,0x06,0xb8,0xf5,0x9e
    };
    static const uint8_t returned_bits[64] = {
        0xd1,0xc0,0x7c,0xd9,0x5a,0xf8,0xa7,0xf1,0x10,0x12,0xc8,0x4c,0xe4,0x8b,0xb8,0xcb,
        0x87,0x18,0x9e,0x99,0xd4,0x0f,0xcc,0xb1,0x77,0x1c,0x61,0x9b,0xdf,0x82,0xab,0x22,
        0x80,0xb1,0xdc,0x2f,0x25,0x81,0xf3,0x91,0x64,0xf7,0xac,0x0c,0x51,0x04,0x94,0xb3,
        0xa4,0x3c,0x41,0xb7,0xdb,0x17,0x51,0x4c,0x87,0xb1,0x07,0xae,0x79,0x3e,0x01,0xc5
    };
    static const uint8_t final_key[32] = {
        0x1a,0x1c,0x6e,0x5f,0x1c,0xcc,0xc6,0x97,0x44,0x36,0xe5,0xfd,0x3f,0x01,0x5b,0xc8,
        0xe9,0xdc,0x0f,0x90,0x05,0x3b,0x73,0xe3,0xc1,0x9d,0x4d,0xfd,0x66,0xd1,0xb8,0x5a
    };
    static const uint8_t final_v[16] = {
        0x53,0xc7,0x8a,0xc6,0x1a,0x0b,0xac,0x9d,0x7d,0x2e,0x92,0xb1,0xe7,0x3e,0x33,0x92
    };
    CRYPTO_CTR_DRBG_CONTEXT ctx;
    uint8_t output[64];

    if (CRYPTO_CTR_DRBG_SEED_SIZE(ALG_CTR_DRBG_AES_256_NO_DF) != 48u) return 1;
    if (CRYPTO_CTR_DRBG_INSTANTIATE(&ctx, entropy, sizeof(entropy), NULL, 0u,
                                     NULL, 0u, ALG_CTR_DRBG_AES_256_NO_DF) != CRYPTO_SUCCESS) return 1;
    if (memcmp(ctx.KEY, key_after_instantiate, sizeof(key_after_instantiate)) != 0) return 1;
    if (memcmp(ctx.V, v_after_instantiate, sizeof(v_after_instantiate)) != 0) return 1;
    if (ctx.RESEED_COUNTER != 1u) return 1;

    if (CRYPTO_CTR_DRBG_GENERATE(&ctx, output, sizeof(output), NULL, 0u, 0) != CRYPTO_SUCCESS) return 1;
    if (CRYPTO_CTR_DRBG_GENERATE(&ctx, output, sizeof(output), NULL, 0u, 0) != CRYPTO_SUCCESS) return 1;
    if (memcmp(output, returned_bits, sizeof(returned_bits)) != 0) return 1;
    if (memcmp(ctx.KEY, final_key, sizeof(final_key)) != 0) return 1;
    if (memcmp(ctx.V, final_v, sizeof(final_v)) != 0) return 1;
    if (ctx.RESEED_COUNTER != 3u) return 1;

    ctx.RESEED_COUNTER = ((uint64_t)1u << 48) + 1u;
    if (CRYPTO_CTR_DRBG_GENERATE(&ctx, output, 16u, NULL, 0u, 0) != CRYPTO_ERROR_RESEED_REQUIRED) return 1;

    CRYPTO_CTR_DRBG_CLEAR(&ctx);
    if (!all_zero(&ctx, sizeof(ctx))) return 1;
    return 0;
}

static int test_df_variants(void) {
    const AlgID algs[] = {
        ALG_CTR_DRBG_AES_128_DF,
        ALG_CTR_DRBG_AES_192_DF,
        ALG_CTR_DRBG_AES_256_DF
    };
    uint8_t entropy[32], nonce[16], additional[13];
    uint8_t a[64], b[64];
    size_t i, j, key_length, security_length, nonce_length;

    for (i = 0u; i < sizeof(entropy); ++i) entropy[i] = (uint8_t)i;
    for (i = 0u; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(0x80u + i);
    for (i = 0u; i < sizeof(additional); ++i) additional[i] = (uint8_t)(0x40u + i);

    for (j = 0u; j < sizeof(algs) / sizeof(algs[0]); ++j) {
        CRYPTO_CTR_DRBG_CONTEXT c1, c2;
        key_length = (j == 0u) ? 16u : (j == 1u ? 24u : 32u);
        security_length = key_length;
        nonce_length = (security_length + 1u) / 2u;
        if (CRYPTO_CTR_DRBG_SEED_SIZE(algs[j]) != key_length + 16u) return 1;
        if (CRYPTO_CTR_DRBG_INSTANTIATE(&c1, entropy, security_length,
                                         nonce, nonce_length,
                                         (const uint8_t *)"crypto-test", 11u,
                                         algs[j]) != CRYPTO_SUCCESS) return 1;
        if (CRYPTO_CTR_DRBG_INSTANTIATE(&c2, entropy, security_length,
                                         nonce, nonce_length,
                                         (const uint8_t *)"crypto-test", 11u,
                                         algs[j]) != CRYPTO_SUCCESS) return 1;
        if (CRYPTO_CTR_DRBG_GENERATE(&c1, a, sizeof(a), additional, sizeof(additional), 0) != CRYPTO_SUCCESS) return 1;
        if (CRYPTO_CTR_DRBG_GENERATE(&c2, b, sizeof(b), additional, sizeof(additional), 0) != CRYPTO_SUCCESS) return 1;
        if (memcmp(a, b, sizeof(a)) != 0) return 1;
        CRYPTO_CTR_DRBG_CLEAR(&c1);
        CRYPTO_CTR_DRBG_CLEAR(&c2);
    }
    return 0;
}

int main(void) {
    if (test_nist_aes256_no_df()) {
        fprintf(stderr, "CTR_DRBG NIST KAT failed\n");
        return 1;
    }
    if (test_df_variants()) {
        fprintf(stderr, "CTR_DRBG derivation-function test failed\n");
        return 1;
    }
    puts("CTR_DRBG tests passed");
    return 0;
}
