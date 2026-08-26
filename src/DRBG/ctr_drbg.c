#include "CTR_DRBG.h"
#include "AES.h"
#include "RANDOM.h"
#include "INTERNAL/secure_zero.h"

#include <stdlib.h>
#include <string.h>

static CryptoError ctr_drbg_parameters(AlgID alg, AlgID *aes_alg, size_t *key_length,
                                       size_t *security_bytes, int *use_df) {
    switch (alg) {
        case ALG_CTR_DRBG_AES_128_DF:
        case ALG_CTR_DRBG_AES_128_NO_DF:
            if (aes_alg) *aes_alg = ALG_AES_128;
            if (key_length) *key_length = 16u;
            if (security_bytes) *security_bytes = 16u;
            if (use_df) *use_df = (alg == ALG_CTR_DRBG_AES_128_DF);
            return CRYPTO_SUCCESS;
        case ALG_CTR_DRBG_AES_192_DF:
        case ALG_CTR_DRBG_AES_192_NO_DF:
            if (aes_alg) *aes_alg = ALG_AES_192;
            if (key_length) *key_length = 24u;
            if (security_bytes) *security_bytes = 24u;
            if (use_df) *use_df = (alg == ALG_CTR_DRBG_AES_192_DF);
            return CRYPTO_SUCCESS;
        case ALG_CTR_DRBG_AES_256_DF:
        case ALG_CTR_DRBG_AES_256_NO_DF:
            if (aes_alg) *aes_alg = ALG_AES_256;
            if (key_length) *key_length = 32u;
            if (security_bytes) *security_bytes = 32u;
            if (use_df) *use_df = (alg == ALG_CTR_DRBG_AES_256_DF);
            return CRYPTO_SUCCESS;
        default:
            return CRYPTO_ERROR_INVALID_ALG_ID;
    }
}

size_t CTR_DRBG_SEED_SIZE(AlgID ALG) {
    size_t key_length = 0u;
    if (ctr_drbg_parameters(ALG, NULL, &key_length, NULL, NULL) != CRYPTO_SUCCESS) return 0u;
    return key_length + CTR_DRBG_BLOCK_BYTES;
}

static void increment_v(uint8_t v[16]) {
    int i;
    for (i = 15; i >= 0; --i) {
        v[i] = (uint8_t)(v[i] + 1u);
        if (v[i] != 0u) break;
    }
}

static void store32_be(uint8_t out[4], uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static CryptoError bcc(const AES_CONTEXT *ctx, const uint8_t iv[16],
                       const uint8_t *s, size_t s_length, uint8_t out[16]) {
    uint8_t chain[16] = {0}, x[16];
    size_t offset, i;
    CryptoError err;

    for (i = 0u; i < 16u; ++i) x[i] = (uint8_t)(chain[i] ^ iv[i]);
    err = AES_ENCRYPT_BLOCK(ctx, x, chain);
    if (err != CRYPTO_SUCCESS) goto done;
    for (offset = 0u; offset < s_length; offset += 16u) {
        for (i = 0u; i < 16u; ++i) x[i] = (uint8_t)(chain[i] ^ s[offset + i]);
        err = AES_ENCRYPT_BLOCK(ctx, x, chain);
        if (err != CRYPTO_SUCCESS) goto done;
    }
    memcpy(out, chain, 16u);

done:
    crypto_zeroize(x, sizeof(x));
    crypto_zeroize(chain, sizeof(chain));
    return err;
}

static CryptoError block_cipher_df(AlgID aes_alg, size_t key_length,
                                   const uint8_t *input, size_t input_length,
                                   uint8_t *output, size_t output_length) {
    AES_CONTEXT ctx;
    uint8_t initial_key[32], temp[48], iv[16], block[16], x[16];
    uint8_t *s = NULL;
    size_t s_length, used = 0u, generated = 0u, i;
    uint32_t counter = 0u;
    CryptoError err = CRYPTO_SUCCESS;

    if ((!input && input_length) || !output || output_length == 0u || output_length > CTR_DRBG_MAX_SEED_BYTES)
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (input_length > (size_t)UINT32_MAX || output_length > (size_t)UINT32_MAX)
        return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    if (input_length > ((size_t)-1) - 9u) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    s_length = 8u + input_length + 1u;
    if (s_length > ((size_t)-1) - 15u) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    s_length = (s_length + 15u) & ~(size_t)15u;
    s = (uint8_t *)calloc(1u, s_length);
    if (!s) return CRYPTO_ERROR_ALLOCATION_FAILED;

    store32_be(s, (uint32_t)input_length);
    store32_be(s + 4u, (uint32_t)output_length);
    if (input_length) memcpy(s + 8u, input, input_length);
    s[8u + input_length] = 0x80u;
    for (i = 0u; i < key_length; ++i) initial_key[i] = (uint8_t)i;

    err = AES_CONTEXT_INIT(&ctx, aes_alg, initial_key, key_length);
    if (err != CRYPTO_SUCCESS) goto done;
    while (used < key_length + 16u) {
        size_t copy_length;
        memset(iv, 0, sizeof(iv));
        store32_be(iv, counter++);
        err = bcc(&ctx, iv, s, s_length, block);
        if (err != CRYPTO_SUCCESS) goto clear_ctx;
        copy_length = key_length + 16u - used;
        if (copy_length > 16u) copy_length = 16u;
        memcpy(temp + used, block, copy_length);
        used += copy_length;
    }
    AES_CONTEXT_CLEAR(&ctx);

    memcpy(x, temp + key_length, 16u);
    err = AES_CONTEXT_INIT(&ctx, aes_alg, temp, key_length);
    if (err != CRYPTO_SUCCESS) goto done;
    while (generated < output_length) {
        size_t copy_length;
        err = AES_ENCRYPT_BLOCK(&ctx, x, x);
        if (err != CRYPTO_SUCCESS) goto clear_ctx;
        copy_length = output_length - generated;
        if (copy_length > 16u) copy_length = 16u;
        memcpy(output + generated, x, copy_length);
        generated += copy_length;
    }

clear_ctx:
    AES_CONTEXT_CLEAR(&ctx);

done:
    if (err != CRYPTO_SUCCESS && output) crypto_zeroize(output, output_length);
    if (s) {
        crypto_zeroize(s, s_length);
        free(s);
    }
    crypto_zeroize(initial_key, sizeof(initial_key));
    crypto_zeroize(temp, sizeof(temp));
    crypto_zeroize(iv, sizeof(iv));
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(x, sizeof(x));
    return err;
}

static CryptoError ctr_drbg_update(CTR_DRBG_CONTEXT *ctx, const uint8_t *provided_data) {
    AES_CONTEXT aes;
    AlgID aes_alg;
    uint8_t temp[CTR_DRBG_MAX_SEED_BYTES], block[16];
    size_t seed_length = (size_t)ctx->KEY_LENGTH + 16u;
    size_t used = 0u, copy_length, i;
    CryptoError err;

    err = ctr_drbg_parameters(ctx->ALG, &aes_alg, NULL, NULL, NULL);
    if (err != CRYPTO_SUCCESS) return err;
    err = AES_CONTEXT_INIT(&aes, aes_alg, ctx->KEY, ctx->KEY_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    while (used < seed_length) {
        increment_v(ctx->V);
        err = AES_ENCRYPT_BLOCK(&aes, ctx->V, block);
        if (err != CRYPTO_SUCCESS) goto done;
        copy_length = seed_length - used;
        if (copy_length > 16u) copy_length = 16u;
        memcpy(temp + used, block, copy_length);
        used += copy_length;
    }
    if (provided_data) {
        for (i = 0u; i < seed_length; ++i) temp[i] ^= provided_data[i];
    }
    memcpy(ctx->KEY, temp, ctx->KEY_LENGTH);
    memcpy(ctx->V, temp + ctx->KEY_LENGTH, 16u);

done:
    AES_CONTEXT_CLEAR(&aes);
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(temp, sizeof(temp));
    return err;
}

static CryptoError make_df_seed(CTR_DRBG_CONTEXT *ctx,
                                const uint8_t *a, size_t a_length,
                                const uint8_t *b, size_t b_length,
                                const uint8_t *c, size_t c_length,
                                uint8_t seed[CTR_DRBG_MAX_SEED_BYTES]) {
    AlgID aes_alg;
    size_t seed_length = (size_t)ctx->KEY_LENGTH + 16u;
    size_t total;
    uint8_t *joined = NULL;
    CryptoError err;

    if (a_length > (size_t)-1 - b_length || a_length + b_length > (size_t)-1 - c_length)
        return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    total = a_length + b_length + c_length;
    if (total > (size_t)UINT32_MAX) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    if (total) {
        joined = (uint8_t *)malloc(total);
        if (!joined) return CRYPTO_ERROR_ALLOCATION_FAILED;
        if (a_length) memcpy(joined, a, a_length);
        if (b_length) memcpy(joined + a_length, b, b_length);
        if (c_length) memcpy(joined + a_length + b_length, c, c_length);
    }
    err = ctr_drbg_parameters(ctx->ALG, &aes_alg, NULL, NULL, NULL);
    if (err == CRYPTO_SUCCESS)
        err = block_cipher_df(aes_alg, ctx->KEY_LENGTH, joined, total, seed, seed_length);
    if (joined) {
        crypto_zeroize(joined, total);
        free(joined);
    }
    return err;
}

static CryptoError prepare_additional(CTR_DRBG_CONTEXT *ctx, const uint8_t *additional,
                                      size_t additional_length,
                                      uint8_t seed[CTR_DRBG_MAX_SEED_BYTES]) {
    size_t seed_length = (size_t)ctx->KEY_LENGTH + 16u;
    if (!additional && additional_length) return CRYPTO_ERROR_INVALID_ARGUMENT;
    crypto_zeroize(seed, CTR_DRBG_MAX_SEED_BYTES);
    if (additional_length == 0u) return CRYPTO_SUCCESS;
    if (ctx->USE_DF)
        return make_df_seed(ctx, additional, additional_length, NULL, 0u, NULL, 0u, seed);
    if (additional_length > seed_length) return CRYPTO_ERROR_INVALID_ARGUMENT;
    memcpy(seed, additional, additional_length);
    return CRYPTO_SUCCESS;
}

CryptoError CTR_DRBG_INSTANTIATE(CTR_DRBG_CONTEXT *CONTEXT, AlgID ALG,
                                 const uint8_t *ENTROPY, size_t ENTROPY_LENGTH,
                                 const uint8_t *NONCE, size_t NONCE_LENGTH,
                                 const uint8_t *PERSONALIZATION, size_t PERSONALIZATION_LENGTH) {
    size_t key_length, security_bytes, seed_length, i;
    int use_df;
    uint8_t seed[CTR_DRBG_MAX_SEED_BYTES];
    CryptoError err;

    if (!CONTEXT || !ENTROPY || (!NONCE && NONCE_LENGTH) || (!PERSONALIZATION && PERSONALIZATION_LENGTH))
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ctr_drbg_parameters(ALG, NULL, &key_length, &security_bytes, &use_df);
    if (err != CRYPTO_SUCCESS) return err;
    seed_length = key_length + 16u;
    crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
    CONTEXT->ALG = ALG;
    CONTEXT->KEY_LENGTH = (uint8_t)key_length;
    CONTEXT->USE_DF = (uint8_t)(use_df != 0);

    if (use_df) {
        if (ENTROPY_LENGTH < security_bytes || NONCE_LENGTH < (security_bytes + 1u) / 2u) {
            CTR_DRBG_CLEAR(CONTEXT);
            return CRYPTO_ERROR_INVALID_ARGUMENT;
        }
        err = make_df_seed(CONTEXT, ENTROPY, ENTROPY_LENGTH, NONCE, NONCE_LENGTH,
                           PERSONALIZATION, PERSONALIZATION_LENGTH, seed);
    } else {
        if (ENTROPY_LENGTH != seed_length || NONCE_LENGTH != 0u || PERSONALIZATION_LENGTH > seed_length) {
            CTR_DRBG_CLEAR(CONTEXT);
            return CRYPTO_ERROR_INVALID_ARGUMENT;
        }
        memcpy(seed, ENTROPY, seed_length);
        for (i = 0u; i < PERSONALIZATION_LENGTH; ++i) seed[i] ^= PERSONALIZATION[i];
        err = CRYPTO_SUCCESS;
    }
    if (err == CRYPTO_SUCCESS) err = ctr_drbg_update(CONTEXT, seed);
    if (err == CRYPTO_SUCCESS) {
        CONTEXT->RESEED_COUNTER = 1u;
        CONTEXT->INSTANTIATED = 1u;
    } else {
        CTR_DRBG_CLEAR(CONTEXT);
    }
    crypto_zeroize(seed, sizeof(seed));
    return err;
}

CryptoError CTR_DRBG_RESEED(CTR_DRBG_CONTEXT *CONTEXT,
                            const uint8_t *ENTROPY, size_t ENTROPY_LENGTH,
                            const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH) {
    size_t security_bytes, seed_length, i;
    uint8_t seed[CTR_DRBG_MAX_SEED_BYTES];
    CryptoError err;

    if (!CONTEXT || !CONTEXT->INSTANTIATED || !ENTROPY || (!ADDITIONAL && ADDITIONAL_LENGTH))
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ctr_drbg_parameters(CONTEXT->ALG, NULL, NULL, &security_bytes, NULL);
    if (err != CRYPTO_SUCCESS) return err;
    seed_length = (size_t)CONTEXT->KEY_LENGTH + 16u;
    if (CONTEXT->USE_DF) {
        if (ENTROPY_LENGTH < security_bytes) return CRYPTO_ERROR_INVALID_ARGUMENT;
        err = make_df_seed(CONTEXT, ENTROPY, ENTROPY_LENGTH, ADDITIONAL, ADDITIONAL_LENGTH,
                           NULL, 0u, seed);
    } else {
        if (ENTROPY_LENGTH != seed_length || ADDITIONAL_LENGTH > seed_length)
            return CRYPTO_ERROR_INVALID_ARGUMENT;
        memcpy(seed, ENTROPY, seed_length);
        for (i = 0u; i < ADDITIONAL_LENGTH; ++i) seed[i] ^= ADDITIONAL[i];
        err = CRYPTO_SUCCESS;
    }
    if (err == CRYPTO_SUCCESS) err = ctr_drbg_update(CONTEXT, seed);
    if (err == CRYPTO_SUCCESS) CONTEXT->RESEED_COUNTER = 1u;
    crypto_zeroize(seed, sizeof(seed));
    return err;
}

CryptoError CTR_DRBG_INSTANTIATE_OS(CTR_DRBG_CONTEXT *CONTEXT, AlgID ALG,
                                    const uint8_t *PERSONALIZATION, size_t PERSONALIZATION_LENGTH) {
    size_t key_length, security_bytes, seed_length, nonce_length;
    int use_df;
    uint8_t entropy[CTR_DRBG_MAX_SEED_BYTES], nonce[16];
    CryptoError err;

    if (!CONTEXT || (!PERSONALIZATION && PERSONALIZATION_LENGTH)) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ctr_drbg_parameters(ALG, NULL, &key_length, &security_bytes, &use_df);
    if (err != CRYPTO_SUCCESS) return err;
    seed_length = key_length + 16u;
    nonce_length = use_df ? (security_bytes + 1u) / 2u : 0u;
    err = RANDOM_BYTES(entropy, use_df ? security_bytes : seed_length);
    if (err == CRYPTO_SUCCESS && nonce_length) err = RANDOM_BYTES(nonce, nonce_length);
    if (err == CRYPTO_SUCCESS)
        err = CTR_DRBG_INSTANTIATE(CONTEXT, ALG, entropy, use_df ? security_bytes : seed_length,
                                   nonce_length ? nonce : NULL, nonce_length,
                                   PERSONALIZATION, PERSONALIZATION_LENGTH);
    crypto_zeroize(entropy, sizeof(entropy));
    crypto_zeroize(nonce, sizeof(nonce));
    return err;
}

CryptoError CTR_DRBG_RESEED_OS(CTR_DRBG_CONTEXT *CONTEXT,
                               const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH) {
    size_t security_bytes, seed_length;
    uint8_t entropy[CTR_DRBG_MAX_SEED_BYTES];
    CryptoError err;

    if (!CONTEXT || !CONTEXT->INSTANTIATED || (!ADDITIONAL && ADDITIONAL_LENGTH))
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ctr_drbg_parameters(CONTEXT->ALG, NULL, NULL, &security_bytes, NULL);
    if (err != CRYPTO_SUCCESS) return err;
    seed_length = (size_t)CONTEXT->KEY_LENGTH + 16u;
    err = RANDOM_BYTES(entropy, CONTEXT->USE_DF ? security_bytes : seed_length);
    if (err == CRYPTO_SUCCESS)
        err = CTR_DRBG_RESEED(CONTEXT, entropy, CONTEXT->USE_DF ? security_bytes : seed_length,
                              ADDITIONAL, ADDITIONAL_LENGTH);
    crypto_zeroize(entropy, sizeof(entropy));
    return err;
}

CryptoError CTR_DRBG_GENERATE(CTR_DRBG_CONTEXT *CONTEXT,
                              uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
                              const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH,
                              int PREDICTION_RESISTANCE) {
    AES_CONTEXT aes;
    AlgID aes_alg;
    uint8_t provided[CTR_DRBG_MAX_SEED_BYTES], block[16];
    size_t offset = 0u, copy_length;
    CryptoError err;

    if (!CONTEXT || !CONTEXT->INSTANTIATED || (!OUTPUT && OUTPUT_LENGTH) ||
        (!ADDITIONAL && ADDITIONAL_LENGTH)) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (OUTPUT_LENGTH > CTR_DRBG_MAX_REQUEST_BYTES) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    if (CONTEXT->RESEED_COUNTER > ((uint64_t)1u << 48)) return CRYPTO_ERROR_RESEED_REQUIRED;

    if (PREDICTION_RESISTANCE) {
        err = CTR_DRBG_RESEED_OS(CONTEXT, ADDITIONAL, ADDITIONAL_LENGTH);
        if (err != CRYPTO_SUCCESS) return err;
        ADDITIONAL = NULL;
        ADDITIONAL_LENGTH = 0u;
    }
    err = prepare_additional(CONTEXT, ADDITIONAL, ADDITIONAL_LENGTH, provided);
    if (err != CRYPTO_SUCCESS) return err;
    if (ADDITIONAL_LENGTH) {
        err = ctr_drbg_update(CONTEXT, provided);
        if (err != CRYPTO_SUCCESS) goto done;
    }
    err = ctr_drbg_parameters(CONTEXT->ALG, &aes_alg, NULL, NULL, NULL);
    if (err != CRYPTO_SUCCESS) goto done;
    err = AES_CONTEXT_INIT(&aes, aes_alg, CONTEXT->KEY, CONTEXT->KEY_LENGTH);
    if (err != CRYPTO_SUCCESS) goto done;
    while (offset < OUTPUT_LENGTH) {
        increment_v(CONTEXT->V);
        err = AES_ENCRYPT_BLOCK(&aes, CONTEXT->V, block);
        if (err != CRYPTO_SUCCESS) break;
        copy_length = OUTPUT_LENGTH - offset;
        if (copy_length > 16u) copy_length = 16u;
        memcpy(OUTPUT + offset, block, copy_length);
        offset += copy_length;
    }
    AES_CONTEXT_CLEAR(&aes);
    if (err != CRYPTO_SUCCESS) goto done;
    err = ctr_drbg_update(CONTEXT, provided);
    if (err == CRYPTO_SUCCESS) ++CONTEXT->RESEED_COUNTER;

done:
    if (err != CRYPTO_SUCCESS && OUTPUT && OUTPUT_LENGTH) crypto_zeroize(OUTPUT, OUTPUT_LENGTH);
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(provided, sizeof(provided));
    return err;
}

void CTR_DRBG_CLEAR(CTR_DRBG_CONTEXT *CONTEXT) {
    if (CONTEXT) crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
}
