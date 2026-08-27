#include "ctr_drbg_internal.h"
#include "BlockCipher/AES/aes_internal.h"
#include "RandomNumberGeneration/Noise/random_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/Endian/endian_internal.h"

#include <stdlib.h>
#include <string.h>

static CryptoError ctr_drbg_parameters(AlgID alg, size_t *key_length,
                                       size_t *security_bytes, int *use_df) {
    switch (alg) {
        case ALG_CTR_DRBG_AES_128_DF:
        case ALG_CTR_DRBG_AES_128_NO_DF:
            if (key_length) *key_length = CRYPTO_AES_128_KEY_BYTES;
            if (security_bytes) *security_bytes = CRYPTO_AES_128_KEY_BYTES;
            if (use_df) *use_df = (alg == ALG_CTR_DRBG_AES_128_DF);
            return CRYPTO_SUCCESS;
        case ALG_CTR_DRBG_AES_192_DF:
        case ALG_CTR_DRBG_AES_192_NO_DF:
            if (key_length) *key_length = CRYPTO_AES_192_KEY_BYTES;
            if (security_bytes) *security_bytes = CRYPTO_AES_192_KEY_BYTES;
            if (use_df) *use_df = (alg == ALG_CTR_DRBG_AES_192_DF);
            return CRYPTO_SUCCESS;
        case ALG_CTR_DRBG_AES_256_DF:
        case ALG_CTR_DRBG_AES_256_NO_DF:
            if (key_length) *key_length = CRYPTO_AES_256_KEY_BYTES;
            if (security_bytes) *security_bytes = CRYPTO_AES_256_KEY_BYTES;
            if (use_df) *use_df = (alg == ALG_CTR_DRBG_AES_256_DF);
            return CRYPTO_SUCCESS;
        default:
            return CRYPTO_ERROR_INVALID_ALG_ID;
    }
}

size_t crypto_ctr_drbg_seed_size_internal(AlgID ALG) {
    size_t key_length = 0u;
    if (ctr_drbg_parameters(ALG, &key_length, NULL, NULL) != CRYPTO_SUCCESS) return 0u;
    return key_length + CRYPTO_CTR_DRBG_BLOCK_BYTES;
}

/* V is secret DRBG state: always walk all 16 bytes instead of stopping at the first non-carry byte. */
static void increment_v(uint8_t v[16]) {
    uint16_t carry = 1u;
    int i;
    for (i = 15; i >= 0; --i) {
        uint16_t sum = (uint16_t)v[i] + carry;
        v[i] = (uint8_t)sum;
        carry = (uint16_t)(sum >> 8);
    }
}

static CryptoError bcc(const AES_CONTEXT *ctx, const uint8_t iv[16],
                       const uint8_t *s, size_t s_length, uint8_t out[16]) {
    uint8_t chain[16] = {0}, x[16];
    size_t offset, i;
    CryptoError err;

    for (i = 0u; i < 16u; ++i) x[i] = (uint8_t)(chain[i] ^ iv[i]);
    err = crypto_aes_encrypt_block(ctx, x, chain);
    if (err != CRYPTO_SUCCESS) goto done;
    for (offset = 0u; offset < s_length; offset += 16u) {
        for (i = 0u; i < 16u; ++i) x[i] = (uint8_t)(chain[i] ^ s[offset + i]);
        err = crypto_aes_encrypt_block(ctx, x, chain);
        if (err != CRYPTO_SUCCESS) goto done;
    }
    memcpy(out, chain, 16u);

done:
    crypto_zeroize(x, sizeof(x));
    crypto_zeroize(chain, sizeof(chain));
    return err;
}

static CryptoError block_cipher_df(size_t key_length,
                                   const uint8_t *input, size_t input_length,
                                   uint8_t *output, size_t output_length) {
    AES_CONTEXT ctx;
    uint8_t initial_key[32], temp[48], iv[16], block[16], x[16];
    uint8_t *s = NULL;
    size_t s_length, used = 0u, generated = 0u, i;
    uint32_t counter = 0u;
    const size_t uint32_max = (size_t)((uint32_t)~(uint32_t)0u);
    CryptoError err = CRYPTO_SUCCESS;

    if ((!input && input_length) || !output || output_length == 0u || output_length > CRYPTO_CTR_DRBG_MAX_SEED_BYTES)
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (input_length > uint32_max || output_length > uint32_max)
        return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    if (input_length > ((size_t)-1) - 9u) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    s_length = 8u + input_length + 1u;
    if (s_length > ((size_t)-1) - 15u) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    s_length = (s_length + 15u) & ~(size_t)15u;
    s = (uint8_t *)calloc(1u, s_length);
    if (!s) return CRYPTO_ERROR_ALLOCATION_FAILED;

    /* SP 800-90A Block_Cipher_df encodes L and N as byte counts in 32-bit big-endian integers. */
    crypto_store32_be(s, (uint32_t)input_length);
    crypto_store32_be(s + 4u, (uint32_t)output_length);
    if (input_length) memcpy(s + 8u, input, input_length);
    s[8u + input_length] = 0x80u;
    for (i = 0u; i < key_length; ++i) initial_key[i] = (uint8_t)i;

    err = crypto_aes_context_init(&ctx, initial_key, key_length);
    if (err != CRYPTO_SUCCESS) goto done;
    while (used < key_length + 16u) {
        size_t copy_length;
        memset(iv, 0, sizeof(iv));
        crypto_store32_be(iv, counter++);
        err = bcc(&ctx, iv, s, s_length, block);
        if (err != CRYPTO_SUCCESS) goto clear_ctx;
        copy_length = key_length + 16u - used;
        if (copy_length > 16u) copy_length = 16u;
        memcpy(temp + used, block, copy_length);
        used += copy_length;
    }
    crypto_aes_context_clear(&ctx);

    memcpy(x, temp + key_length, 16u);
    err = crypto_aes_context_init(&ctx, temp, key_length);
    if (err != CRYPTO_SUCCESS) goto done;
    while (generated < output_length) {
        size_t copy_length;
        err = crypto_aes_encrypt_block(&ctx, x, x);
        if (err != CRYPTO_SUCCESS) goto clear_ctx;
        copy_length = output_length - generated;
        if (copy_length > 16u) copy_length = 16u;
        memcpy(output + generated, x, copy_length);
        generated += copy_length;
    }

clear_ctx:
    crypto_aes_context_clear(&ctx);

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

static CryptoError ctr_drbg_update(CRYPTO_CTR_DRBG_CONTEXT *ctx, const uint8_t *provided_data) {
    AES_CONTEXT aes;
    uint8_t temp[CRYPTO_CTR_DRBG_MAX_SEED_BYTES], block[16];
    size_t seed_length = (size_t)ctx->KEY_LENGTH + 16u;
    size_t used = 0u, copy_length, i;
    CryptoError err;

    err = ctr_drbg_parameters(ctx->ALG, NULL, NULL, NULL);
    if (err != CRYPTO_SUCCESS) return err;
    err = crypto_aes_context_init(&aes, ctx->KEY, ctx->KEY_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    while (used < seed_length) {
        increment_v(ctx->V);
        err = crypto_aes_encrypt_block(&aes, ctx->V, block);
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
    crypto_aes_context_clear(&aes);
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(temp, sizeof(temp));
    return err;
}

static CryptoError make_df_seed(CRYPTO_CTR_DRBG_CONTEXT *ctx,
                                const uint8_t *a, size_t a_length,
                                const uint8_t *b, size_t b_length,
                                const uint8_t *c, size_t c_length,
                                uint8_t seed[CRYPTO_CTR_DRBG_MAX_SEED_BYTES]) {
    size_t seed_length = (size_t)ctx->KEY_LENGTH + 16u;
    size_t total;
    uint8_t *joined = NULL;
    const size_t uint32_max = (size_t)((uint32_t)~(uint32_t)0u);
    CryptoError err;

    if (a_length > (size_t)-1 - b_length || a_length + b_length > (size_t)-1 - c_length)
        return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    total = a_length + b_length + c_length;
    if (total > uint32_max) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    if (total) {
        joined = (uint8_t *)malloc(total);
        if (!joined) return CRYPTO_ERROR_ALLOCATION_FAILED;
        if (a_length) memcpy(joined, a, a_length);
        if (b_length) memcpy(joined + a_length, b, b_length);
        if (c_length) memcpy(joined + a_length + b_length, c, c_length);
    }
    err = ctr_drbg_parameters(ctx->ALG, NULL, NULL, NULL);
    if (err == CRYPTO_SUCCESS)
        err = block_cipher_df(ctx->KEY_LENGTH, joined, total, seed, seed_length);
    if (joined) {
        crypto_zeroize(joined, total);
        free(joined);
    }
    return err;
}

static CryptoError prepare_additional(CRYPTO_CTR_DRBG_CONTEXT *ctx, const uint8_t *additional,
                                      size_t additional_length,
                                      uint8_t seed[CRYPTO_CTR_DRBG_MAX_SEED_BYTES]) {
    size_t seed_length = (size_t)ctx->KEY_LENGTH + 16u;
    if (!additional && additional_length) return CRYPTO_ERROR_INVALID_ARGUMENT;
    crypto_zeroize(seed, CRYPTO_CTR_DRBG_MAX_SEED_BYTES);
    if (additional_length == 0u) return CRYPTO_SUCCESS;
    if (ctx->USE_DF)
        return make_df_seed(ctx, additional, additional_length, NULL, 0u, NULL, 0u, seed);
    if (additional_length > seed_length) return CRYPTO_ERROR_INVALID_ARGUMENT;
    memcpy(seed, additional, additional_length);
    return CRYPTO_SUCCESS;
}

CryptoError crypto_ctr_drbg_instantiate_internal(CRYPTO_CTR_DRBG_CONTEXT *CONTEXT, AlgID ALG,
                                 const uint8_t *ENTROPY, size_t ENTROPY_LENGTH,
                                 const uint8_t *NONCE, size_t NONCE_LENGTH,
                                 const uint8_t *PERSONALIZATION, size_t PERSONALIZATION_LENGTH) {
    size_t key_length, security_bytes, seed_length, i;
    int use_df;
    uint8_t seed[CRYPTO_CTR_DRBG_MAX_SEED_BYTES];
    CryptoError err;

    if (!CONTEXT || !ENTROPY || (!NONCE && NONCE_LENGTH) || (!PERSONALIZATION && PERSONALIZATION_LENGTH))
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ctr_drbg_parameters(ALG, &key_length, &security_bytes, &use_df);
    if (err != CRYPTO_SUCCESS) return err;
    seed_length = key_length + 16u;
    crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
    CONTEXT->ALG = ALG;
    CONTEXT->KEY_LENGTH = (uint8_t)key_length;
    CONTEXT->USE_DF = (uint8_t)(use_df != 0);

    if (use_df) {
        if (ENTROPY_LENGTH < security_bytes ||
            ENTROPY_LENGTH + NONCE_LENGTH < security_bytes + (security_bytes + 1u) / 2u) {
            crypto_ctr_drbg_clear_internal(CONTEXT);
            return CRYPTO_ERROR_INVALID_ARGUMENT;
        }
        err = make_df_seed(CONTEXT, ENTROPY, ENTROPY_LENGTH, NONCE, NONCE_LENGTH,
                           PERSONALIZATION, PERSONALIZATION_LENGTH, seed);
    } else {
        if (ENTROPY_LENGTH != seed_length || NONCE_LENGTH != 0u || PERSONALIZATION_LENGTH > seed_length) {
            crypto_ctr_drbg_clear_internal(CONTEXT);
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
        crypto_ctr_drbg_clear_internal(CONTEXT);
    }
    crypto_zeroize(seed, sizeof(seed));
    return err;
}

CryptoError crypto_ctr_drbg_reseed_internal(CRYPTO_CTR_DRBG_CONTEXT *CONTEXT,
                            const uint8_t *ENTROPY, size_t ENTROPY_LENGTH,
                            const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH) {
    size_t security_bytes, seed_length, i;
    uint8_t seed[CRYPTO_CTR_DRBG_MAX_SEED_BYTES];
    CryptoError err;

    if (!CONTEXT || !CONTEXT->INSTANTIATED || !ENTROPY || (!ADDITIONAL && ADDITIONAL_LENGTH))
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ctr_drbg_parameters(CONTEXT->ALG, NULL, &security_bytes, NULL);
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

CryptoError crypto_ctr_drbg_instantiate_os_internal(CRYPTO_CTR_DRBG_CONTEXT *CONTEXT, AlgID ALG,
                                    const uint8_t *PERSONALIZATION, size_t PERSONALIZATION_LENGTH) {
    size_t key_length, security_bytes, seed_length, nonce_length;
    int use_df;
    uint8_t entropy[CRYPTO_CTR_DRBG_MAX_SEED_BYTES], nonce[16];
    CryptoError err;

    if (!CONTEXT || (!PERSONALIZATION && PERSONALIZATION_LENGTH)) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ctr_drbg_parameters(ALG, &key_length, &security_bytes, &use_df);
    if (err != CRYPTO_SUCCESS) return err;
    seed_length = key_length + 16u;
    nonce_length = use_df ? (security_bytes + 1u) / 2u : 0u;
    err = crypto_random_bytes_internal(entropy, use_df ? security_bytes : seed_length);
    if (err == CRYPTO_SUCCESS && nonce_length) err = crypto_random_bytes_internal(nonce, nonce_length);
    if (err == CRYPTO_SUCCESS)
        err = crypto_ctr_drbg_instantiate_internal(CONTEXT, ALG, entropy, use_df ? security_bytes : seed_length,
                                   nonce_length ? nonce : NULL, nonce_length,
                                   PERSONALIZATION, PERSONALIZATION_LENGTH);
    crypto_zeroize(entropy, sizeof(entropy));
    crypto_zeroize(nonce, sizeof(nonce));
    return err;
}

CryptoError crypto_ctr_drbg_reseed_os_internal(CRYPTO_CTR_DRBG_CONTEXT *CONTEXT,
                               const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH) {
    size_t security_bytes, seed_length;
    uint8_t entropy[CRYPTO_CTR_DRBG_MAX_SEED_BYTES];
    CryptoError err;

    if (!CONTEXT || !CONTEXT->INSTANTIATED || (!ADDITIONAL && ADDITIONAL_LENGTH))
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ctr_drbg_parameters(CONTEXT->ALG, NULL, &security_bytes, NULL);
    if (err != CRYPTO_SUCCESS) return err;
    seed_length = (size_t)CONTEXT->KEY_LENGTH + 16u;
    err = crypto_random_bytes_internal(entropy, CONTEXT->USE_DF ? security_bytes : seed_length);
    if (err == CRYPTO_SUCCESS)
        err = crypto_ctr_drbg_reseed_internal(CONTEXT, entropy, CONTEXT->USE_DF ? security_bytes : seed_length,
                              ADDITIONAL, ADDITIONAL_LENGTH);
    crypto_zeroize(entropy, sizeof(entropy));
    return err;
}

CryptoError crypto_ctr_drbg_generate_internal(CRYPTO_CTR_DRBG_CONTEXT *CONTEXT,
                              uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
                              const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH,
                              int PREDICTION_RESISTANCE) {
    AES_CONTEXT aes;
    uint8_t provided[CRYPTO_CTR_DRBG_MAX_SEED_BYTES], block[16];
    size_t offset = 0u, copy_length;
    CryptoError err;

    if (!CONTEXT || !CONTEXT->INSTANTIATED || (!OUTPUT && OUTPUT_LENGTH) ||
        (!ADDITIONAL && ADDITIONAL_LENGTH)) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (OUTPUT_LENGTH > CRYPTO_CTR_DRBG_MAX_REQUEST_BYTES) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;

    if (PREDICTION_RESISTANCE) {
        err = crypto_ctr_drbg_reseed_os_internal(CONTEXT, ADDITIONAL, ADDITIONAL_LENGTH);
        if (err != CRYPTO_SUCCESS) return err;
        ADDITIONAL = NULL;
        ADDITIONAL_LENGTH = 0u;
    }
    if (CONTEXT->RESEED_COUNTER > ((uint64_t)1u << 48)) return CRYPTO_ERROR_RESEED_REQUIRED;

    err = prepare_additional(CONTEXT, ADDITIONAL, ADDITIONAL_LENGTH, provided);
    if (err != CRYPTO_SUCCESS) {
        crypto_zeroize(provided, sizeof(provided));
        crypto_zeroize(block, sizeof(block));
        return err;
    }
    if (ADDITIONAL_LENGTH) {
        err = ctr_drbg_update(CONTEXT, provided);
        if (err != CRYPTO_SUCCESS) goto done;
    }
    err = ctr_drbg_parameters(CONTEXT->ALG, NULL, NULL, NULL);
    if (err != CRYPTO_SUCCESS) goto done;
    err = crypto_aes_context_init(&aes, CONTEXT->KEY, CONTEXT->KEY_LENGTH);
    if (err != CRYPTO_SUCCESS) goto done;
    while (offset < OUTPUT_LENGTH) {
        increment_v(CONTEXT->V);
        err = crypto_aes_encrypt_block(&aes, CONTEXT->V, block);
        if (err != CRYPTO_SUCCESS) break;
        copy_length = OUTPUT_LENGTH - offset;
        if (copy_length > 16u) copy_length = 16u;
        memcpy(OUTPUT + offset, block, copy_length);
        offset += copy_length;
    }
    crypto_aes_context_clear(&aes);
    if (err != CRYPTO_SUCCESS) goto done;
    err = ctr_drbg_update(CONTEXT, provided);
    if (err == CRYPTO_SUCCESS) ++CONTEXT->RESEED_COUNTER;

done:
    if (err != CRYPTO_SUCCESS && OUTPUT && OUTPUT_LENGTH) crypto_zeroize(OUTPUT, OUTPUT_LENGTH);
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(provided, sizeof(provided));
    return err;
}

void crypto_ctr_drbg_clear_internal(CRYPTO_CTR_DRBG_CONTEXT *CONTEXT) {
    if (CONTEXT) crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
}
