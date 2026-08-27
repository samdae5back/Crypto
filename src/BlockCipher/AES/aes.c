/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "BlockCipher/AES/aes_internal.h"
#include "Util/Core/secure_zero.h"

#include <string.h>

static uint8_t aes_xtime(uint8_t x) {
    uint8_t hi = (uint8_t)(x >> 7);
    return (uint8_t)((uint8_t)(x << 1) ^
                     (uint8_t)(0x1bu & (uint8_t)(0u - hi)));
}

static uint8_t aes_gmul(uint8_t a, uint8_t b) {
    uint8_t result = 0u;
    size_t i;

    for (i = 0u; i < 8u; ++i) {
        uint8_t mask = (uint8_t)(0u - (uint8_t)(b & 1u));
        result ^= (uint8_t)(a & mask);
        a = aes_xtime(a);
        b = (uint8_t)(b >> 1);
    }
    return result;
}

static uint8_t aes_rotl8(uint8_t x, uint8_t n) {
    return (uint8_t)(((uint16_t)x << n) | ((uint16_t)x >> (8u - n)));
}

static uint8_t aes_gf_inv(uint8_t x) {
    uint8_t x2 = aes_gmul(x, x);
    uint8_t x4 = aes_gmul(x2, x2);
    uint8_t x8 = aes_gmul(x4, x4);
    uint8_t x16 = aes_gmul(x8, x8);
    uint8_t x32 = aes_gmul(x16, x16);
    uint8_t x64 = aes_gmul(x32, x32);
    uint8_t x128 = aes_gmul(x64, x64);
    uint8_t result = aes_gmul(x2, x4);

    result = aes_gmul(result, x8);
    result = aes_gmul(result, x16);
    result = aes_gmul(result, x32);
    result = aes_gmul(result, x64);
    result = aes_gmul(result, x128);
    return result;
}

/* Fixed-operation algebraic S-box: no secret-indexed S-box/T-table loads. */
static uint8_t aes_sbox(uint8_t x) {
    uint8_t y = aes_gf_inv(x);
    return (uint8_t)(y ^ aes_rotl8(y, 1u) ^ aes_rotl8(y, 2u) ^
                     aes_rotl8(y, 3u) ^ aes_rotl8(y, 4u) ^ 0x63u);
}

static uint8_t aes_inv_sbox(uint8_t x) {
    uint8_t y = (uint8_t)(aes_rotl8(x, 1u) ^ aes_rotl8(x, 3u) ^
                          aes_rotl8(x, 6u) ^ 0x05u);
    return aes_gf_inv(y);
}

static void add_round_key(uint8_t state[AES_BLOCK_SIZE],
                          const uint8_t *round_key) {
    size_t i;
    for (i = 0u; i < AES_BLOCK_SIZE; ++i) state[i] ^= round_key[i];
}

static void sub_bytes(uint8_t state[AES_BLOCK_SIZE]) {
    size_t i;
    for (i = 0u; i < AES_BLOCK_SIZE; ++i) state[i] = aes_sbox(state[i]);
}

static void inv_sub_bytes(uint8_t state[AES_BLOCK_SIZE]) {
    size_t i;
    for (i = 0u; i < AES_BLOCK_SIZE; ++i) state[i] = aes_inv_sbox(state[i]);
}

static void shift_rows(uint8_t state[AES_BLOCK_SIZE]) {
    uint8_t temp[AES_BLOCK_SIZE];

    temp[0] = state[0];   temp[4] = state[4];
    temp[8] = state[8];   temp[12] = state[12];
    temp[1] = state[5];   temp[5] = state[9];
    temp[9] = state[13];  temp[13] = state[1];
    temp[2] = state[10];  temp[6] = state[14];
    temp[10] = state[2];  temp[14] = state[6];
    temp[3] = state[15];  temp[7] = state[3];
    temp[11] = state[7];  temp[15] = state[11];
    memcpy(state, temp, sizeof(temp));
    crypto_zeroize(temp, sizeof(temp));
}

static void inv_shift_rows(uint8_t state[AES_BLOCK_SIZE]) {
    uint8_t temp[AES_BLOCK_SIZE];

    temp[0] = state[0];   temp[4] = state[4];
    temp[8] = state[8];   temp[12] = state[12];
    temp[1] = state[13];  temp[5] = state[1];
    temp[9] = state[5];   temp[13] = state[9];
    temp[2] = state[10];  temp[6] = state[14];
    temp[10] = state[2];  temp[14] = state[6];
    temp[3] = state[7];   temp[7] = state[11];
    temp[11] = state[15]; temp[15] = state[3];
    memcpy(state, temp, sizeof(temp));
    crypto_zeroize(temp, sizeof(temp));
}

static void mix_columns(uint8_t state[AES_BLOCK_SIZE]) {
    size_t column;

    for (column = 0u; column < 4u; ++column) {
        size_t i = column * 4u;
        uint8_t a0 = state[i];
        uint8_t a1 = state[i + 1u];
        uint8_t a2 = state[i + 2u];
        uint8_t a3 = state[i + 3u];
        uint8_t x0 = aes_xtime(a0);
        uint8_t x1 = aes_xtime(a1);
        uint8_t x2 = aes_xtime(a2);
        uint8_t x3 = aes_xtime(a3);

        state[i] = (uint8_t)(x0 ^ (uint8_t)(x1 ^ a1) ^ a2 ^ a3);
        state[i + 1u] = (uint8_t)(a0 ^ x1 ^ (uint8_t)(x2 ^ a2) ^ a3);
        state[i + 2u] = (uint8_t)(a0 ^ a1 ^ x2 ^ (uint8_t)(x3 ^ a3));
        state[i + 3u] = (uint8_t)((uint8_t)(x0 ^ a0) ^ a1 ^ a2 ^ x3);
    }
}

static void inv_mix_columns(uint8_t state[AES_BLOCK_SIZE]) {
    size_t column;

    for (column = 0u; column < 4u; ++column) {
        size_t i = column * 4u;
        uint8_t a0 = state[i];
        uint8_t a1 = state[i + 1u];
        uint8_t a2 = state[i + 2u];
        uint8_t a3 = state[i + 3u];

        state[i] = (uint8_t)(aes_gmul(a0, 14u) ^ aes_gmul(a1, 11u) ^
                             aes_gmul(a2, 13u) ^ aes_gmul(a3, 9u));
        state[i + 1u] = (uint8_t)(aes_gmul(a0, 9u) ^ aes_gmul(a1, 14u) ^
                                  aes_gmul(a2, 11u) ^ aes_gmul(a3, 13u));
        state[i + 2u] = (uint8_t)(aes_gmul(a0, 13u) ^ aes_gmul(a1, 9u) ^
                                  aes_gmul(a2, 14u) ^ aes_gmul(a3, 11u));
        state[i + 3u] = (uint8_t)(aes_gmul(a0, 11u) ^ aes_gmul(a1, 13u) ^
                                  aes_gmul(a2, 9u) ^ aes_gmul(a3, 14u));
    }
}

static CryptoError aes_key_parameters(size_t key_length,
                                      uint8_t *key_words, uint8_t *rounds) {
    switch (key_length) {
        case 16u:
            *key_words = 4u;
            *rounds = 10u;
            return CRYPTO_SUCCESS;
        case 24u:
            *key_words = 6u;
            *rounds = 12u;
            return CRYPTO_SUCCESS;
        case 32u:
            *key_words = 8u;
            *rounds = 14u;
            return CRYPTO_SUCCESS;
        default:
            return CRYPTO_ERROR_INVALID_KEY;
    }
}

CryptoError crypto_aes_context_init(AES_CONTEXT *CONTEXT,
                                     const uint8_t *KEY, size_t KEY_LENGTH) {
    size_t bytes_generated;
    size_t total_bytes;
    size_t i;
    uint8_t key_words = 0u;
    uint8_t rounds = 0u;
    uint8_t rcon = 1u;
    uint8_t temp[4] = {0u, 0u, 0u, 0u};
    CryptoError err;

    if (!CONTEXT) return CRYPTO_ERROR_INVALID_ARGUMENT;
    crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
    if (!KEY) return CRYPTO_ERROR_INVALID_ARGUMENT;

    err = aes_key_parameters(KEY_LENGTH, &key_words, &rounds);
    if (err != CRYPTO_SUCCESS) return err;

    memcpy(CONTEXT->ROUND_KEYS, KEY, KEY_LENGTH);
    CONTEXT->ROUNDS = rounds;
    CONTEXT->KEY_WORDS = key_words;
    bytes_generated = KEY_LENGTH;
    total_bytes = AES_BLOCK_SIZE * ((size_t)rounds + 1u);

    while (bytes_generated < total_bytes) {
        for (i = 0u; i < 4u; ++i) {
            temp[i] = CONTEXT->ROUND_KEYS[bytes_generated - 4u + i];
        }
        if ((bytes_generated % KEY_LENGTH) == 0u) {
            uint8_t x = temp[0];
            temp[0] = aes_sbox(temp[1]);
            temp[1] = aes_sbox(temp[2]);
            temp[2] = aes_sbox(temp[3]);
            temp[3] = aes_sbox(x);
            temp[0] ^= rcon;
            rcon = aes_xtime(rcon);
        } else if (KEY_LENGTH == 32u &&
                   (bytes_generated % KEY_LENGTH) == 16u) {
            for (i = 0u; i < 4u; ++i) temp[i] = aes_sbox(temp[i]);
        }
        for (i = 0u; i < 4u && bytes_generated < total_bytes; ++i) {
            CONTEXT->ROUND_KEYS[bytes_generated] =
                (uint8_t)(CONTEXT->ROUND_KEYS[bytes_generated - KEY_LENGTH] ^
                          temp[i]);
            ++bytes_generated;
        }
    }

    crypto_zeroize(temp, sizeof(temp));
    return CRYPTO_SUCCESS;
}

void crypto_aes_context_clear(AES_CONTEXT *CONTEXT) {
    if (CONTEXT) crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
}

static int aes_context_valid(const AES_CONTEXT *context) {
    if (!context) return 0;
    return (context->ROUNDS == 10u && context->KEY_WORDS == 4u) ||
           (context->ROUNDS == 12u && context->KEY_WORDS == 6u) ||
           (context->ROUNDS == 14u && context->KEY_WORDS == 8u);
}

CryptoError crypto_aes_encrypt_block(const AES_CONTEXT *CONTEXT,
                                      const uint8_t INPUT[AES_BLOCK_SIZE],
                                      uint8_t OUTPUT[AES_BLOCK_SIZE]) {
    uint8_t state[AES_BLOCK_SIZE];
    uint8_t round;

    if (!aes_context_valid(CONTEXT) || !INPUT || !OUTPUT)
        return CRYPTO_ERROR_INVALID_ARGUMENT;

    memcpy(state, INPUT, sizeof(state));
    add_round_key(state, CONTEXT->ROUND_KEYS);
    for (round = 1u; round < CONTEXT->ROUNDS; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state,
                      CONTEXT->ROUND_KEYS + AES_BLOCK_SIZE * (size_t)round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state,
                  CONTEXT->ROUND_KEYS +
                  AES_BLOCK_SIZE * (size_t)CONTEXT->ROUNDS);
    memcpy(OUTPUT, state, sizeof(state));
    crypto_zeroize(state, sizeof(state));
    return CRYPTO_SUCCESS;
}

CryptoError crypto_aes_decrypt_block(const AES_CONTEXT *CONTEXT,
                                      const uint8_t INPUT[AES_BLOCK_SIZE],
                                      uint8_t OUTPUT[AES_BLOCK_SIZE]) {
    uint8_t state[AES_BLOCK_SIZE];
    uint8_t round;

    if (!aes_context_valid(CONTEXT) || !INPUT || !OUTPUT)
        return CRYPTO_ERROR_INVALID_ARGUMENT;

    memcpy(state, INPUT, sizeof(state));
    add_round_key(state,
                  CONTEXT->ROUND_KEYS +
                  AES_BLOCK_SIZE * (size_t)CONTEXT->ROUNDS);
    for (round = CONTEXT->ROUNDS; round > 1u; --round) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state,
                      CONTEXT->ROUND_KEYS +
                      AES_BLOCK_SIZE * (size_t)(round - 1u));
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, CONTEXT->ROUND_KEYS);
    memcpy(OUTPUT, state, sizeof(state));
    crypto_zeroize(state, sizeof(state));
    return CRYPTO_SUCCESS;
}

static CryptoError aes_ecb_encrypt(const AES_CONTEXT *context,
                                   uint8_t *output,
                                   const uint8_t *input, size_t input_length) {
    CryptoError err = CRYPTO_SUCCESS;
    size_t offset;

    for (offset = 0u; offset < input_length; offset += AES_BLOCK_SIZE) {
        err = crypto_aes_encrypt_block(context, input + offset, output + offset);
        if (err != CRYPTO_SUCCESS) break;
    }
    return err;
}

static CryptoError aes_ecb_decrypt(const AES_CONTEXT *context,
                                   uint8_t *output,
                                   const uint8_t *input, size_t input_length) {
    CryptoError err = CRYPTO_SUCCESS;
    size_t offset;

    for (offset = 0u; offset < input_length; offset += AES_BLOCK_SIZE) {
        err = crypto_aes_decrypt_block(context, input + offset, output + offset);
        if (err != CRYPTO_SUCCESS) break;
    }
    return err;
}

static CryptoError aes_cbc_encrypt(const AES_CONTEXT *context,
                                   uint8_t *output, const uint8_t *input,
                                   size_t input_length, const uint8_t iv[16]) {
    uint8_t chain[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    CryptoError err = CRYPTO_SUCCESS;
    size_t offset;
    size_t i;

    memcpy(chain, iv, sizeof(chain));
    for (offset = 0u; offset < input_length; offset += AES_BLOCK_SIZE) {
        for (i = 0u; i < AES_BLOCK_SIZE; ++i) {
            block[i] = (uint8_t)(input[offset + i] ^ chain[i]);
        }
        err = crypto_aes_encrypt_block(context, block, output + offset);
        if (err != CRYPTO_SUCCESS) break;
        memcpy(chain, output + offset, sizeof(chain));
    }

    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(chain, sizeof(chain));
    return err;
}

static CryptoError aes_cbc_decrypt(const AES_CONTEXT *context,
                                   uint8_t *output, const uint8_t *input,
                                   size_t input_length, const uint8_t iv[16]) {
    uint8_t chain[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    uint8_t cipher_block[AES_BLOCK_SIZE];
    CryptoError err = CRYPTO_SUCCESS;
    size_t offset;
    size_t i;

    memcpy(chain, iv, sizeof(chain));
    for (offset = 0u; offset < input_length; offset += AES_BLOCK_SIZE) {
        memcpy(cipher_block, input + offset, sizeof(cipher_block));
        err = crypto_aes_decrypt_block(context, cipher_block, block);
        if (err != CRYPTO_SUCCESS) break;
        for (i = 0u; i < AES_BLOCK_SIZE; ++i) {
            output[offset + i] = (uint8_t)(block[i] ^ chain[i]);
        }
        memcpy(chain, cipher_block, sizeof(chain));
    }

    crypto_zeroize(cipher_block, sizeof(cipher_block));
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(chain, sizeof(chain));
    return err;
}

static void increment_counter128(uint8_t counter[AES_BLOCK_SIZE]) {
    int i;
    for (i = (int)AES_BLOCK_SIZE - 1; i >= 0; --i) {
        counter[i] = (uint8_t)(counter[i] + 1u);
        if (counter[i] != 0u) break;
    }
}

static CryptoError aes_ctr_crypt(const AES_CONTEXT *context,
                                 uint8_t *output, const uint8_t *input,
                                 size_t input_length,
                                 const uint8_t initial_counter[16]) {
    uint8_t counter[AES_BLOCK_SIZE];
    uint8_t stream[AES_BLOCK_SIZE];
    CryptoError err = CRYPTO_SUCCESS;
    size_t offset = 0u;
    size_t chunk;
    size_t i;

    memcpy(counter, initial_counter, sizeof(counter));
    while (offset < input_length) {
        err = crypto_aes_encrypt_block(context, counter, stream);
        if (err != CRYPTO_SUCCESS) break;
        chunk = input_length - offset;
        if (chunk > AES_BLOCK_SIZE) chunk = AES_BLOCK_SIZE;
        for (i = 0u; i < chunk; ++i) {
            output[offset + i] = (uint8_t)(input[offset + i] ^ stream[i]);
        }
        offset += chunk;
        increment_counter128(counter);
    }

    crypto_zeroize(stream, sizeof(stream));
    crypto_zeroize(counter, sizeof(counter));
    return err;
}

static CryptoError aes_validate_request(
    const uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    size_t expected_key_length, CryptoAesMode mode) {
    if (!KEY || (!INPUT && INPUT_LENGTH != 0u) ||
        (!OUTPUT && INPUT_LENGTH != 0u) || (!AAD && AAD_LENGTH != 0u)) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (KEY_LENGTH != expected_key_length) return CRYPTO_ERROR_INVALID_KEY;
    if (expected_key_length != 16u && expected_key_length != 24u &&
        expected_key_length != 32u) {
        return CRYPTO_ERROR_INVALID_KEY;
    }
    switch (mode) {
        case CRYPTO_AES_MODE_ECB:
            if (IV_LENGTH != 0u || AAD_LENGTH != 0u || TAG_LENGTH != 0u ||
                (INPUT_LENGTH % AES_BLOCK_SIZE) != 0u) {
                return CRYPTO_ERROR_INVALID_ARGUMENT;
            }
            break;
        case CRYPTO_AES_MODE_CBC:
            if (!IV || IV_LENGTH != AES_BLOCK_SIZE || AAD_LENGTH != 0u ||
                TAG_LENGTH != 0u ||
                (INPUT_LENGTH % AES_BLOCK_SIZE) != 0u) {
                return CRYPTO_ERROR_INVALID_ARGUMENT;
            }
            break;
        case CRYPTO_AES_MODE_CTR:
            if (!IV || IV_LENGTH != AES_BLOCK_SIZE || AAD_LENGTH != 0u ||
                TAG_LENGTH != 0u) {
                return CRYPTO_ERROR_INVALID_ARGUMENT;
            }
            break;
        case CRYPTO_AES_MODE_CCM:
            if (!IV || IV_LENGTH < 7u || IV_LENGTH > 13u || !TAG)
                return CRYPTO_ERROR_INVALID_ARGUMENT;
            break;
        case CRYPTO_AES_MODE_GCM:
            if (!IV || IV_LENGTH == 0u || !TAG)
                return CRYPTO_ERROR_INVALID_ARGUMENT;
            break;
        default:
            return CRYPTO_ERROR_INVALID_ALG_ID;
    }
    if (OUTPUT_CAPACITY < INPUT_LENGTH) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    return CRYPTO_SUCCESS;
}

CryptoError crypto_aes_encrypt(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    size_t EXPECTED_KEY_LENGTH, CryptoAesMode MODE) {
    AES_CONTEXT context;
    CryptoError err;

    err = aes_validate_request(OUTPUT, OUTPUT_CAPACITY, TAG, TAG_LENGTH,
                               INPUT, INPUT_LENGTH, KEY, KEY_LENGTH,
                               IV, IV_LENGTH, AAD, AAD_LENGTH,
                               EXPECTED_KEY_LENGTH, MODE);
    if (err != CRYPTO_SUCCESS) return err;

    err = crypto_aes_context_init(&context, KEY, KEY_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;

    switch (MODE) {
        case CRYPTO_AES_MODE_ECB:
            err = aes_ecb_encrypt(&context, OUTPUT, INPUT, INPUT_LENGTH);
            break;
        case CRYPTO_AES_MODE_CBC:
            err = aes_cbc_encrypt(&context, OUTPUT, INPUT, INPUT_LENGTH, IV);
            break;
        case CRYPTO_AES_MODE_CTR:
            err = aes_ctr_crypt(&context, OUTPUT, INPUT, INPUT_LENGTH, IV);
            break;
        case CRYPTO_AES_MODE_CCM:
            err = crypto_aes_ccm_encrypt(&context, OUTPUT, TAG, TAG_LENGTH,
                                         INPUT, INPUT_LENGTH, IV, IV_LENGTH,
                                         AAD, AAD_LENGTH);
            break;
        case CRYPTO_AES_MODE_GCM:
            err = crypto_aes_gcm_encrypt(&context, OUTPUT, TAG, TAG_LENGTH,
                                         INPUT, INPUT_LENGTH, IV, IV_LENGTH,
                                         AAD, AAD_LENGTH);
            break;
        default:
            err = CRYPTO_ERROR_INVALID_ALG_ID;
            break;
    }

    crypto_aes_context_clear(&context);
    return err;
}

CryptoError crypto_aes_decrypt(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    size_t EXPECTED_KEY_LENGTH, CryptoAesMode MODE) {
    AES_CONTEXT context;
    CryptoError err;

    err = aes_validate_request(OUTPUT, OUTPUT_CAPACITY, TAG, TAG_LENGTH,
                               INPUT, INPUT_LENGTH, KEY, KEY_LENGTH,
                               IV, IV_LENGTH, AAD, AAD_LENGTH,
                               EXPECTED_KEY_LENGTH, MODE);
    if (err != CRYPTO_SUCCESS) return err;

    err = crypto_aes_context_init(&context, KEY, KEY_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;

    switch (MODE) {
        case CRYPTO_AES_MODE_ECB:
            err = aes_ecb_decrypt(&context, OUTPUT, INPUT, INPUT_LENGTH);
            break;
        case CRYPTO_AES_MODE_CBC:
            err = aes_cbc_decrypt(&context, OUTPUT, INPUT, INPUT_LENGTH, IV);
            break;
        case CRYPTO_AES_MODE_CTR:
            err = aes_ctr_crypt(&context, OUTPUT, INPUT, INPUT_LENGTH, IV);
            break;
        case CRYPTO_AES_MODE_CCM:
            err = crypto_aes_ccm_decrypt(&context, OUTPUT, TAG, TAG_LENGTH,
                                         INPUT, INPUT_LENGTH, IV, IV_LENGTH,
                                         AAD, AAD_LENGTH);
            break;
        case CRYPTO_AES_MODE_GCM:
            err = crypto_aes_gcm_decrypt(&context, OUTPUT, TAG, TAG_LENGTH,
                                         INPUT, INPUT_LENGTH, IV, IV_LENGTH,
                                         AAD, AAD_LENGTH);
            break;
        default:
            err = CRYPTO_ERROR_INVALID_ALG_ID;
            break;
    }

    crypto_aes_context_clear(&context);
    return err;
}
