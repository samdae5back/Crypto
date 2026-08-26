#include "AES.h"
#include "INTERNAL/secure_zero.h"

#include <string.h>

static uint8_t aes_xtime(uint8_t x) {
    uint8_t hi = (uint8_t)(x >> 7);
    return (uint8_t)((uint8_t)(x << 1) ^ (uint8_t)(0x1bu & (uint8_t)(0u - hi)));
}

static uint8_t aes_gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0u;
    size_t i;
    for (i = 0u; i < 8u; ++i) {
        uint8_t mask = (uint8_t)(0u - (uint8_t)(b & 1u));
        r ^= (uint8_t)(a & mask);
        a = aes_xtime(a);
        b = (uint8_t)(b >> 1);
    }
    return r;
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
    uint8_t y = aes_gmul(x2, x4);
    y = aes_gmul(y, x8);
    y = aes_gmul(y, x16);
    y = aes_gmul(y, x32);
    y = aes_gmul(y, x64);
    y = aes_gmul(y, x128);
    return y;
}

/* Fixed-operation algebraic S-box. No secret-indexed S-box/T-table loads. */
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

static void add_round_key(uint8_t state[16], const uint8_t *round_key) {
    size_t i;
    for (i = 0u; i < 16u; ++i) state[i] ^= round_key[i];
}

static void sub_bytes(uint8_t state[16]) {
    size_t i;
    for (i = 0u; i < 16u; ++i) state[i] = aes_sbox(state[i]);
}

static void inv_sub_bytes(uint8_t state[16]) {
    size_t i;
    for (i = 0u; i < 16u; ++i) state[i] = aes_inv_sbox(state[i]);
}

static void shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    t[0]=s[0];  t[4]=s[4];  t[8]=s[8];   t[12]=s[12];
    t[1]=s[5];  t[5]=s[9];  t[9]=s[13];  t[13]=s[1];
    t[2]=s[10]; t[6]=s[14]; t[10]=s[2];  t[14]=s[6];
    t[3]=s[15]; t[7]=s[3];  t[11]=s[7];  t[15]=s[11];
    memcpy(s, t, sizeof(t));
    crypto_zeroize(t, sizeof(t));
}

static void inv_shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    t[0]=s[0];  t[4]=s[4];  t[8]=s[8];   t[12]=s[12];
    t[1]=s[13]; t[5]=s[1];  t[9]=s[5];   t[13]=s[9];
    t[2]=s[10]; t[6]=s[14]; t[10]=s[2];  t[14]=s[6];
    t[3]=s[7];  t[7]=s[11]; t[11]=s[15]; t[15]=s[3];
    memcpy(s, t, sizeof(t));
    crypto_zeroize(t, sizeof(t));
}

static void mix_columns(uint8_t s[16]) {
    size_t c;
    for (c = 0u; c < 4u; ++c) {
        size_t i = c * 4u;
        uint8_t a0=s[i], a1=s[i+1u], a2=s[i+2u], a3=s[i+3u];
        uint8_t x0 = aes_xtime(a0), x1 = aes_xtime(a1);
        uint8_t x2 = aes_xtime(a2), x3 = aes_xtime(a3);
        s[i]    = (uint8_t)(x0 ^ (uint8_t)(x1 ^ a1) ^ a2 ^ a3);
        s[i+1u] = (uint8_t)(a0 ^ x1 ^ (uint8_t)(x2 ^ a2) ^ a3);
        s[i+2u] = (uint8_t)(a0 ^ a1 ^ x2 ^ (uint8_t)(x3 ^ a3));
        s[i+3u] = (uint8_t)((uint8_t)(x0 ^ a0) ^ a1 ^ a2 ^ x3);
    }
}

static void inv_mix_columns(uint8_t s[16]) {
    size_t c;
    for (c = 0u; c < 4u; ++c) {
        size_t i = c * 4u;
        uint8_t a0=s[i], a1=s[i+1u], a2=s[i+2u], a3=s[i+3u];
        s[i]    = (uint8_t)(aes_gmul(a0,14u)^aes_gmul(a1,11u)^aes_gmul(a2,13u)^aes_gmul(a3,9u));
        s[i+1u] = (uint8_t)(aes_gmul(a0,9u)^aes_gmul(a1,14u)^aes_gmul(a2,11u)^aes_gmul(a3,13u));
        s[i+2u] = (uint8_t)(aes_gmul(a0,13u)^aes_gmul(a1,9u)^aes_gmul(a2,14u)^aes_gmul(a3,11u));
        s[i+3u] = (uint8_t)(aes_gmul(a0,11u)^aes_gmul(a1,13u)^aes_gmul(a2,9u)^aes_gmul(a3,14u));
    }
}

static CryptoError aes_parameters(AlgID alg, size_t *key_length, uint8_t *key_words, uint8_t *rounds) {
    switch (alg) {
        case ALG_AES_128:
            if (key_length) *key_length = 16u;
            if (key_words) *key_words = 4u;
            if (rounds) *rounds = 10u;
            return CRYPTO_SUCCESS;
        case ALG_AES_192:
            if (key_length) *key_length = 24u;
            if (key_words) *key_words = 6u;
            if (rounds) *rounds = 12u;
            return CRYPTO_SUCCESS;
        case ALG_AES_256:
            if (key_length) *key_length = 32u;
            if (key_words) *key_words = 8u;
            if (rounds) *rounds = 14u;
            return CRYPTO_SUCCESS;
        default:
            return CRYPTO_ERROR_INVALID_ALG_ID;
    }
}

size_t CRYPTO_AES_KEY_SIZE(AlgID ALG) {
    size_t key_length = 0u;
    return aes_parameters(ALG, &key_length, NULL, NULL) == CRYPTO_SUCCESS ? key_length : 0u;
}

CryptoError CRYPTO_AES_CONTEXT_INIT(AES_CONTEXT *CONTEXT, AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH) {
    size_t expected = 0u, bytes_generated, total_bytes, i;
    uint8_t key_words = 0u, rounds = 0u, rcon = 1u, temp[4] = {0};
    CryptoError err;

    if (!CONTEXT || !KEY) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = aes_parameters(ALG, &expected, &key_words, &rounds);
    if (err != CRYPTO_SUCCESS) return err;
    if (KEY_LENGTH != expected) return CRYPTO_ERROR_INVALID_KEY;

    crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
    memcpy(CONTEXT->ROUND_KEYS, KEY, KEY_LENGTH);
    CONTEXT->ROUNDS = rounds;
    CONTEXT->KEY_WORDS = key_words;

    bytes_generated = KEY_LENGTH;
    total_bytes = 16u * ((size_t)rounds + 1u);
    while (bytes_generated < total_bytes) {
        for (i = 0u; i < 4u; ++i) temp[i] = CONTEXT->ROUND_KEYS[bytes_generated - 4u + i];
        if ((bytes_generated % KEY_LENGTH) == 0u) {
            uint8_t x = temp[0];
            temp[0] = aes_sbox(temp[1]);
            temp[1] = aes_sbox(temp[2]);
            temp[2] = aes_sbox(temp[3]);
            temp[3] = aes_sbox(x);
            temp[0] ^= rcon;
            rcon = aes_xtime(rcon);
        } else if (KEY_LENGTH == 32u && (bytes_generated % KEY_LENGTH) == 16u) {
            for (i = 0u; i < 4u; ++i) temp[i] = aes_sbox(temp[i]);
        }
        for (i = 0u; i < 4u && bytes_generated < total_bytes; ++i) {
            CONTEXT->ROUND_KEYS[bytes_generated] =
                (uint8_t)(CONTEXT->ROUND_KEYS[bytes_generated - KEY_LENGTH] ^ temp[i]);
            ++bytes_generated;
        }
    }
    crypto_zeroize(temp, sizeof(temp));
    return CRYPTO_SUCCESS;
}

void CRYPTO_AES_CONTEXT_CLEAR(AES_CONTEXT *CONTEXT) {
    if (CONTEXT) crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
}

static int aes_context_valid(const AES_CONTEXT *ctx) {
    return ctx && (ctx->ROUNDS == 10u || ctx->ROUNDS == 12u || ctx->ROUNDS == 14u);
}

CryptoError CRYPTO_AES_ENCRYPT_BLOCK(const AES_CONTEXT *CONTEXT, const uint8_t INPUT[16], uint8_t OUTPUT[16]) {
    uint8_t state[16];
    uint8_t round;
    if (!aes_context_valid(CONTEXT) || !INPUT || !OUTPUT) return CRYPTO_ERROR_INVALID_ARGUMENT;
    memcpy(state, INPUT, 16u);
    add_round_key(state, CONTEXT->ROUND_KEYS);
    for (round = 1u; round < CONTEXT->ROUNDS; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, CONTEXT->ROUND_KEYS + 16u * (size_t)round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, CONTEXT->ROUND_KEYS + 16u * (size_t)CONTEXT->ROUNDS);
    memcpy(OUTPUT, state, 16u);
    crypto_zeroize(state, sizeof(state));
    return CRYPTO_SUCCESS;
}

CryptoError CRYPTO_AES_DECRYPT_BLOCK(const AES_CONTEXT *CONTEXT, const uint8_t INPUT[16], uint8_t OUTPUT[16]) {
    uint8_t state[16];
    uint8_t round;
    if (!aes_context_valid(CONTEXT) || !INPUT || !OUTPUT) return CRYPTO_ERROR_INVALID_ARGUMENT;
    memcpy(state, INPUT, 16u);
    add_round_key(state, CONTEXT->ROUND_KEYS + 16u * (size_t)CONTEXT->ROUNDS);
    for (round = CONTEXT->ROUNDS; round > 1u; --round) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, CONTEXT->ROUND_KEYS + 16u * (size_t)(round - 1u));
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, CONTEXT->ROUND_KEYS);
    memcpy(OUTPUT, state, 16u);
    crypto_zeroize(state, sizeof(state));
    return CRYPTO_SUCCESS;
}

static CryptoError aes_oneshot_init(AES_CONTEXT *ctx, AlgID alg, const uint8_t *key,
                                    size_t key_length, const uint8_t *input, size_t input_length,
                                    uint8_t *output, size_t output_length) {
    if (!ctx || !key || (!input && input_length) || (!output && input_length))
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (output_length < input_length) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    return CRYPTO_AES_CONTEXT_INIT(ctx, alg, key, key_length);
}

CryptoError CRYPTO_AES_ECB_ENCRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t *INPUT, size_t INPUT_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    CryptoError err;
    size_t offset;
    if ((INPUT_LENGTH % AES_BLOCK_SIZE) != 0u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = aes_oneshot_init(&ctx, ALG, KEY, KEY_LENGTH, INPUT, INPUT_LENGTH, OUTPUT, OUTPUT_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    for (offset = 0u; offset < INPUT_LENGTH; offset += AES_BLOCK_SIZE) {
        err = CRYPTO_AES_ENCRYPT_BLOCK(&ctx, INPUT + offset, OUTPUT + offset);
        if (err != CRYPTO_SUCCESS) break;
    }
    CRYPTO_AES_CONTEXT_CLEAR(&ctx);
    return err;
}

CryptoError CRYPTO_AES_ECB_DECRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t *INPUT, size_t INPUT_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    CryptoError err;
    size_t offset;
    if ((INPUT_LENGTH % AES_BLOCK_SIZE) != 0u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = aes_oneshot_init(&ctx, ALG, KEY, KEY_LENGTH, INPUT, INPUT_LENGTH, OUTPUT, OUTPUT_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    for (offset = 0u; offset < INPUT_LENGTH; offset += AES_BLOCK_SIZE) {
        err = CRYPTO_AES_DECRYPT_BLOCK(&ctx, INPUT + offset, OUTPUT + offset);
        if (err != CRYPTO_SUCCESS) break;
    }
    CRYPTO_AES_CONTEXT_CLEAR(&ctx);
    return err;
}

CryptoError CRYPTO_AES_CBC_ENCRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t IV[16], const uint8_t *INPUT, size_t INPUT_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    uint8_t chain[16], block[16];
    CryptoError err;
    size_t offset, i;
    if (!IV || (INPUT_LENGTH % AES_BLOCK_SIZE) != 0u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = aes_oneshot_init(&ctx, ALG, KEY, KEY_LENGTH, INPUT, INPUT_LENGTH, OUTPUT, OUTPUT_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    memcpy(chain, IV, 16u);
    for (offset = 0u; offset < INPUT_LENGTH; offset += 16u) {
        for (i = 0u; i < 16u; ++i) block[i] = (uint8_t)(INPUT[offset + i] ^ chain[i]);
        err = CRYPTO_AES_ENCRYPT_BLOCK(&ctx, block, OUTPUT + offset);
        if (err != CRYPTO_SUCCESS) break;
        memcpy(chain, OUTPUT + offset, 16u);
    }
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(chain, sizeof(chain));
    CRYPTO_AES_CONTEXT_CLEAR(&ctx);
    return err;
}

CryptoError CRYPTO_AES_CBC_DECRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t IV[16], const uint8_t *INPUT, size_t INPUT_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    uint8_t chain[16], block[16], cipher_block[16];
    CryptoError err;
    size_t offset, i;
    if (!IV || (INPUT_LENGTH % AES_BLOCK_SIZE) != 0u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = aes_oneshot_init(&ctx, ALG, KEY, KEY_LENGTH, INPUT, INPUT_LENGTH, OUTPUT, OUTPUT_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    memcpy(chain, IV, 16u);
    for (offset = 0u; offset < INPUT_LENGTH; offset += 16u) {
        memcpy(cipher_block, INPUT + offset, 16u);
        err = CRYPTO_AES_DECRYPT_BLOCK(&ctx, cipher_block, block);
        if (err != CRYPTO_SUCCESS) break;
        for (i = 0u; i < 16u; ++i) OUTPUT[offset + i] = (uint8_t)(block[i] ^ chain[i]);
        memcpy(chain, cipher_block, 16u);
    }
    crypto_zeroize(cipher_block, sizeof(cipher_block));
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(chain, sizeof(chain));
    CRYPTO_AES_CONTEXT_CLEAR(&ctx);
    return err;
}

static void increment_counter128(uint8_t counter[16]) {
    int i;
    for (i = 15; i >= 0; --i) {
        counter[i] = (uint8_t)(counter[i] + 1u);
        if (counter[i] != 0u) break;
    }
}

CryptoError CRYPTO_AES_CTR_CRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                          const uint8_t INITIAL_COUNTER[16], const uint8_t *INPUT, size_t INPUT_LENGTH,
                          uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    uint8_t counter[16], stream[16];
    CryptoError err;
    size_t offset = 0u, i, chunk;
    if (!INITIAL_COUNTER) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = aes_oneshot_init(&ctx, ALG, KEY, KEY_LENGTH, INPUT, INPUT_LENGTH, OUTPUT, OUTPUT_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    memcpy(counter, INITIAL_COUNTER, 16u);
    while (offset < INPUT_LENGTH) {
        err = CRYPTO_AES_ENCRYPT_BLOCK(&ctx, counter, stream);
        if (err != CRYPTO_SUCCESS) break;
        chunk = INPUT_LENGTH - offset;
        if (chunk > 16u) chunk = 16u;
        for (i = 0u; i < chunk; ++i) OUTPUT[offset + i] = (uint8_t)(INPUT[offset + i] ^ stream[i]);
        offset += chunk;
        increment_counter128(counter);
    }
    crypto_zeroize(stream, sizeof(stream));
    crypto_zeroize(counter, sizeof(counter));
    CRYPTO_AES_CONTEXT_CLEAR(&ctx);
    return err;
}
