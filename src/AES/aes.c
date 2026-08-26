#include "AES.h"
#include "aes_internal.h"

#include <string.h>

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t AES_INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1bu));
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1u) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

static void add_round_key(uint8_t state[16], const uint8_t *round_key) {
    size_t i;
    for (i = 0; i < 16u; ++i) state[i] ^= round_key[i];
}

static void sub_bytes(uint8_t state[16]) {
    size_t i;
    for (i = 0; i < 16u; ++i) state[i] = AES_SBOX[state[i]];
}

static void inv_sub_bytes(uint8_t state[16]) {
    size_t i;
    for (i = 0; i < 16u; ++i) state[i] = AES_INV_SBOX[state[i]];
}

static void shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    t[0]=s[0];  t[4]=s[4];  t[8]=s[8];   t[12]=s[12];
    t[1]=s[5];  t[5]=s[9];  t[9]=s[13];  t[13]=s[1];
    t[2]=s[10]; t[6]=s[14]; t[10]=s[2];  t[14]=s[6];
    t[3]=s[15]; t[7]=s[3];  t[11]=s[7];  t[15]=s[11];
    memcpy(s, t, sizeof(t));
}

static void inv_shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    t[0]=s[0];  t[4]=s[4];  t[8]=s[8];   t[12]=s[12];
    t[1]=s[13]; t[5]=s[1];  t[9]=s[5];   t[13]=s[9];
    t[2]=s[10]; t[6]=s[14]; t[10]=s[2];  t[14]=s[6];
    t[3]=s[7];  t[7]=s[11]; t[11]=s[15]; t[15]=s[3];
    memcpy(s, t, sizeof(t));
}

static void mix_columns(uint8_t s[16]) {
    size_t c;
    for (c = 0; c < 4u; ++c) {
        size_t i = c * 4u;
        uint8_t a0=s[i], a1=s[i+1u], a2=s[i+2u], a3=s[i+3u];
        s[i]    = (uint8_t)(gmul(a0,2)^gmul(a1,3)^a2^a3);
        s[i+1u] = (uint8_t)(a0^gmul(a1,2)^gmul(a2,3)^a3);
        s[i+2u] = (uint8_t)(a0^a1^gmul(a2,2)^gmul(a3,3));
        s[i+3u] = (uint8_t)(gmul(a0,3)^a1^a2^gmul(a3,2));
    }
}

static void inv_mix_columns(uint8_t s[16]) {
    size_t c;
    for (c = 0; c < 4u; ++c) {
        size_t i = c * 4u;
        uint8_t a0=s[i], a1=s[i+1u], a2=s[i+2u], a3=s[i+3u];
        s[i]    = (uint8_t)(gmul(a0,14)^gmul(a1,11)^gmul(a2,13)^gmul(a3,9));
        s[i+1u] = (uint8_t)(gmul(a0,9)^gmul(a1,14)^gmul(a2,11)^gmul(a3,13));
        s[i+2u] = (uint8_t)(gmul(a0,13)^gmul(a1,9)^gmul(a2,14)^gmul(a3,11));
        s[i+3u] = (uint8_t)(gmul(a0,11)^gmul(a1,13)^gmul(a2,9)^gmul(a3,14));
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

size_t AES_KEY_SIZE(AlgID ALG) {
    size_t key_length = 0;
    return aes_parameters(ALG, &key_length, NULL, NULL) == CRYPTO_SUCCESS ? key_length : 0u;
}

CryptoError AES_CONTEXT_INIT(AES_CONTEXT *CONTEXT, AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH) {
    size_t expected = 0, bytes_generated, total_bytes;
    uint8_t key_words = 0, rounds = 0, rcon = 1u, temp[4];
    CryptoError err;
    size_t i;

    if (!CONTEXT || !KEY) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = aes_parameters(ALG, &expected, &key_words, &rounds);
    if (err != CRYPTO_SUCCESS) return err;
    if (KEY_LENGTH != expected) return CRYPTO_ERROR_INVALID_KEY;

    memset(CONTEXT, 0, sizeof(*CONTEXT));
    memcpy(CONTEXT->ROUND_KEYS, KEY, KEY_LENGTH);
    CONTEXT->ROUNDS = rounds;
    CONTEXT->KEY_WORDS = key_words;

    bytes_generated = KEY_LENGTH;
    total_bytes = 16u * ((size_t)rounds + 1u);
    while (bytes_generated < total_bytes) {
        for (i = 0; i < 4u; ++i) temp[i] = CONTEXT->ROUND_KEYS[bytes_generated - 4u + i];

        if ((bytes_generated % KEY_LENGTH) == 0u) {
            uint8_t x = temp[0];
            temp[0] = AES_SBOX[temp[1]];
            temp[1] = AES_SBOX[temp[2]];
            temp[2] = AES_SBOX[temp[3]];
            temp[3] = AES_SBOX[x];
            temp[0] ^= rcon;
            rcon = xtime(rcon);
        } else if (KEY_LENGTH == 32u && (bytes_generated % KEY_LENGTH) == 16u) {
            for (i = 0; i < 4u; ++i) temp[i] = AES_SBOX[temp[i]];
        }

        for (i = 0; i < 4u && bytes_generated < total_bytes; ++i) {
            CONTEXT->ROUND_KEYS[bytes_generated] = (uint8_t)(CONTEXT->ROUND_KEYS[bytes_generated - KEY_LENGTH] ^ temp[i]);
            ++bytes_generated;
        }
    }
    return CRYPTO_SUCCESS;
}

void AES_CONTEXT_CLEAR(AES_CONTEXT *CONTEXT) {
    if (CONTEXT) {
        volatile uint8_t *p = (volatile uint8_t *)CONTEXT;
        size_t i;
        for (i = 0; i < sizeof(*CONTEXT); ++i) p[i] = 0;
    }
}

void aes_encrypt_block_internal(const AES_CONTEXT *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    uint8_t round;
    memcpy(state, in, 16u);
    add_round_key(state, ctx->ROUND_KEYS);
    for (round = 1u; round < ctx->ROUNDS; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx->ROUND_KEYS + 16u * round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx->ROUND_KEYS + 16u * ctx->ROUNDS);
    memcpy(out, state, 16u);
    memset(state, 0, sizeof(state));
}

void aes_decrypt_block_internal(const AES_CONTEXT *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    uint8_t round;
    memcpy(state, in, 16u);
    add_round_key(state, ctx->ROUND_KEYS + 16u * ctx->ROUNDS);
    for (round = ctx->ROUNDS; round > 1u; --round) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, ctx->ROUND_KEYS + 16u * (round - 1u));
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, ctx->ROUND_KEYS);
    memcpy(out, state, 16u);
    memset(state, 0, sizeof(state));
}

static CryptoError validate_context(const AES_CONTEXT *ctx) {
    if (!ctx) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (!((ctx->ROUNDS == 10u && ctx->KEY_WORDS == 4u) ||
          (ctx->ROUNDS == 12u && ctx->KEY_WORDS == 6u) ||
          (ctx->ROUNDS == 14u && ctx->KEY_WORDS == 8u))) return CRYPTO_ERROR_INVALID_KEY;
    return CRYPTO_SUCCESS;
}

CryptoError AES_ENCRYPT_BLOCK(const AES_CONTEXT *CONTEXT, const uint8_t INPUT[16], uint8_t OUTPUT[16]) {
    CryptoError err = validate_context(CONTEXT);
    if (err != CRYPTO_SUCCESS) return err;
    if (!INPUT || !OUTPUT) return CRYPTO_ERROR_INVALID_ARGUMENT;
    aes_encrypt_block_internal(CONTEXT, INPUT, OUTPUT);
    return CRYPTO_SUCCESS;
}

CryptoError AES_DECRYPT_BLOCK(const AES_CONTEXT *CONTEXT, const uint8_t INPUT[16], uint8_t OUTPUT[16]) {
    CryptoError err = validate_context(CONTEXT);
    if (err != CRYPTO_SUCCESS) return err;
    if (!INPUT || !OUTPUT) return CRYPTO_ERROR_INVALID_ARGUMENT;
    aes_decrypt_block_internal(CONTEXT, INPUT, OUTPUT);
    return CRYPTO_SUCCESS;
}

static CryptoError init_for_mode(AES_CONTEXT *ctx, AlgID alg, const uint8_t *key, size_t key_length,
                                 const uint8_t *input, size_t input_length, uint8_t *output, size_t output_length,
                                 int require_blocks) {
    if ((!input && input_length) || (!output && input_length)) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (require_blocks && (input_length % AES_BLOCK_SIZE) != 0u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (output_length < input_length) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    return AES_CONTEXT_INIT(ctx, alg, key, key_length);
}

CryptoError AES_ECB_ENCRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t *INPUT, size_t INPUT_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    CryptoError err = init_for_mode(&ctx, ALG, KEY, KEY_LENGTH, INPUT, INPUT_LENGTH, OUTPUT, OUTPUT_LENGTH, 1);
    size_t off;
    if (err != CRYPTO_SUCCESS) return err;
    for (off = 0; off < INPUT_LENGTH; off += AES_BLOCK_SIZE) aes_encrypt_block_internal(&ctx, INPUT + off, OUTPUT + off);
    AES_CONTEXT_CLEAR(&ctx);
    return CRYPTO_SUCCESS;
}

CryptoError AES_ECB_DECRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t *INPUT, size_t INPUT_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    CryptoError err = init_for_mode(&ctx, ALG, KEY, KEY_LENGTH, INPUT, INPUT_LENGTH, OUTPUT, OUTPUT_LENGTH, 1);
    size_t off;
    if (err != CRYPTO_SUCCESS) return err;
    for (off = 0; off < INPUT_LENGTH; off += AES_BLOCK_SIZE) aes_decrypt_block_internal(&ctx, INPUT + off, OUTPUT + off);
    AES_CONTEXT_CLEAR(&ctx);
    return CRYPTO_SUCCESS;
}

CryptoError AES_CBC_ENCRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t IV[16], const uint8_t *INPUT, size_t INPUT_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    uint8_t chain[16], block[16];
    CryptoError err;
    size_t off, i;
    if (!IV) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = init_for_mode(&ctx, ALG, KEY, KEY_LENGTH, INPUT, INPUT_LENGTH, OUTPUT, OUTPUT_LENGTH, 1);
    if (err != CRYPTO_SUCCESS) return err;
    memcpy(chain, IV, 16u);
    for (off = 0; off < INPUT_LENGTH; off += 16u) {
        for (i = 0; i < 16u; ++i) block[i] = (uint8_t)(INPUT[off + i] ^ chain[i]);
        aes_encrypt_block_internal(&ctx, block, OUTPUT + off);
        memcpy(chain, OUTPUT + off, 16u);
    }
    memset(chain, 0, sizeof(chain));
    memset(block, 0, sizeof(block));
    AES_CONTEXT_CLEAR(&ctx);
    return CRYPTO_SUCCESS;
}

CryptoError AES_CBC_DECRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t IV[16], const uint8_t *INPUT, size_t INPUT_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    uint8_t chain[16], block[16], ciphertext_block[16];
    CryptoError err;
    size_t off, i;
    if (!IV) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = init_for_mode(&ctx, ALG, KEY, KEY_LENGTH, INPUT, INPUT_LENGTH, OUTPUT, OUTPUT_LENGTH, 1);
    if (err != CRYPTO_SUCCESS) return err;
    memcpy(chain, IV, 16u);
    for (off = 0; off < INPUT_LENGTH; off += 16u) {
        memcpy(ciphertext_block, INPUT + off, 16u);
        aes_decrypt_block_internal(&ctx, ciphertext_block, block);
        for (i = 0; i < 16u; ++i) OUTPUT[off + i] = (uint8_t)(block[i] ^ chain[i]);
        memcpy(chain, ciphertext_block, 16u);
    }
    memset(chain, 0, sizeof(chain));
    memset(block, 0, sizeof(block));
    memset(ciphertext_block, 0, sizeof(ciphertext_block));
    AES_CONTEXT_CLEAR(&ctx);
    return CRYPTO_SUCCESS;
}

static void increment_counter(uint8_t counter[16]) {
    size_t i = 16u;
    while (i > 0u) {
        --i;
        counter[i] = (uint8_t)(counter[i] + 1u);
        if (counter[i] != 0u) break;
    }
}

CryptoError AES_CTR_CRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                          const uint8_t INITIAL_COUNTER[16], const uint8_t *INPUT, size_t INPUT_LENGTH,
                          uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    uint8_t counter[16], stream[16];
    CryptoError err;
    size_t off = 0;
    if (!INITIAL_COUNTER) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = init_for_mode(&ctx, ALG, KEY, KEY_LENGTH, INPUT, INPUT_LENGTH, OUTPUT, OUTPUT_LENGTH, 0);
    if (err != CRYPTO_SUCCESS) return err;
    memcpy(counter, INITIAL_COUNTER, 16u);
    while (off < INPUT_LENGTH) {
        size_t i, chunk = INPUT_LENGTH - off;
        if (chunk > 16u) chunk = 16u;
        aes_encrypt_block_internal(&ctx, counter, stream);
        for (i = 0; i < chunk; ++i) OUTPUT[off + i] = (uint8_t)(INPUT[off + i] ^ stream[i]);
        off += chunk;
        increment_counter(counter);
    }
    memset(counter, 0, sizeof(counter));
    memset(stream, 0, sizeof(stream));
    AES_CONTEXT_CLEAR(&ctx);
    return CRYPTO_SUCCESS;
}
