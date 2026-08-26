#include "AES.h"

#include <string.h>

static void secure_zero(void *ptr, size_t length) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (length--) *p++ = 0;
}

static int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t length) {
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < length; ++i) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static void xor_block(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    size_t i;
    for (i = 0; i < 16u; ++i) out[i] = (uint8_t)(a[i] ^ b[i]);
}

static void store64_be(uint8_t out[8], uint64_t value) {
    size_t i;
    for (i = 0; i < 8u; ++i) out[7u - i] = (uint8_t)(value >> (8u * i));
}

static void gcm_shift_right_one(uint8_t v[16]) {
    uint8_t carry = 0;
    size_t i;
    for (i = 0; i < 16u; ++i) {
        uint8_t next = (uint8_t)(v[i] & 1u);
        v[i] = (uint8_t)((v[i] >> 1) | (carry << 7));
        carry = next;
    }
}

/* Bit-serial GHASH multiplication: no secret-indexed lookup table. */
static void gcm_multiply(uint8_t x[16], const uint8_t h[16]) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    size_t bit;
    memcpy(v, h, sizeof(v));
    for (bit = 0; bit < 128u; ++bit) {
        uint8_t mask = (uint8_t)(0u - ((x[bit / 8u] >> (7u - (bit % 8u))) & 1u));
        uint8_t lsb = (uint8_t)(v[15] & 1u);
        size_t i;
        for (i = 0; i < 16u; ++i) z[i] ^= (uint8_t)(v[i] & mask);
        gcm_shift_right_one(v);
        v[0] ^= (uint8_t)(0xe1u & (uint8_t)(0u - lsb));
    }
    memcpy(x, z, sizeof(z));
    secure_zero(z, sizeof(z));
    secure_zero(v, sizeof(v));
}

static void ghash_block(uint8_t y[16], const uint8_t h[16], const uint8_t block[16]) {
    size_t i;
    for (i = 0; i < 16u; ++i) y[i] ^= block[i];
    gcm_multiply(y, h);
}

static void ghash_bytes(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t length) {
    uint8_t block[16];
    while (length >= 16u) {
        ghash_block(y, h, data);
        data += 16u;
        length -= 16u;
    }
    if (length) {
        memset(block, 0, sizeof(block));
        memcpy(block, data, length);
        ghash_block(y, h, block);
        secure_zero(block, sizeof(block));
    }
}

static void gcm_inc32(uint8_t counter[16]) {
    int i;
    for (i = 15; i >= 12; --i) {
        counter[i] = (uint8_t)(counter[i] + 1u);
        if (counter[i] != 0u) break;
    }
}

static CryptoError gcm_make_j0(const uint8_t h[16], const uint8_t *iv, size_t iv_length, uint8_t j0[16]) {
    uint8_t lengths[16] = {0};
    uint64_t iv_bits;
    if (iv_length == 12u) {
        memcpy(j0, iv, 12u);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
        return CRYPTO_SUCCESS;
    }
    if (iv_length > (size_t)(UINT64_MAX / 8u)) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    memset(j0, 0, 16u);
    ghash_bytes(j0, h, iv, iv_length);
    iv_bits = (uint64_t)iv_length * 8u;
    store64_be(lengths + 8u, iv_bits);
    ghash_block(j0, h, lengths);
    secure_zero(lengths, sizeof(lengths));
    return CRYPTO_SUCCESS;
}

static CryptoError gcm_tag(const AES_CONTEXT *ctx, const uint8_t h[16], const uint8_t j0[16],
                           const uint8_t *aad, size_t aad_length,
                           const uint8_t *ciphertext, size_t ciphertext_length,
                           uint8_t tag[16]) {
    uint8_t y[16] = {0}, lengths[16], s[16];
    uint64_t aad_bits, ct_bits;
    size_t i;
    if (aad_length > (size_t)(UINT64_MAX / 8u) || ciphertext_length > (size_t)(UINT64_MAX / 8u))
        return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    ghash_bytes(y, h, aad, aad_length);
    ghash_bytes(y, h, ciphertext, ciphertext_length);
    aad_bits = (uint64_t)aad_length * 8u;
    ct_bits = (uint64_t)ciphertext_length * 8u;
    store64_be(lengths, aad_bits);
    store64_be(lengths + 8u, ct_bits);
    ghash_block(y, h, lengths);
    if (AES_ENCRYPT_BLOCK(ctx, j0, s) != CRYPTO_SUCCESS) return CRYPTO_ERROR_INTERNAL;
    for (i = 0; i < 16u; ++i) tag[i] = (uint8_t)(s[i] ^ y[i]);
    secure_zero(y, sizeof(y));
    secure_zero(lengths, sizeof(lengths));
    secure_zero(s, sizeof(s));
    return CRYPTO_SUCCESS;
}

static CryptoError gcm_ctr(const AES_CONTEXT *ctx, const uint8_t j0[16], const uint8_t *input, size_t length, uint8_t *output) {
    uint8_t counter[16], stream[16];
    size_t offset = 0, i, chunk;
    memcpy(counter, j0, 16u);
    while (offset < length) {
        gcm_inc32(counter);
        if (AES_ENCRYPT_BLOCK(ctx, counter, stream) != CRYPTO_SUCCESS) return CRYPTO_ERROR_INTERNAL;
        chunk = length - offset;
        if (chunk > 16u) chunk = 16u;
        for (i = 0; i < chunk; ++i) output[offset + i] = (uint8_t)(input[offset + i] ^ stream[i]);
        offset += chunk;
    }
    secure_zero(counter, sizeof(counter));
    secure_zero(stream, sizeof(stream));
    return CRYPTO_SUCCESS;
}

CryptoError AES_GCM_ENCRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t *IV, size_t IV_LENGTH,
                            const uint8_t *AAD, size_t AAD_LENGTH,
                            const uint8_t *INPUT, size_t INPUT_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
                            uint8_t *TAG, size_t TAG_LENGTH) {
    AES_CONTEXT ctx;
    uint8_t h[16] = {0}, j0[16], full_tag[16];
    CryptoError err;
    if (!KEY || !IV || (!AAD && AAD_LENGTH) || (!INPUT && INPUT_LENGTH) || (!OUTPUT && INPUT_LENGTH) || !TAG)
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (IV_LENGTH == 0u || TAG_LENGTH < 4u || TAG_LENGTH > 16u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (OUTPUT_LENGTH < INPUT_LENGTH) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    err = AES_CONTEXT_INIT(&ctx, ALG, KEY, KEY_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    err = AES_ENCRYPT_BLOCK(&ctx, h, h);
    if (err == CRYPTO_SUCCESS) err = gcm_make_j0(h, IV, IV_LENGTH, j0);
    if (err == CRYPTO_SUCCESS) err = gcm_ctr(&ctx, j0, INPUT, INPUT_LENGTH, OUTPUT);
    if (err == CRYPTO_SUCCESS) err = gcm_tag(&ctx, h, j0, AAD, AAD_LENGTH, OUTPUT, INPUT_LENGTH, full_tag);
    if (err == CRYPTO_SUCCESS) memcpy(TAG, full_tag, TAG_LENGTH);
    AES_CONTEXT_CLEAR(&ctx);
    secure_zero(h, sizeof(h)); secure_zero(j0, sizeof(j0)); secure_zero(full_tag, sizeof(full_tag));
    return err;
}

CryptoError AES_GCM_DECRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t *IV, size_t IV_LENGTH,
                            const uint8_t *AAD, size_t AAD_LENGTH,
                            const uint8_t *INPUT, size_t INPUT_LENGTH,
                            const uint8_t *TAG, size_t TAG_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    uint8_t h[16] = {0}, j0[16], full_tag[16];
    CryptoError err;
    if (!KEY || !IV || (!AAD && AAD_LENGTH) || (!INPUT && INPUT_LENGTH) || !TAG || (!OUTPUT && INPUT_LENGTH))
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (IV_LENGTH == 0u || TAG_LENGTH < 4u || TAG_LENGTH > 16u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (OUTPUT_LENGTH < INPUT_LENGTH) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    err = AES_CONTEXT_INIT(&ctx, ALG, KEY, KEY_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    err = AES_ENCRYPT_BLOCK(&ctx, h, h);
    if (err == CRYPTO_SUCCESS) err = gcm_make_j0(h, IV, IV_LENGTH, j0);
    if (err == CRYPTO_SUCCESS) err = gcm_tag(&ctx, h, j0, AAD, AAD_LENGTH, INPUT, INPUT_LENGTH, full_tag);
    if (err == CRYPTO_SUCCESS && !constant_time_equal(full_tag, TAG, TAG_LENGTH)) err = CRYPTO_ERROR_AUTHENTICATION_FAILED;
    if (err == CRYPTO_SUCCESS) err = gcm_ctr(&ctx, j0, INPUT, INPUT_LENGTH, OUTPUT);
    if (err != CRYPTO_SUCCESS && OUTPUT && INPUT_LENGTH) secure_zero(OUTPUT, INPUT_LENGTH);
    AES_CONTEXT_CLEAR(&ctx);
    secure_zero(h, sizeof(h)); secure_zero(j0, sizeof(j0)); secure_zero(full_tag, sizeof(full_tag));
    return err;
}

static void ccm_encode_length(uint8_t *out, size_t q, size_t value) {
    size_t i;
    for (i = 0; i < q; ++i) {
        out[q - 1u - i] = (uint8_t)value;
        value >>= 8;
    }
}

static int ccm_length_fits(size_t q, size_t length) {
    if (q >= sizeof(size_t)) return 1;
    return length <= ((((size_t)1u) << (8u * q)) - 1u);
}

static CryptoError ccm_mac_block(const AES_CONTEXT *ctx, uint8_t state[16], const uint8_t block[16]) {
    uint8_t x[16];
    xor_block(x, state, block);
    if (AES_ENCRYPT_BLOCK(ctx, x, state) != CRYPTO_SUCCESS) {
        secure_zero(x, sizeof(x));
        return CRYPTO_ERROR_INTERNAL;
    }
    secure_zero(x, sizeof(x));
    return CRYPTO_SUCCESS;
}

static CryptoError ccm_mac_bytes(const AES_CONTEXT *ctx, uint8_t state[16], const uint8_t *data, size_t length) {
    uint8_t block[16];
    while (length >= 16u) {
        CryptoError err = ccm_mac_block(ctx, state, data);
        if (err != CRYPTO_SUCCESS) return err;
        data += 16u;
        length -= 16u;
    }
    if (length) {
        CryptoError err;
        memset(block, 0, sizeof(block));
        memcpy(block, data, length);
        err = ccm_mac_block(ctx, state, block);
        secure_zero(block, sizeof(block));
        return err;
    }
    return CRYPTO_SUCCESS;
}

static CryptoError ccm_mac_aad(const AES_CONTEXT *ctx, uint8_t state[16], const uint8_t *aad, size_t aad_length) {
    uint8_t prefix[10], block[16];
    size_t prefix_length, chunk;
    CryptoError err;
    if (aad_length == 0u) return CRYPTO_SUCCESS;
    if (aad_length < 0xff00u) {
        prefix[0] = (uint8_t)(aad_length >> 8);
        prefix[1] = (uint8_t)aad_length;
        prefix_length = 2u;
    } else if ((uint64_t)aad_length <= UINT32_MAX) {
        prefix[0] = 0xff; prefix[1] = 0xfe;
        prefix[2] = (uint8_t)(aad_length >> 24); prefix[3] = (uint8_t)(aad_length >> 16);
        prefix[4] = (uint8_t)(aad_length >> 8); prefix[5] = (uint8_t)aad_length;
        prefix_length = 6u;
    } else {
        uint64_t n = (uint64_t)aad_length;
        prefix[0] = 0xff; prefix[1] = 0xff;
        store64_be(prefix + 2u, n);
        prefix_length = 10u;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, prefix, prefix_length);
    chunk = 16u - prefix_length;
    if (chunk > aad_length) chunk = aad_length;
    memcpy(block + prefix_length, aad, chunk);
    err = ccm_mac_block(ctx, state, block);
    if (err != CRYPTO_SUCCESS) return err;
    aad += chunk;
    aad_length -= chunk;
    err = ccm_mac_bytes(ctx, state, aad, aad_length);
    secure_zero(prefix, sizeof(prefix)); secure_zero(block, sizeof(block));
    return err;
}

static CryptoError ccm_compute_mac(const AES_CONTEXT *ctx, const uint8_t *nonce, size_t nonce_length,
                                   const uint8_t *aad, size_t aad_length,
                                   const uint8_t *plaintext, size_t plaintext_length,
                                   size_t tag_length, uint8_t mac[16]) {
    uint8_t b0[16] = {0};
    size_t q = 15u - nonce_length;
    CryptoError err;
    b0[0] = (uint8_t)((aad_length ? 0x40u : 0u) | (((tag_length - 2u) / 2u) << 3) | (q - 1u));
    memcpy(b0 + 1u, nonce, nonce_length);
    ccm_encode_length(b0 + 1u + nonce_length, q, plaintext_length);
    memset(mac, 0, 16u);
    err = ccm_mac_block(ctx, mac, b0);
    if (err == CRYPTO_SUCCESS) err = ccm_mac_aad(ctx, mac, aad, aad_length);
    if (err == CRYPTO_SUCCESS) err = ccm_mac_bytes(ctx, mac, plaintext, plaintext_length);
    secure_zero(b0, sizeof(b0));
    return err;
}

static void ccm_counter_block(uint8_t counter[16], const uint8_t *nonce, size_t nonce_length, size_t value) {
    size_t q = 15u - nonce_length;
    memset(counter, 0, 16u);
    counter[0] = (uint8_t)(q - 1u);
    memcpy(counter + 1u, nonce, nonce_length);
    ccm_encode_length(counter + 1u + nonce_length, q, value);
}

static CryptoError ccm_ctr(const AES_CONTEXT *ctx, const uint8_t *nonce, size_t nonce_length,
                           const uint8_t *input, size_t length, uint8_t *output) {
    uint8_t counter[16], stream[16];
    size_t block_index = 1u, offset = 0, chunk, i;
    while (offset < length) {
        ccm_counter_block(counter, nonce, nonce_length, block_index++);
        if (AES_ENCRYPT_BLOCK(ctx, counter, stream) != CRYPTO_SUCCESS) return CRYPTO_ERROR_INTERNAL;
        chunk = length - offset;
        if (chunk > 16u) chunk = 16u;
        for (i = 0; i < chunk; ++i) output[offset + i] = (uint8_t)(input[offset + i] ^ stream[i]);
        offset += chunk;
    }
    secure_zero(counter, sizeof(counter)); secure_zero(stream, sizeof(stream));
    return CRYPTO_SUCCESS;
}

static CryptoError ccm_validate(const uint8_t *nonce, size_t nonce_length, size_t message_length, size_t tag_length) {
    size_t q;
    if (!nonce || nonce_length < 7u || nonce_length > 13u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (tag_length < 4u || tag_length > 16u || (tag_length & 1u)) return CRYPTO_ERROR_INVALID_ARGUMENT;
    q = 15u - nonce_length;
    if (!ccm_length_fits(q, message_length)) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    return CRYPTO_SUCCESS;
}

CryptoError AES_CCM_ENCRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t *NONCE, size_t NONCE_LENGTH,
                            const uint8_t *AAD, size_t AAD_LENGTH,
                            const uint8_t *INPUT, size_t INPUT_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
                            uint8_t *TAG, size_t TAG_LENGTH) {
    AES_CONTEXT ctx;
    uint8_t mac[16], ctr0[16], s0[16];
    size_t i;
    CryptoError err;
    if (!KEY || (!AAD && AAD_LENGTH) || (!INPUT && INPUT_LENGTH) || (!OUTPUT && INPUT_LENGTH) || !TAG)
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ccm_validate(NONCE, NONCE_LENGTH, INPUT_LENGTH, TAG_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    if (OUTPUT_LENGTH < INPUT_LENGTH) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    err = AES_CONTEXT_INIT(&ctx, ALG, KEY, KEY_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    err = ccm_compute_mac(&ctx, NONCE, NONCE_LENGTH, AAD, AAD_LENGTH, INPUT, INPUT_LENGTH, TAG_LENGTH, mac);
    if (err == CRYPTO_SUCCESS) err = ccm_ctr(&ctx, NONCE, NONCE_LENGTH, INPUT, INPUT_LENGTH, OUTPUT);
    ccm_counter_block(ctr0, NONCE, NONCE_LENGTH, 0u);
    if (err == CRYPTO_SUCCESS) err = AES_ENCRYPT_BLOCK(&ctx, ctr0, s0);
    if (err == CRYPTO_SUCCESS) for (i = 0; i < TAG_LENGTH; ++i) TAG[i] = (uint8_t)(mac[i] ^ s0[i]);
    AES_CONTEXT_CLEAR(&ctx);
    secure_zero(mac, sizeof(mac)); secure_zero(ctr0, sizeof(ctr0)); secure_zero(s0, sizeof(s0));
    return err;
}

CryptoError AES_CCM_DECRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                            const uint8_t *NONCE, size_t NONCE_LENGTH,
                            const uint8_t *AAD, size_t AAD_LENGTH,
                            const uint8_t *INPUT, size_t INPUT_LENGTH,
                            const uint8_t *TAG, size_t TAG_LENGTH,
                            uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    AES_CONTEXT ctx;
    uint8_t mac[16], ctr0[16], s0[16], expected[16] = {0};
    size_t i;
    CryptoError err;
    if (!KEY || (!AAD && AAD_LENGTH) || (!INPUT && INPUT_LENGTH) || !TAG || (!OUTPUT && INPUT_LENGTH))
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ccm_validate(NONCE, NONCE_LENGTH, INPUT_LENGTH, TAG_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    if (OUTPUT_LENGTH < INPUT_LENGTH) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    err = AES_CONTEXT_INIT(&ctx, ALG, KEY, KEY_LENGTH);
    if (err != CRYPTO_SUCCESS) return err;
    err = ccm_ctr(&ctx, NONCE, NONCE_LENGTH, INPUT, INPUT_LENGTH, OUTPUT);
    if (err == CRYPTO_SUCCESS) err = ccm_compute_mac(&ctx, NONCE, NONCE_LENGTH, AAD, AAD_LENGTH, OUTPUT, INPUT_LENGTH, TAG_LENGTH, mac);
    ccm_counter_block(ctr0, NONCE, NONCE_LENGTH, 0u);
    if (err == CRYPTO_SUCCESS) err = AES_ENCRYPT_BLOCK(&ctx, ctr0, s0);
    if (err == CRYPTO_SUCCESS) {
        for (i = 0; i < TAG_LENGTH; ++i) expected[i] = (uint8_t)(mac[i] ^ s0[i]);
        if (!constant_time_equal(expected, TAG, TAG_LENGTH)) err = CRYPTO_ERROR_AUTHENTICATION_FAILED;
    }
    if (err != CRYPTO_SUCCESS && OUTPUT && INPUT_LENGTH) secure_zero(OUTPUT, INPUT_LENGTH);
    AES_CONTEXT_CLEAR(&ctx);
    secure_zero(mac, sizeof(mac)); secure_zero(ctr0, sizeof(ctr0)); secure_zero(s0, sizeof(s0)); secure_zero(expected, sizeof(expected));
    return err;
}
