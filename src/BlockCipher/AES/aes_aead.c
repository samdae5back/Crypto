/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "BlockCipher/AES/aes_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/Endian/endian_internal.h"

#include <string.h>

static void xor_block(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    size_t i;
    for (i = 0; i < 16u; ++i) out[i] = (uint8_t)(a[i] ^ b[i]);
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
    crypto_zeroize(z, sizeof(z));
    crypto_zeroize(v, sizeof(v));
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
        crypto_zeroize(block, sizeof(block));
    }
}

static void gcm_inc32(uint8_t counter[16]) {
    int i;
    for (i = 15; i >= 12; --i) {
        counter[i] = (uint8_t)(counter[i] + 1u);
        if (counter[i] != 0u) break;
    }
}

static LiberaCError gcm_make_j0(const uint8_t h[16], const uint8_t *iv, size_t iv_length, uint8_t j0[16]) {
    uint8_t lengths[16] = {0};
    uint64_t iv_bits;
    if (iv_length == 12u) {
        memcpy(j0, iv, 12u);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
        return LIBERAC_SUCCESS;
    }
    if (iv_length > (size_t)(UINT64_MAX / 8u)) return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    memset(j0, 0, 16u);
    ghash_bytes(j0, h, iv, iv_length);
    iv_bits = (uint64_t)iv_length * 8u;
    crypto_store64_be(lengths + 8u, iv_bits);
    ghash_block(j0, h, lengths);
    crypto_zeroize(lengths, sizeof(lengths));
    return LIBERAC_SUCCESS;
}

static LiberaCError gcm_tag(const AES_CONTEXT *ctx, const uint8_t h[16], const uint8_t j0[16],
                           const uint8_t *aad, size_t aad_length,
                           const uint8_t *ciphertext, size_t ciphertext_length,
                           uint8_t tag[16]) {
    uint8_t y[16] = {0}, lengths[16], s[16];
    uint64_t aad_bits, ct_bits;
    LiberaCError err;
    size_t i;
    if (aad_length > (size_t)(UINT64_MAX / 8u) || ciphertext_length > (size_t)(UINT64_MAX / 8u))
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    ghash_bytes(y, h, aad, aad_length);
    ghash_bytes(y, h, ciphertext, ciphertext_length);
    aad_bits = (uint64_t)aad_length * 8u;
    ct_bits = (uint64_t)ciphertext_length * 8u;
    crypto_store64_be(lengths, aad_bits);
    crypto_store64_be(lengths + 8u, ct_bits);
    ghash_block(y, h, lengths);
    err = crypto_aes_encrypt_block(ctx, j0, s);
    if (err == LIBERAC_SUCCESS) {
        for (i = 0; i < 16u; ++i) tag[i] = (uint8_t)(s[i] ^ y[i]);
    } else {
        err = LIBERAC_ERROR_INTERNAL;
    }
    crypto_zeroize(y, sizeof(y));
    crypto_zeroize(lengths, sizeof(lengths));
    crypto_zeroize(s, sizeof(s));
    return err;
}

static LiberaCError gcm_ctr(const AES_CONTEXT *ctx, const uint8_t j0[16], const uint8_t *input, size_t length, uint8_t *output) {
    uint8_t counter[16], stream[16];
    size_t offset = 0, i, chunk;
    memcpy(counter, j0, 16u);
    while (offset < length) {
        gcm_inc32(counter);
        if (crypto_aes_encrypt_block(ctx, counter, stream) != LIBERAC_SUCCESS) {
            crypto_zeroize(counter, sizeof(counter));
            crypto_zeroize(stream, sizeof(stream));
            return LIBERAC_ERROR_INTERNAL;
        }
        chunk = length - offset;
        if (chunk > 16u) chunk = 16u;
        for (i = 0; i < chunk; ++i) output[offset + i] = (uint8_t)(input[offset + i] ^ stream[i]);
        offset += chunk;
    }
    crypto_zeroize(counter, sizeof(counter));
    crypto_zeroize(stream, sizeof(stream));
    return LIBERAC_SUCCESS;
}

static int gcm_tag_length_valid(size_t tag_length) {
    switch (tag_length) {
        case 4u:
        case 8u:
        case 12u:
        case 13u:
        case 14u:
        case 15u:
        case 16u:
            return 1;
        default:
            return 0;
    }
}

static LiberaCError gcm_validate_lengths(size_t iv_length, size_t aad_length,
                                        size_t message_length,
                                        size_t tag_length) {
    const uint64_t max_bit_string_bytes = UINT64_MAX / 8u;
    const uint64_t max_gctr_bytes = (uint64_t)0xfffffffeu * 16u;

    if (!gcm_tag_length_valid(tag_length))
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if ((uint64_t)iv_length > max_bit_string_bytes ||
        (uint64_t)aad_length > max_bit_string_bytes ||
        (uint64_t)message_length > max_bit_string_bytes ||
        (uint64_t)message_length > max_gctr_bytes) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_aes_gcm_encrypt(
    const AES_CONTEXT *CONTEXT,
    uint8_t *OUTPUT, uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH) {
    uint8_t h[16] = {0};
    uint8_t j0[16] = {0};
    uint8_t full_tag[16] = {0};
    LiberaCError err;

    if (!CONTEXT || !IV || !TAG || (!AAD && AAD_LENGTH != 0u) ||
        (!INPUT && INPUT_LENGTH != 0u) || (!OUTPUT && INPUT_LENGTH != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (IV_LENGTH == 0u) return LIBERAC_ERROR_INVALID_ARGUMENT;
    err = gcm_validate_lengths(IV_LENGTH, AAD_LENGTH,
                               INPUT_LENGTH, TAG_LENGTH);
    if (err != LIBERAC_SUCCESS) return err;

    err = crypto_aes_encrypt_block(CONTEXT, h, h);
    if (err == LIBERAC_SUCCESS) err = gcm_make_j0(h, IV, IV_LENGTH, j0);
    if (err == LIBERAC_SUCCESS)
        err = gcm_ctr(CONTEXT, j0, INPUT, INPUT_LENGTH, OUTPUT);
    if (err == LIBERAC_SUCCESS) {
        err = gcm_tag(CONTEXT, h, j0, AAD, AAD_LENGTH,
                      OUTPUT, INPUT_LENGTH, full_tag);
    }
    if (err == LIBERAC_SUCCESS) memcpy(TAG, full_tag, TAG_LENGTH);

    crypto_zeroize(h, sizeof(h));
    crypto_zeroize(j0, sizeof(j0));
    crypto_zeroize(full_tag, sizeof(full_tag));
    return err;
}

LiberaCError crypto_aes_gcm_decrypt(
    const AES_CONTEXT *CONTEXT,
    uint8_t *OUTPUT, const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH) {
    uint8_t h[16] = {0};
    uint8_t j0[16] = {0};
    uint8_t full_tag[16] = {0};
    LiberaCError err;

    if (!CONTEXT || !IV || !TAG || (!AAD && AAD_LENGTH != 0u) ||
        (!INPUT && INPUT_LENGTH != 0u) || (!OUTPUT && INPUT_LENGTH != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (IV_LENGTH == 0u) return LIBERAC_ERROR_INVALID_ARGUMENT;
    err = gcm_validate_lengths(IV_LENGTH, AAD_LENGTH,
                               INPUT_LENGTH, TAG_LENGTH);
    if (err != LIBERAC_SUCCESS) return err;

    err = crypto_aes_encrypt_block(CONTEXT, h, h);
    if (err == LIBERAC_SUCCESS) err = gcm_make_j0(h, IV, IV_LENGTH, j0);
    if (err == LIBERAC_SUCCESS) {
        err = gcm_tag(CONTEXT, h, j0, AAD, AAD_LENGTH,
                      INPUT, INPUT_LENGTH, full_tag);
    }
    if (err == LIBERAC_SUCCESS &&
        !crypto_constant_time_equal(full_tag, TAG, TAG_LENGTH)) {
        err = LIBERAC_ERROR_AUTHENTICATION_FAILED;
    }
    if (err == LIBERAC_SUCCESS)
        err = gcm_ctr(CONTEXT, j0, INPUT, INPUT_LENGTH, OUTPUT);
    if (err != LIBERAC_SUCCESS && OUTPUT && INPUT_LENGTH != 0u)
        crypto_zeroize(OUTPUT, INPUT_LENGTH);

    crypto_zeroize(h, sizeof(h));
    crypto_zeroize(j0, sizeof(j0));
    crypto_zeroize(full_tag, sizeof(full_tag));
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

static LiberaCError ccm_mac_block(const AES_CONTEXT *ctx, uint8_t state[16], const uint8_t block[16]) {
    uint8_t x[16];
    xor_block(x, state, block);
    if (crypto_aes_encrypt_block(ctx, x, state) != LIBERAC_SUCCESS) {
        crypto_zeroize(x, sizeof(x));
        return LIBERAC_ERROR_INTERNAL;
    }
    crypto_zeroize(x, sizeof(x));
    return LIBERAC_SUCCESS;
}

static LiberaCError ccm_mac_bytes(const AES_CONTEXT *ctx, uint8_t state[16], const uint8_t *data, size_t length) {
    uint8_t block[16];
    while (length >= 16u) {
        LiberaCError err = ccm_mac_block(ctx, state, data);
        if (err != LIBERAC_SUCCESS) return err;
        data += 16u;
        length -= 16u;
    }
    if (length) {
        LiberaCError err;
        memset(block, 0, sizeof(block));
        memcpy(block, data, length);
        err = ccm_mac_block(ctx, state, block);
        crypto_zeroize(block, sizeof(block));
        return err;
    }
    return LIBERAC_SUCCESS;
}

static LiberaCError ccm_mac_aad(const AES_CONTEXT *ctx, uint8_t state[16], const uint8_t *aad, size_t aad_length) {
    uint8_t prefix[10], block[16];
    size_t prefix_length, chunk;
    LiberaCError err;
    if (aad_length == 0u) return LIBERAC_SUCCESS;
    if (aad_length < 0xff00u) {
        crypto_store16_be(prefix, (uint16_t)aad_length);
        prefix_length = 2u;
    } else if ((uint64_t)aad_length <= UINT32_MAX) {
        prefix[0] = 0xff; prefix[1] = 0xfe;
        crypto_store32_be(prefix + 2u, (uint32_t)aad_length);
        prefix_length = 6u;
    } else {
        uint64_t n = (uint64_t)aad_length;
        prefix[0] = 0xff; prefix[1] = 0xff;
        crypto_store64_be(prefix + 2u, n);
        prefix_length = 10u;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, prefix, prefix_length);
    chunk = 16u - prefix_length;
    if (chunk > aad_length) chunk = aad_length;
    memcpy(block + prefix_length, aad, chunk);
    err = ccm_mac_block(ctx, state, block);
    if (err != LIBERAC_SUCCESS) {
        crypto_zeroize(prefix, sizeof(prefix));
        crypto_zeroize(block, sizeof(block));
        return err;
    }
    aad += chunk;
    aad_length -= chunk;
    err = ccm_mac_bytes(ctx, state, aad, aad_length);
    crypto_zeroize(prefix, sizeof(prefix));
    crypto_zeroize(block, sizeof(block));
    return err;
}

static LiberaCError ccm_compute_mac(const AES_CONTEXT *ctx, const uint8_t *nonce, size_t nonce_length,
                                   const uint8_t *aad, size_t aad_length,
                                   const uint8_t *plaintext, size_t plaintext_length,
                                   size_t tag_length, uint8_t mac[16]) {
    uint8_t b0[16] = {0};
    size_t q = 15u - nonce_length;
    LiberaCError err;
    b0[0] = (uint8_t)((aad_length ? 0x40u : 0u) | (((tag_length - 2u) / 2u) << 3) | (q - 1u));
    memcpy(b0 + 1u, nonce, nonce_length);
    ccm_encode_length(b0 + 1u + nonce_length, q, plaintext_length);
    memset(mac, 0, 16u);
    err = ccm_mac_block(ctx, mac, b0);
    if (err == LIBERAC_SUCCESS) err = ccm_mac_aad(ctx, mac, aad, aad_length);
    if (err == LIBERAC_SUCCESS) err = ccm_mac_bytes(ctx, mac, plaintext, plaintext_length);
    crypto_zeroize(b0, sizeof(b0));
    return err;
}

static void ccm_counter_block(uint8_t counter[16], const uint8_t *nonce, size_t nonce_length, size_t value) {
    size_t q = 15u - nonce_length;
    memset(counter, 0, 16u);
    counter[0] = (uint8_t)(q - 1u);
    memcpy(counter + 1u, nonce, nonce_length);
    ccm_encode_length(counter + 1u + nonce_length, q, value);
}

static LiberaCError ccm_ctr(const AES_CONTEXT *ctx, const uint8_t *nonce, size_t nonce_length,
                           const uint8_t *input, size_t length, uint8_t *output) {
    uint8_t counter[16], stream[16];
    size_t block_index = 1u, offset = 0, chunk, i;
    while (offset < length) {
        ccm_counter_block(counter, nonce, nonce_length, block_index++);
        if (crypto_aes_encrypt_block(ctx, counter, stream) != LIBERAC_SUCCESS) {
            crypto_zeroize(counter, sizeof(counter));
            crypto_zeroize(stream, sizeof(stream));
            return LIBERAC_ERROR_INTERNAL;
        }
        chunk = length - offset;
        if (chunk > 16u) chunk = 16u;
        for (i = 0; i < chunk; ++i) output[offset + i] = (uint8_t)(input[offset + i] ^ stream[i]);
        offset += chunk;
    }
    crypto_zeroize(counter, sizeof(counter));
    crypto_zeroize(stream, sizeof(stream));
    return LIBERAC_SUCCESS;
}

static LiberaCError ccm_validate(const uint8_t *nonce, size_t nonce_length, size_t message_length, size_t tag_length) {
    size_t q;
    if (!nonce || nonce_length < 7u || nonce_length > 13u) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (tag_length < 4u || tag_length > 16u || (tag_length & 1u)) return LIBERAC_ERROR_INVALID_ARGUMENT;
    q = 15u - nonce_length;
    if (!ccm_length_fits(q, message_length)) return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_aes_ccm_encrypt(
    const AES_CONTEXT *CONTEXT,
    uint8_t *OUTPUT, uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH) {
    uint8_t mac[16];
    uint8_t ctr0[16];
    uint8_t s0[16];
    size_t i;
    LiberaCError err;

    if (!CONTEXT || (!AAD && AAD_LENGTH != 0u) ||
        (!INPUT && INPUT_LENGTH != 0u) ||
        (!OUTPUT && INPUT_LENGTH != 0u) || !TAG) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    err = ccm_validate(NONCE, NONCE_LENGTH, INPUT_LENGTH, TAG_LENGTH);
    if (err != LIBERAC_SUCCESS) return err;

    err = ccm_compute_mac(CONTEXT, NONCE, NONCE_LENGTH,
                          AAD, AAD_LENGTH, INPUT, INPUT_LENGTH,
                          TAG_LENGTH, mac);
    if (err == LIBERAC_SUCCESS) {
        err = ccm_ctr(CONTEXT, NONCE, NONCE_LENGTH,
                      INPUT, INPUT_LENGTH, OUTPUT);
    }
    ccm_counter_block(ctr0, NONCE, NONCE_LENGTH, 0u);
    if (err == LIBERAC_SUCCESS)
        err = crypto_aes_encrypt_block(CONTEXT, ctr0, s0);
    if (err == LIBERAC_SUCCESS) {
        for (i = 0; i < TAG_LENGTH; ++i) TAG[i] = (uint8_t)(mac[i] ^ s0[i]);
    }
    crypto_zeroize(mac, sizeof(mac));
    crypto_zeroize(ctr0, sizeof(ctr0));
    crypto_zeroize(s0, sizeof(s0));
    return err;
}

LiberaCError crypto_aes_ccm_decrypt(
    const AES_CONTEXT *CONTEXT,
    uint8_t *OUTPUT, const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH) {
    uint8_t mac[16];
    uint8_t ctr0[16];
    uint8_t s0[16];
    uint8_t expected[16] = {0};
    size_t i;
    LiberaCError err;

    if (!CONTEXT || (!AAD && AAD_LENGTH != 0u) ||
        (!INPUT && INPUT_LENGTH != 0u) || !TAG ||
        (!OUTPUT && INPUT_LENGTH != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    err = ccm_validate(NONCE, NONCE_LENGTH, INPUT_LENGTH, TAG_LENGTH);
    if (err != LIBERAC_SUCCESS) return err;

    err = ccm_ctr(CONTEXT, NONCE, NONCE_LENGTH,
                  INPUT, INPUT_LENGTH, OUTPUT);
    if (err == LIBERAC_SUCCESS) {
        err = ccm_compute_mac(CONTEXT, NONCE, NONCE_LENGTH,
                              AAD, AAD_LENGTH, OUTPUT, INPUT_LENGTH,
                              TAG_LENGTH, mac);
    }
    ccm_counter_block(ctr0, NONCE, NONCE_LENGTH, 0u);
    if (err == LIBERAC_SUCCESS)
        err = crypto_aes_encrypt_block(CONTEXT, ctr0, s0);
    if (err == LIBERAC_SUCCESS) {
        for (i = 0; i < TAG_LENGTH; ++i) expected[i] = (uint8_t)(mac[i] ^ s0[i]);
        if (!crypto_constant_time_equal(expected, TAG, TAG_LENGTH))
            err = LIBERAC_ERROR_AUTHENTICATION_FAILED;
    }
    if (err != LIBERAC_SUCCESS && OUTPUT && INPUT_LENGTH != 0u)
        crypto_zeroize(OUTPUT, INPUT_LENGTH);
    crypto_zeroize(mac, sizeof(mac));
    crypto_zeroize(ctr0, sizeof(ctr0));
    crypto_zeroize(s0, sizeof(s0));
    crypto_zeroize(expected, sizeof(expected));
    return err;
}
