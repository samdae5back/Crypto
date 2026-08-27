/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_AES_INTERNAL_H
#define CRYPTO_AES_INTERNAL_H

#include "BlockCipher.h"

#define AES_BLOCK_SIZE 16u
#define AES_MAX_ROUND_KEY_BYTES 240u

/* AES is an implementation detail of the public BlockCipher dispatcher. */
typedef struct {
    uint8_t ROUND_KEYS[AES_MAX_ROUND_KEY_BYTES];
    uint8_t ROUNDS;
    uint8_t KEY_WORDS;
} AES_CONTEXT;

typedef enum {
    CRYPTO_AES_MODE_ECB = 1,
    CRYPTO_AES_MODE_CBC = 2,
    CRYPTO_AES_MODE_CTR = 3,
    CRYPTO_AES_MODE_CCM = 4,
    CRYPTO_AES_MODE_GCM = 5
} CryptoAesMode;

/* Private raw-block API used by the modes and by CTR_DRBG. */
LiberaCError crypto_aes_context_init(
    AES_CONTEXT *CONTEXT,
    const uint8_t *KEY, size_t KEY_LENGTH);
void crypto_aes_context_clear(AES_CONTEXT *CONTEXT);
LiberaCError crypto_aes_encrypt_block(
    const AES_CONTEXT *CONTEXT,
    const uint8_t INPUT[AES_BLOCK_SIZE],
    uint8_t OUTPUT[AES_BLOCK_SIZE]);
LiberaCError crypto_aes_decrypt_block(
    const AES_CONTEXT *CONTEXT,
    const uint8_t INPUT[AES_BLOCK_SIZE],
    uint8_t OUTPUT[AES_BLOCK_SIZE]);

/* Private mode-independent entrypoints used only by src/BlockCipher.c. */
LiberaCError crypto_aes_encrypt(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    size_t EXPECTED_KEY_LENGTH, CryptoAesMode MODE);

LiberaCError crypto_aes_decrypt(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    size_t EXPECTED_KEY_LENGTH, CryptoAesMode MODE);

/* Cross-translation-unit AEAD helpers. All are private library symbols. */
LiberaCError crypto_aes_gcm_encrypt(
    const AES_CONTEXT *CONTEXT,
    uint8_t *OUTPUT, uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH);
LiberaCError crypto_aes_gcm_decrypt(
    const AES_CONTEXT *CONTEXT,
    uint8_t *OUTPUT, const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH);
LiberaCError crypto_aes_ccm_encrypt(
    const AES_CONTEXT *CONTEXT,
    uint8_t *OUTPUT, uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH);
LiberaCError crypto_aes_ccm_decrypt(
    const AES_CONTEXT *CONTEXT,
    uint8_t *OUTPUT, const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH);

#endif
