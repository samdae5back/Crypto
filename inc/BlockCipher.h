#ifndef CRYPTO_BLOCK_CIPHER_H
#define CRYPTO_BLOCK_CIPHER_H

#include "Def.h"

#define CRYPTO_BLOCK_CIPHER_BLOCK_BYTES 16u
#define CRYPTO_BLOCK_CIPHER_MAX_TAG_BYTES 16u
#define CRYPTO_AES_128_KEY_BYTES 16u
#define CRYPTO_AES_192_KEY_BYTES 24u
#define CRYPTO_AES_256_KEY_BYTES 32u

CRYPTO_BEGIN_DECLS

CRYPTO_API size_t CRYPTO_BLOCK_CIPHER_KEY_SIZE(AlgID ALG);

CRYPTO_API CryptoError CRYPTO_BLOCK_CIPHER_ENCRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    AlgID ALG);

CRYPTO_API CryptoError CRYPTO_BLOCK_CIPHER_DECRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    AlgID ALG);

CRYPTO_END_DECLS
#endif
