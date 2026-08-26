#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include "TYPES.h"
#include "ALGID.h"
#include "ERROR.h"
#include "CRYPTO_EXPORT.h"

#define AES_BLOCK_SIZE 16u
#define AES_MAX_ROUND_KEY_BYTES 240u

typedef struct {
    uint8_t ROUND_KEYS[AES_MAX_ROUND_KEY_BYTES];
    uint8_t ROUNDS;
    uint8_t KEY_WORDS;
} AES_CONTEXT;

CRYPTO_API size_t AES_KEY_SIZE(AlgID ALG);
CRYPTO_API CryptoError AES_CONTEXT_INIT(AES_CONTEXT *CONTEXT, AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH);
CRYPTO_API void AES_CONTEXT_CLEAR(AES_CONTEXT *CONTEXT);
CRYPTO_API CryptoError AES_ENCRYPT_BLOCK(const AES_CONTEXT *CONTEXT, const uint8_t INPUT[AES_BLOCK_SIZE], uint8_t OUTPUT[AES_BLOCK_SIZE]);
CRYPTO_API CryptoError AES_DECRYPT_BLOCK(const AES_CONTEXT *CONTEXT, const uint8_t INPUT[AES_BLOCK_SIZE], uint8_t OUTPUT[AES_BLOCK_SIZE]);

CRYPTO_API CryptoError AES_ECB_ENCRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                                       const uint8_t *INPUT, size_t INPUT_LENGTH,
                                       uint8_t *OUTPUT, size_t OUTPUT_LENGTH);
CRYPTO_API CryptoError AES_ECB_DECRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                                       const uint8_t *INPUT, size_t INPUT_LENGTH,
                                       uint8_t *OUTPUT, size_t OUTPUT_LENGTH);
CRYPTO_API CryptoError AES_CBC_ENCRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                                       const uint8_t IV[AES_BLOCK_SIZE],
                                       const uint8_t *INPUT, size_t INPUT_LENGTH,
                                       uint8_t *OUTPUT, size_t OUTPUT_LENGTH);
CRYPTO_API CryptoError AES_CBC_DECRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                                       const uint8_t IV[AES_BLOCK_SIZE],
                                       const uint8_t *INPUT, size_t INPUT_LENGTH,
                                       uint8_t *OUTPUT, size_t OUTPUT_LENGTH);
CRYPTO_API CryptoError AES_CTR_CRYPT(AlgID ALG, const uint8_t *KEY, size_t KEY_LENGTH,
                                     const uint8_t INITIAL_COUNTER[AES_BLOCK_SIZE],
                                     const uint8_t *INPUT, size_t INPUT_LENGTH,
                                     uint8_t *OUTPUT, size_t OUTPUT_LENGTH);

#endif
