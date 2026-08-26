#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H
#include "TYPES.h"
#include "ALGID.h"
#include "ERROR.h"
#include "CRYPTO_EXPORT.h"
CRYPTO_API CryptoError CRYPTO_HASH(AlgID ALG, const uint8_t *INPUT, size_t INPUT_LENGTH, uint8_t *OUTPUT, size_t OUTPUT_LENGTH);
CRYPTO_API size_t CRYPTO_HASH_OUTPUT_SIZE(AlgID ALG);
#endif
