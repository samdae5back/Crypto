#ifndef CRYPTO_RANDOM_H
#define CRYPTO_RANDOM_H
#include "TYPES.h"
#include "ERROR.h"
#include "CRYPTO_EXPORT.h"
CRYPTO_API CryptoError RANDOM_BYTES(uint8_t *OUT, size_t LENGTH);
#endif
