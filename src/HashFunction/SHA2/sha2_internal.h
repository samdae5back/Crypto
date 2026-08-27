#ifndef CRYPTO_SHA2_INTERNAL_H
#define CRYPTO_SHA2_INTERNAL_H

#include "Def.h"

CryptoError crypto_sha2_hash(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    AlgID ALG);

#endif
