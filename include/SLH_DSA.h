#ifndef CRYPTO_SLH_DSA_H
#define CRYPTO_SLH_DSA_H

#include "TYPES.h"
#include "ALGID.h"
#include "ERROR.h"
#include "CRYPTO_EXPORT.h"

#define SLH_DSA_CONTEXT_MAX_BYTES 255u

CRYPTO_API size_t SLH_DSA_PUBLIC_KEY_SIZE(AlgID ALG);
CRYPTO_API size_t SLH_DSA_PRIVATE_KEY_SIZE(AlgID ALG);
CRYPTO_API size_t SLH_DSA_SIGNATURE_SIZE(AlgID ALG);

CRYPTO_API CryptoError SLH_DSA_KEYGEN(
    AlgID ALG,
    uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
    uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH);

CRYPTO_API CryptoError SLH_DSA_SIGN(
    AlgID ALG,
    const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
    uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH);

CRYPTO_API CryptoError SLH_DSA_VERIFY(
    AlgID ALG,
    const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
    const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH);

#endif
