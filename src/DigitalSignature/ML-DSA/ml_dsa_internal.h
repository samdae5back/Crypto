#ifndef CRYPTO_ML_DSA_INTERNAL_H
#define CRYPTO_ML_DSA_INTERNAL_H

#include "DigitalSignature.h"

#define ML_DSA_44_PUBLIC_KEY_BYTES 1312u
#define ML_DSA_44_PRIVATE_KEY_BYTES 2560u
#define ML_DSA_44_SIGNATURE_BYTES 2420u
#define ML_DSA_65_PUBLIC_KEY_BYTES 1952u
#define ML_DSA_65_PRIVATE_KEY_BYTES 4032u
#define ML_DSA_65_SIGNATURE_BYTES 3309u
#define ML_DSA_87_PUBLIC_KEY_BYTES 2592u
#define ML_DSA_87_PRIVATE_KEY_BYTES 4896u
#define ML_DSA_87_SIGNATURE_BYTES 4627u

size_t crypto_ml_dsa_public_key_size_internal(AlgID alg);
size_t crypto_ml_dsa_private_key_size_internal(AlgID alg);
size_t crypto_ml_dsa_signature_size_internal(AlgID alg);
CryptoError crypto_ml_dsa_keygen_internal(
    AlgID alg, uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length);
CryptoError crypto_ml_dsa_sign_internal(
    AlgID alg, const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length);
CryptoError crypto_ml_dsa_verify_internal(
    AlgID alg, const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length);

#endif
