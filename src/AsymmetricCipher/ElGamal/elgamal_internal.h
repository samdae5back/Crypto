#ifndef CRYPTO_ELGAMAL_INTERNAL_H
#define CRYPTO_ELGAMAL_INTERNAL_H

#include "AsymmetricCipher.h"

CryptoError elgamal_random_nonzero(CRYPTO_BIGNUM *out,
                                    const CRYPTO_BIGNUM *upper);
void crypto_elgamal_public_key_init_internal(CRYPTO_ELGAMAL_PUBLIC_KEY *key);
void crypto_elgamal_public_key_free_internal(CRYPTO_ELGAMAL_PUBLIC_KEY *key);
void crypto_elgamal_private_key_init_internal(CRYPTO_ELGAMAL_PRIVATE_KEY *key);
void crypto_elgamal_private_key_free_internal(CRYPTO_ELGAMAL_PRIVATE_KEY *key);
void crypto_elgamal_ciphertext_init_internal(CRYPTO_ELGAMAL_CIPHERTEXT *ciphertext);
void crypto_elgamal_ciphertext_free_internal(CRYPTO_ELGAMAL_CIPHERTEXT *ciphertext);
CryptoError crypto_elgamal_keygen_internal(AlgID alg,
                                            CRYPTO_ELGAMAL_PUBLIC_KEY *public_key,
                                            CRYPTO_ELGAMAL_PRIVATE_KEY *private_key,
                                            size_t modulus_bits, uint32_t prime_rounds);
CryptoError crypto_elgamal_encrypt_internal(AlgID alg,
                                             CRYPTO_ELGAMAL_CIPHERTEXT *ciphertext,
                                             const CRYPTO_BIGNUM *message,
                                             const CRYPTO_ELGAMAL_PUBLIC_KEY *public_key);
CryptoError crypto_elgamal_decrypt_internal(AlgID alg, CRYPTO_BIGNUM *message,
                                             const CRYPTO_ELGAMAL_CIPHERTEXT *ciphertext,
                                             const CRYPTO_ELGAMAL_PUBLIC_KEY *public_key,
                                             const CRYPTO_ELGAMAL_PRIVATE_KEY *private_key);

#endif
