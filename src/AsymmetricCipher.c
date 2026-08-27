#include "AsymmetricCipher.h"

#include "AsymmetricCipher/ElGamal/elgamal_internal.h"
#include "AsymmetricCipher/RSA/rsa_internal.h"

void CRYPTO_RSA_PUBLIC_KEY_INIT(CRYPTO_RSA_PUBLIC_KEY *key) {
    crypto_rsa_public_key_init_internal(key);
}

void CRYPTO_RSA_PUBLIC_KEY_FREE(CRYPTO_RSA_PUBLIC_KEY *key) {
    crypto_rsa_public_key_free_internal(key);
}

void CRYPTO_RSA_PRIVATE_KEY_INIT(CRYPTO_RSA_PRIVATE_KEY *key) {
    crypto_rsa_private_key_init_internal(key);
}

void CRYPTO_RSA_PRIVATE_KEY_FREE(CRYPTO_RSA_PRIVATE_KEY *key) {
    crypto_rsa_private_key_free_internal(key);
}

CryptoError CRYPTO_RSA_KEYGEN(CRYPTO_RSA_PUBLIC_KEY *public_key,
                               CRYPTO_RSA_PRIVATE_KEY *private_key,
                               size_t modulus_bits, uint32_t prime_rounds,
                               AlgID alg) {
    return crypto_rsa_keygen_internal(alg, public_key, private_key,
                                      modulus_bits, prime_rounds);
}

CryptoError CRYPTO_RSA_ENCRYPT(CRYPTO_BIGNUM *ciphertext,
                                const CRYPTO_BIGNUM *message,
                                const CRYPTO_RSA_PUBLIC_KEY *public_key,
                                AlgID alg) {
    return crypto_rsa_encrypt_internal(alg, ciphertext, message, public_key);
}

CryptoError CRYPTO_RSA_DECRYPT(CRYPTO_BIGNUM *message,
                                const CRYPTO_BIGNUM *ciphertext,
                                const CRYPTO_RSA_PRIVATE_KEY *private_key,
                                AlgID alg) {
    return crypto_rsa_decrypt_internal(alg, message, ciphertext, private_key);
}

void CRYPTO_ELGAMAL_PUBLIC_KEY_INIT(CRYPTO_ELGAMAL_PUBLIC_KEY *key) {
    crypto_elgamal_public_key_init_internal(key);
}

void CRYPTO_ELGAMAL_PUBLIC_KEY_FREE(CRYPTO_ELGAMAL_PUBLIC_KEY *key) {
    crypto_elgamal_public_key_free_internal(key);
}

void CRYPTO_ELGAMAL_PRIVATE_KEY_INIT(CRYPTO_ELGAMAL_PRIVATE_KEY *key) {
    crypto_elgamal_private_key_init_internal(key);
}

void CRYPTO_ELGAMAL_PRIVATE_KEY_FREE(CRYPTO_ELGAMAL_PRIVATE_KEY *key) {
    crypto_elgamal_private_key_free_internal(key);
}

void CRYPTO_ELGAMAL_CIPHERTEXT_INIT(CRYPTO_ELGAMAL_CIPHERTEXT *ciphertext) {
    crypto_elgamal_ciphertext_init_internal(ciphertext);
}

void CRYPTO_ELGAMAL_CIPHERTEXT_FREE(CRYPTO_ELGAMAL_CIPHERTEXT *ciphertext) {
    crypto_elgamal_ciphertext_free_internal(ciphertext);
}

CryptoError CRYPTO_ELGAMAL_KEYGEN(CRYPTO_ELGAMAL_PUBLIC_KEY *public_key,
                                   CRYPTO_ELGAMAL_PRIVATE_KEY *private_key,
                                   size_t modulus_bits, uint32_t prime_rounds,
                                   AlgID alg) {
    return crypto_elgamal_keygen_internal(alg, public_key, private_key,
                                          modulus_bits, prime_rounds);
}

CryptoError CRYPTO_ELGAMAL_ENCRYPT(CRYPTO_ELGAMAL_CIPHERTEXT *ciphertext,
                                    const CRYPTO_BIGNUM *message,
                                    const CRYPTO_ELGAMAL_PUBLIC_KEY *public_key,
                                    AlgID alg) {
    return crypto_elgamal_encrypt_internal(alg, ciphertext, message, public_key);
}

CryptoError CRYPTO_ELGAMAL_DECRYPT(CRYPTO_BIGNUM *message,
                                    const CRYPTO_ELGAMAL_CIPHERTEXT *ciphertext,
                                    const CRYPTO_ELGAMAL_PUBLIC_KEY *public_key,
                                    const CRYPTO_ELGAMAL_PRIVATE_KEY *private_key,
                                    AlgID alg) {
    return crypto_elgamal_decrypt_internal(alg, message, ciphertext,
                                           public_key, private_key);
}
