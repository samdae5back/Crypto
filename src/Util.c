#include "Util.h"

#include "Util/Bignum/bignum_internal.h"
#include "Util/Prime/prime_internal.h"

void CRYPTO_BIGNUM_INIT(CRYPTO_BIGNUM *value) {
    crypto_bignum_init(value);
}

void CRYPTO_BIGNUM_FREE(CRYPTO_BIGNUM *value) {
    crypto_bignum_free(value);
}

CryptoError CRYPTO_BIGNUM_FROM_BYTES_BE(CRYPTO_BIGNUM *output,
                                         const uint8_t *bytes, size_t length) {
    return crypto_bignum_from_bytes_be(output, bytes, length);
}

CryptoError CRYPTO_BIGNUM_FROM_BYTES_LE(CRYPTO_BIGNUM *output,
                                         const uint8_t *bytes, size_t length) {
    return crypto_bignum_from_bytes_le(output, bytes, length);
}

CryptoError CRYPTO_BIGNUM_TO_BYTES_BE(const CRYPTO_BIGNUM *input,
                                       uint8_t *output, size_t output_length) {
    return crypto_bignum_to_bytes_be(input, output, output_length);
}

CryptoError CRYPTO_BIGNUM_TO_BYTES_LE(const CRYPTO_BIGNUM *input,
                                       uint8_t *output, size_t output_length) {
    return crypto_bignum_to_bytes_le(input, output, output_length);
}

int CRYPTO_PRIME_IS_PROBABLE(const CRYPTO_BIGNUM *value, uint32_t rounds) {
    return crypto_prime_is_probable_internal(value, rounds);
}

CryptoError CRYPTO_PRIME_GENERATE(CRYPTO_BIGNUM *output,
                                   size_t bits, uint32_t rounds) {
    return crypto_prime_generate_internal(output, bits, rounds);
}

CryptoError CRYPTO_PRIME_GENERATE_SAFE(CRYPTO_BIGNUM *p, CRYPTO_BIGNUM *q,
                                        size_t p_bits, uint32_t rounds) {
    return crypto_prime_generate_safe_internal(p, q, p_bits, rounds);
}
