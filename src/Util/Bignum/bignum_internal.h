#ifndef crypto_bignum_internal_h
#define crypto_bignum_internal_h

#include "Util.h"

void crypto_bignum_init(CRYPTO_BIGNUM *value);
void crypto_bignum_free(CRYPTO_BIGNUM *value);
CryptoError crypto_bignum_copy(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *in);
CryptoError crypto_bignum_set_u64(CRYPTO_BIGNUM *out, uint64_t value);
CryptoError crypto_bignum_from_bytes_be(CRYPTO_BIGNUM *out, const uint8_t *bytes, size_t length);
CryptoError crypto_bignum_from_bytes_le(CRYPTO_BIGNUM *out, const uint8_t *bytes, size_t length);
CryptoError crypto_bignum_to_bytes_be(const CRYPTO_BIGNUM *in, uint8_t *out, size_t out_length);
CryptoError crypto_bignum_to_bytes_le(const CRYPTO_BIGNUM *in, uint8_t *out, size_t out_length);
size_t crypto_bignum_byte_length(const CRYPTO_BIGNUM *value);
size_t crypto_bignum_bit_length(const CRYPTO_BIGNUM *value);
int crypto_bignum_compare(const CRYPTO_BIGNUM *a, const CRYPTO_BIGNUM *b);
int crypto_bignum_is_zero(const CRYPTO_BIGNUM *value);
CryptoError crypto_bignum_add(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, const CRYPTO_BIGNUM *b);
CryptoError crypto_bignum_sub(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, const CRYPTO_BIGNUM *b);
CryptoError crypto_bignum_mul(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, const CRYPTO_BIGNUM *b);
CryptoError crypto_bignum_mod(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, const CRYPTO_BIGNUM *modulus);
CryptoError crypto_bignum_mod_mul(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a,
                                   const CRYPTO_BIGNUM *b, const CRYPTO_BIGNUM *modulus);
CryptoError crypto_bignum_mod_exp(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *base,
                                   const CRYPTO_BIGNUM *exponent, const CRYPTO_BIGNUM *modulus);
CryptoError crypto_bignum_random_bits(CRYPTO_BIGNUM *out, size_t bits, int set_top_bit, int set_odd);
CryptoError crypto_bignum_random_range(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *upper_exclusive);

int bignum_reserve(CRYPTO_BIGNUM *a, size_t capacity);
void bignum_normalize(CRYPTO_BIGNUM *a);
int bignum_get_bit(const CRYPTO_BIGNUM *a, size_t bit);
int bignum_shift_left_one(CRYPTO_BIGNUM *a);
int bignum_add_u32(CRYPTO_BIGNUM *a, uint32_t v);
int bignum_mul_u32(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, uint32_t v);
uint32_t bignum_mod_u32(const CRYPTO_BIGNUM *a, uint32_t v);
int bignum_div_u32(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, uint32_t v, uint32_t *remainder);
int bignum_sub_u32(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, uint32_t v);
int bignum_add_u32_copy(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, uint32_t v);

#endif
