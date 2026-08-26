#ifndef CRYPTO_ELGAMAL_INTERNAL_H
#define CRYPTO_ELGAMAL_INTERNAL_H
#include "BIGNUM.h"
int elgamal_random_nonzero(BIGNUM *out, const BIGNUM *upper);
#endif
