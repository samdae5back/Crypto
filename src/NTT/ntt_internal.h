#ifndef CRYPTO_NTT_INTERNAL_H
#define CRYPTO_NTT_INTERNAL_H
#include <stdint.h>
uint32_t ntt_mod_pow(uint32_t a, uint64_t e, uint32_t q);
#endif
