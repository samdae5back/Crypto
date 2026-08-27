#ifndef CRYPTO_BIT_INTERNAL_H
#define CRYPTO_BIT_INTERNAL_H

#include "Def.h"

static inline uint32_t crypto_rotl32(uint32_t value, unsigned int count) {
    count &= 31u;
    return (value << count) | (value >> ((32u - count) & 31u));
}

static inline uint64_t crypto_rotl64(uint64_t value, unsigned int count) {
    count &= 63u;
    return (value << count) | (value >> ((64u - count) & 63u));
}

static inline uint32_t crypto_rotr32(uint32_t value, unsigned int count) {
    count &= 31u;
    return (value >> count) | (value << ((32u - count) & 31u));
}

static inline uint64_t crypto_rotr64(uint64_t value, unsigned int count) {
    count &= 63u;
    return (value >> count) | (value << ((64u - count) & 63u));
}

#endif
