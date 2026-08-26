#ifndef CRYPTO_ENDIAN_H
#define CRYPTO_ENDIAN_H

#include <stdint.h>

static inline uint16_t crypto_load16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static inline uint32_t crypto_load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t crypto_load64_le(const uint8_t *p) {
    return (uint64_t)crypto_load32_le(p) | ((uint64_t)crypto_load32_le(p + 4) << 32);
}
static inline uint16_t crypto_load16_be(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static inline uint32_t crypto_load32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline uint64_t crypto_load64_be(const uint8_t *p) {
    return ((uint64_t)crypto_load32_be(p) << 32) | (uint64_t)crypto_load32_be(p + 4);
}
static inline void crypto_store16_le(uint8_t *p, uint16_t x) {
    p[0] = (uint8_t)x; p[1] = (uint8_t)(x >> 8);
}
static inline void crypto_store32_le(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x; p[1] = (uint8_t)(x >> 8); p[2] = (uint8_t)(x >> 16); p[3] = (uint8_t)(x >> 24);
}
static inline void crypto_store64_le(uint8_t *p, uint64_t x) {
    crypto_store32_le(p, (uint32_t)x); crypto_store32_le(p + 4, (uint32_t)(x >> 32));
}
static inline void crypto_store16_be(uint8_t *p, uint16_t x) {
    p[0] = (uint8_t)(x >> 8); p[1] = (uint8_t)x;
}
static inline void crypto_store32_be(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24); p[1] = (uint8_t)(x >> 16); p[2] = (uint8_t)(x >> 8); p[3] = (uint8_t)x;
}
static inline void crypto_store64_be(uint8_t *p, uint64_t x) {
    crypto_store32_be(p, (uint32_t)(x >> 32)); crypto_store32_be(p + 4, (uint32_t)x);
}

#endif
