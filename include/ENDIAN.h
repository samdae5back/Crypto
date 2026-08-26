#ifndef CRYPTO_ENDIAN_H
#define CRYPTO_ENDIAN_H
#include "TYPES.h"
#include "CRYPTO_EXPORT.h"
uint16_t CRYPTO_ENDIAN_LOAD16_LE(const uint8_t *P);
uint32_t CRYPTO_ENDIAN_LOAD32_LE(const uint8_t *P);
uint64_t CRYPTO_ENDIAN_LOAD64_LE(const uint8_t *P);
uint16_t CRYPTO_ENDIAN_LOAD16_BE(const uint8_t *P);
uint32_t CRYPTO_ENDIAN_LOAD32_BE(const uint8_t *P);
uint64_t CRYPTO_ENDIAN_LOAD64_BE(const uint8_t *P);
void CRYPTO_ENDIAN_STORE16_LE(uint8_t *P, uint16_t X);
void CRYPTO_ENDIAN_STORE32_LE(uint8_t *P, uint32_t X);
void CRYPTO_ENDIAN_STORE64_LE(uint8_t *P, uint64_t X);
void CRYPTO_ENDIAN_STORE16_BE(uint8_t *P, uint16_t X);
void CRYPTO_ENDIAN_STORE32_BE(uint8_t *P, uint32_t X);
void CRYPTO_ENDIAN_STORE64_BE(uint8_t *P, uint64_t X);
#endif
