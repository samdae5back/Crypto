#ifndef CRYPTO_PUBLIC_NTT_H
#define CRYPTO_PUBLIC_NTT_H
#include "TYPES.h"
#include "ERROR.h"
#include "CRYPTO_EXPORT.h"
typedef struct { size_t N; uint32_t MODULUS; uint32_t ROOT; uint32_t ROOT_INV; uint32_t N_INV; } NTT_PLAN;
CRYPTO_API CryptoError NTT_PLAN_INIT(NTT_PLAN *PLAN, size_t N, uint32_t MODULUS, uint32_t PRIMITIVE_ROOT);
CRYPTO_API CryptoError NTT_FORWARD(const NTT_PLAN *PLAN, uint32_t *A);
CRYPTO_API CryptoError NTT_INVERSE(const NTT_PLAN *PLAN, uint32_t *A);
#endif
