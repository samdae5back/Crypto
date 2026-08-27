#ifndef CRYPTO_NTT_INTERNAL_H
#define CRYPTO_NTT_INTERNAL_H
#include "Def.h"

typedef struct {
    size_t N;
    uint32_t MODULUS;
    uint32_t ROOT;
    uint32_t ROOT_INV;
    uint32_t N_INV;
} NTT_PLAN;

uint32_t ntt_mod_pow(uint32_t a, uint64_t e, uint32_t q);
int crypto_ntt_plan_init(NTT_PLAN *plan, size_t n, uint32_t modulus, uint32_t primitive_root);
int crypto_ntt_forward(const NTT_PLAN *plan, uint32_t *values);
int crypto_ntt_inverse(const NTT_PLAN *plan, uint32_t *values);
#endif
