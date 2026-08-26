#ifndef CRYPTO_NTT_H
#define CRYPTO_NTT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t n;
    uint32_t modulus;
    uint32_t root;
    uint32_t root_inv;
    uint32_t n_inv;
} crypto_ntt_plan;

int crypto_ntt_plan_init(crypto_ntt_plan *plan, size_t n, uint32_t modulus, uint32_t primitive_root);
int crypto_ntt_forward(const crypto_ntt_plan *plan, uint32_t *a);
int crypto_ntt_inverse(const crypto_ntt_plan *plan, uint32_t *a);

#endif
