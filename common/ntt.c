#include "ntt.h"

static uint32_t mod_pow(uint32_t a, uint64_t e, uint32_t q) {
    uint64_t r = 1;
    uint64_t x = a % q;
    while (e) {
        if (e & 1u) {
            r = (r * x) % q;
        }
        x = (x * x) % q;
        e >>= 1;
    }
    return (uint32_t)r;
}

static uint32_t mod_inv(uint32_t a, uint32_t q) {
    return mod_pow(a, (uint64_t)q - 2u, q);
}

static int is_power_of_two(size_t n) {
    return n && !(n & (n - 1u));
}

static void bit_reverse_permute(uint32_t *a, size_t n) {
    size_t i, j = 0;
    for (i = 1; i < n; ++i) {
        size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) {
            j ^= bit;
        }
        j ^= bit;
        if (i < j) {
            uint32_t t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }
}

int crypto_ntt_plan_init(crypto_ntt_plan *plan, size_t n, uint32_t modulus, uint32_t primitive_root) {
    uint32_t root;

    if (!plan || !is_power_of_two(n) || modulus < 3u || ((uint64_t)modulus - 1u) % n) {
        return -1;
    }

    root = mod_pow(primitive_root, ((uint64_t)modulus - 1u) / n, modulus);
    if (mod_pow(root, n, modulus) != 1u || (n > 1u && mod_pow(root, n / 2u, modulus) == 1u)) {
        return -1;
    }

    plan->n = n;
    plan->modulus = modulus;
    plan->root = root;
    plan->root_inv = mod_inv(root, modulus);
    plan->n_inv = mod_inv((uint32_t)(n % modulus), modulus);
    return 0;
}

static int transform(const crypto_ntt_plan *plan, uint32_t *a, uint32_t root) {
    uint32_t q;
    size_t len;

    if (!plan || !a) {
        return -1;
    }

    q = plan->modulus;
    bit_reverse_permute(a, plan->n);

    for (len = 2; len <= plan->n; len <<= 1) {
        uint32_t wlen = mod_pow(root, plan->n / len, q);
        size_t i;
        for (i = 0; i < plan->n; i += len) {
            uint32_t w = 1;
            size_t j;
            for (j = 0; j < len / 2; ++j) {
                uint32_t u = a[i + j] % q;
                uint32_t v = (uint32_t)(((uint64_t)a[i + j + len / 2] * w) % q);
                a[i + j] = (u + v >= q) ? (u + v - q) : (u + v);
                a[i + j + len / 2] = (u >= v) ? (u - v) : (u + q - v);
                w = (uint32_t)(((uint64_t)w * wlen) % q);
            }
        }
        if (len == plan->n) {
            break;
        }
    }

    return 0;
}

int crypto_ntt_forward(const crypto_ntt_plan *plan, uint32_t *a) {
    return transform(plan, a, plan->root);
}

int crypto_ntt_inverse(const crypto_ntt_plan *plan, uint32_t *a) {
    size_t i;

    if (transform(plan, a, plan->root_inv) != 0) {
        return -1;
    }
    for (i = 0; i < plan->n; ++i) {
        a[i] = (uint32_t)(((uint64_t)a[i] * plan->n_inv) % plan->modulus);
    }
    return 0;
}
