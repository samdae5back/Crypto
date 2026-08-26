#include "random.h"
#include "entropy.h"

int crypto_random_bytes(uint8_t *out, size_t out_len) {
    return crypto_entropy_get(out, out_len);
}
