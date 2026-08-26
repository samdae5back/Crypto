#include "secure_zero.h"

void crypto_zeroize(void *TARGET, size_t LENGTH) {
    volatile uint8_t *target = (volatile uint8_t *)TARGET;
    if (!TARGET) return;
    while (LENGTH--) {
        *target++ = 0u;
    }
}
