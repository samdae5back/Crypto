#ifndef CRYPTO_RANDOM_H
#define CRYPTO_RANDOM_H

#include <stddef.h>
#include <stdint.h>

int crypto_random_bytes(uint8_t *out, size_t out_len);

#endif
