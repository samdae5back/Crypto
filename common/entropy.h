#ifndef CRYPTO_ENTROPY_H
#define CRYPTO_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

int crypto_entropy_get(uint8_t *out, size_t out_len);

#endif
