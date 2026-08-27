#ifndef CRYPTO_RANDOM_INTERNAL_H
#define CRYPTO_RANDOM_INTERNAL_H
#include "Def.h"

int random_os_bytes(uint8_t *out, size_t length);
CryptoError crypto_random_bytes_internal(uint8_t *out, size_t length);
#endif
