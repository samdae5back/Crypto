#ifndef CRYPTO_RANDOM_INTERNAL_H
#define CRYPTO_RANDOM_INTERNAL_H
#include "Util/Core/crypto_types.h"
int random_os_bytes(uint8_t *out, size_t length);
#endif
