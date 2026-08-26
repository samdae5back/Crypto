#ifndef CRYPTO_AES_INTERNAL_H
#define CRYPTO_AES_INTERNAL_H

#include "AES.h"

void aes_encrypt_block_internal(const AES_CONTEXT *ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);
void aes_decrypt_block_internal(const AES_CONTEXT *ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);

#endif
