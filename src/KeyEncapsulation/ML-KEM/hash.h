/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef ML_KEM_HASH_H
#define ML_KEM_HASH_H
#include <stddef.h>
#include "Def.h"
#include "HashFunction/SHA3/sha3_internal.h"
typedef crypto_sha3_context crypto_sha3_ctx;
CryptoError RBG(unsigned char *seed, size_t length);
int PRF(size_t eta, const unsigned char *seed, unsigned char nonce,
        unsigned char *output);
void H(const unsigned char *input,size_t input_length,unsigned char *output);
void J(const unsigned char *input,size_t input_length,unsigned char *output);
void G(const unsigned char *input,size_t input_length,unsigned char *output_1,unsigned char *output_2);
void XOF_init(crypto_sha3_ctx *ctx);
void XOF_absorb(crypto_sha3_ctx *ctx,const unsigned char *input,size_t input_length);
int XOF_squeeze(crypto_sha3_ctx *ctx,unsigned char *output,size_t length);
void XOF_clear(crypto_sha3_ctx *ctx);
#endif
