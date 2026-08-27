/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef K_PKE_H
#define K_PKE_H

#include "Def.h"

LiberaCError K_PKE_KeyGen(const unsigned char *seed, unsigned char *public_key,
                         unsigned char *private_key);
LiberaCError K_PKE_Enc(const unsigned char *public_key,
                      const unsigned char *message,
                      const unsigned char *randomness,
                      unsigned char *ciphertext);
LiberaCError K_PKE_Dec(const unsigned char *private_key,
                      const unsigned char *ciphertext,
                      unsigned char *message);

#endif
