/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef ML_KEM_H
#define ML_KEM_H

#include "Def.h"

LiberaCError ML_KEM_KeyGen_internal(const unsigned char seed[32],
                                   const unsigned char rejection_seed[32],
                                   unsigned char *public_key,
                                   unsigned char *private_key);
LiberaCError ML_KEM_Encaps_internal(const unsigned char *public_key,
                                   const unsigned char message[32],
                                   unsigned char shared_secret[32],
                                   unsigned char *ciphertext);
LiberaCError ML_KEM_Decaps_internal(const unsigned char *private_key,
                                   const unsigned char *ciphertext,
                                   unsigned char shared_secret[32]);

LiberaCError ML_KEM_KeyGen(unsigned char *public_key,
                          unsigned char *private_key);
LiberaCError ML_KEM_Encaps(const unsigned char *public_key,
                          unsigned char shared_secret[32],
                          unsigned char *ciphertext);
LiberaCError ML_KEM_Decaps(const unsigned char *private_key,
                          const unsigned char *ciphertext,
                          unsigned char shared_secret[32]);

#endif
