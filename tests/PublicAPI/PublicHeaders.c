/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Def.h"
#include "BlockCipher.h"
#include "HashFunction.h"
#include "RandomNumberGeneration.h"
#include "Util.h"
#include "AsymmetricCipher.h"
#include "KeyEncapsulation.h"
#include "DigitalSignature.h"
#include "LiberaCrypt.h"

int main(void) {
    LiberaCBignum value;
    LiberaCCtrDrbgContext drbg;
    LiberaCHashContext hash;
    LiberaCAlgID alg = LIBERAC_ALG_HASH_SHA2_256;
    LiberaCError error = LIBERAC_SUCCESS;

    (void)value;
    (void)drbg;
    (void)hash;
    (void)alg;
    (void)error;
    return 0;
}
