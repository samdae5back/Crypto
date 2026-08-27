/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file Crypto.h
 * @brief Umbrella header for the complete public Crypto C API.
 *
 * Include this header to use every supported API family.  Applications that
 * need a smaller declaration surface may instead include an individual public
 * header such as BlockCipher.h or HashFunction.h.
 *
 * @mainpage Crypto C API
 *
 * The library exposes one operation-oriented API per cryptographic family.
 * Algorithms and parameter sets are selected at runtime with an AlgID passed
 * as the final function argument.  Public functions are prefixed with
 * @c CRYPTO_, and failures are reported using CryptoError status codes.
 *
 * @section crypto_quick_start Quick start
 * @code{.c}
 * #include <Crypto.h>
 *
 * uint8_t digest[CRYPTO_SHA2_256_DIGEST_BYTES];
 * CryptoError error = CRYPTO_HASH(
 *     digest, sizeof(digest), message, message_length,
 *     ALG_HASH_SHA2_256);
 * @endcode
 *
 * See each family header for buffer ownership, parameter-set sizes, and
 * algorithm-specific constraints.  The library does not allocate byte-array
 * output buffers on behalf of the caller; managed bignum and asymmetric-key
 * objects allocate their internal storage as needed.
 */
#ifndef CRYPTO_H
#define CRYPTO_H

#include "Def.h"
#include "BlockCipher.h"
#include "HashFunction.h"
#include "RandomNumberGeneration.h"
#include "Util.h"
#include "AsymmetricCipher.h"
#include "KeyEncapsulation.h"
#include "DigitalSignature.h"

#endif
