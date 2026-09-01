/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBERAC_KEY_AGREEMENT_H
#define LIBERAC_KEY_AGREEMENT_H

/**
 * @file KeyAgreement.h
 * @brief Runtime-selected ECDH and X25519 key-agreement APIs.
 *
 * The NIST-curve ECDH variants use fixed-width big-endian private scalars and
 * SEC 1 encoded public keys. Key generation and public-key derivation emit
 * uncompressed SEC 1 public keys; shared-secret derivation accepts either
 * compressed or uncompressed SEC 1 public keys and returns the affine
 * x-coordinate as a fixed-width big-endian byte string.
 *
 * X25519 uses the RFC 7748 wire format: private inputs, public keys, and shared
 * secrets are all 32-byte strings, with public u-coordinates encoded little
 * endian. The scalar is clamped internally as required by X25519.
 *
 * @warning The result of LIBERAC_KEY_AGREEMENT_SHARED_SECRET() is raw key-
 *          agreement material. Feed it to a suitable KDF such as HKDF before
 *          using it as a symmetric key.
 *
 * @defgroup crypto_key_agreement Key-agreement API
 * @brief ECDH over NIST prime curves and X25519.
 * @{
 */

#include "Def.h"

/** @brief P-256 ECDH private-scalar length in bytes. */
#define LIBERAC_ECDH_P256_PRIVATE_KEY_BYTES 32u
/** @brief P-256 uncompressed SEC 1 public-key length in bytes. */
#define LIBERAC_ECDH_P256_PUBLIC_KEY_BYTES 65u
/** @brief P-256 raw ECDH shared-secret length in bytes. */
#define LIBERAC_ECDH_P256_SHARED_SECRET_BYTES 32u

/** @brief P-384 ECDH private-scalar length in bytes. */
#define LIBERAC_ECDH_P384_PRIVATE_KEY_BYTES 48u
/** @brief P-384 uncompressed SEC 1 public-key length in bytes. */
#define LIBERAC_ECDH_P384_PUBLIC_KEY_BYTES 97u
/** @brief P-384 raw ECDH shared-secret length in bytes. */
#define LIBERAC_ECDH_P384_SHARED_SECRET_BYTES 48u

/** @brief P-521 ECDH private-scalar length in bytes. */
#define LIBERAC_ECDH_P521_PRIVATE_KEY_BYTES 66u
/** @brief P-521 uncompressed SEC 1 public-key length in bytes. */
#define LIBERAC_ECDH_P521_PUBLIC_KEY_BYTES 133u
/** @brief P-521 raw ECDH shared-secret length in bytes. */
#define LIBERAC_ECDH_P521_SHARED_SECRET_BYTES 66u

/** @brief X25519 private-input length in bytes. */
#define LIBERAC_X25519_PRIVATE_KEY_BYTES 32u
/** @brief X25519 public-key length in bytes. */
#define LIBERAC_X25519_PUBLIC_KEY_BYTES 32u
/** @brief X25519 shared-secret length in bytes. */
#define LIBERAC_X25519_SHARED_SECRET_BYTES 32u

LIBERAC_BEGIN_DECLS

/**
 * @brief Return the private-key length for a key-agreement algorithm.
 * @param[in] ALG An LIBERAC_ALG_ECDH_* or LIBERAC_ALG_X25519 identifier.
 * @return Required private-key bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_KEY_AGREEMENT_PRIVATE_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the generated public-key length for a key-agreement algorithm.
 * @param[in] ALG An LIBERAC_ALG_ECDH_* or LIBERAC_ALG_X25519 identifier.
 * @return Required public-key bytes, or zero if ALG is unsupported.
 * @note ECDH key generation emits uncompressed SEC 1 points. Shared-secret
 *       derivation also accepts the corresponding compressed encoding.
 */
LIBERAC_API size_t LIBERAC_KEY_AGREEMENT_PUBLIC_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the raw shared-secret length for a key-agreement algorithm.
 * @param[in] ALG An LIBERAC_ALG_ECDH_* or LIBERAC_ALG_X25519 identifier.
 * @return Required shared-secret bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_KEY_AGREEMENT_SHARED_SECRET_SIZE(LiberaCAlgID ALG);

/**
 * @brief Generate a private key and its corresponding public key.
 * @param[out] PUBLIC_KEY Buffer receiving an uncompressed SEC 1 point for ECDH
 *                        or a 32-byte RFC 7748 u-coordinate for X25519.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY.
 * @param[out] PRIVATE_KEY Buffer receiving the fixed-width private input.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY.
 * @param[in] ALG Key-agreement algorithm identifier.
 * @retval LIBERAC_SUCCESS The key pair was generated successfully.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID ALG is unsupported.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer is null or the required
 *         output regions overlap.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL An output buffer is undersized.
 * @retval LIBERAC_ERROR_RANDOM_FAILED Operating-system randomness failed.
 * @note Validation failures leave the output buffers unchanged. Once
 *       validation succeeds, an operational failure clears the required output
 *       regions.
 */
LIBERAC_API LiberaCError LIBERAC_KEY_AGREEMENT_KEYGEN(
    uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
    uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Derive a public key from a supplied private input.
 * @param[out] PUBLIC_KEY Buffer receiving the canonical generated encoding.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY.
 * @param[in] PRIVATE_KEY Fixed-width ECDH scalar or 32-byte X25519 input.
 * @param[in] PRIVATE_KEY_LENGTH Exact private-input length.
 * @param[in] ALG Key-agreement algorithm identifier.
 * @retval LIBERAC_SUCCESS Public-key derivation succeeded.
 * @retval LIBERAC_ERROR_INVALID_KEY The ECDH scalar is not in 1 <= d < n.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer/length is invalid or the
 *         output overlaps the private input.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL PUBLIC_KEY is undersized.
 * @note X25519 clamps PRIVATE_KEY internally and therefore accepts every
 *       32-byte private input.
 */
LIBERAC_API LiberaCError LIBERAC_KEY_AGREEMENT_PUBLIC_FROM_PRIVATE(
    uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
    const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Derive raw shared-secret material from a peer public key.
 * @param[out] SHARED_SECRET Buffer receiving the raw shared secret.
 * @param[in] SHARED_SECRET_LENGTH Available bytes in SHARED_SECRET.
 * @param[in] PRIVATE_KEY Local fixed-width private input.
 * @param[in] PRIVATE_KEY_LENGTH Exact local private-input length.
 * @param[in] PEER_PUBLIC_KEY Peer SEC 1 point for ECDH or RFC 7748
 *                            u-coordinate for X25519.
 * @param[in] PEER_PUBLIC_KEY_LENGTH Exact peer-public-key encoding length.
 * @param[in] ALG Key-agreement algorithm identifier.
 * @retval LIBERAC_SUCCESS Shared-secret derivation succeeded.
 * @retval LIBERAC_ERROR_INVALID_KEY A private ECDH scalar or peer public key is
 *         invalid, or X25519 produced the all-zero shared secret.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer/length is invalid or the
 *         output overlaps an input region.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL SHARED_SECRET is undersized.
 * @note ECDH accepts compressed or uncompressed SEC 1 peer keys, but never the
 *       point at infinity. X25519 accepts the RFC 7748 non-canonical u-coordinate
 *       encodings and masks the high input bit as specified by that standard.
 */
LIBERAC_API LiberaCError LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
    uint8_t *SHARED_SECRET, size_t SHARED_SECRET_LENGTH,
    const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
    const uint8_t *PEER_PUBLIC_KEY, size_t PEER_PUBLIC_KEY_LENGTH,
    LiberaCAlgID ALG);

LIBERAC_END_DECLS

#endif

/** @} */
