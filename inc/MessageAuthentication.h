/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file MessageAuthentication.h
 * @brief Runtime-selected HMAC, CMAC, GMAC, and Poly1305 API.
 *
 * @defgroup crypto_message_authentication Message-authentication API
 * @brief One-shot generation and constant-time verification of HMAC, CMAC,
 *        GMAC, and Poly1305 tags.
 *
 * The selected primitive is identified with an existing hash or block-cipher
 * LiberaCAlgID:
 *
 * - HMAC accepts SHA-1, every fixed-output SHA-2 identifier, and every
 *   fixed-output SHA-3 identifier. SHAKE and LSH identifiers are rejected.
 * - CMAC accepts AES-128/192/256 ECB and three-key Triple-DES EDE ECB.
 * - GMAC accepts AES-128/192/256 GCM.
 * - Poly1305 accepts its dedicated identifier and an exactly 32-byte one-time
 *   key. Its complete 16-byte tag is always produced and required.
 *
 * Tag lengths are expressed in bytes. HMAC and CMAC permit a non-empty prefix
 * of the full tag; applications must choose a length appropriate for their
 * protocol and security target. GMAC accepts the same tag lengths as the GCM
 * block-cipher API: 4, 8, and 12 through 16 bytes.
 *
 * Triple-DES CMAC is provided only for compatibility with legacy systems. New
 * designs should use AES-CMAC, AES-GMAC, or an HMAC construction with a modern
 * fixed-output hash. A GMAC IV must never be reused with the same key.
 * @{
 */
#ifndef LIBERAC_MESSAGE_AUTHENTICATION_H
#define LIBERAC_MESSAGE_AUTHENTICATION_H

#include "Def.h"

/** Maximum full HMAC tag size among the supported hash algorithms. */
#define LIBERAC_HMAC_MAX_TAG_BYTES 64u
/** Maximum full CMAC tag size among the supported block ciphers. */
#define LIBERAC_CMAC_MAX_TAG_BYTES 16u
/** Maximum full GMAC tag size. */
#define LIBERAC_GMAC_MAX_TAG_BYTES 16u
/** Poly1305 one-time-key size, in bytes. */
#define LIBERAC_POLY1305_KEY_BYTES 32u
/** Complete Poly1305 tag size, in bytes. */
#define LIBERAC_POLY1305_TAG_BYTES 16u

LIBERAC_BEGIN_DECLS

/**
 * @brief Return the full HMAC tag size for a supported hash identifier.
 *
 * @param[in] ALG A supported fixed-output SHA-1, SHA-2, or SHA-3 identifier.
 * @return Full HMAC tag size in bytes, or zero when @p ALG is not accepted by
 *         HMAC.
 */
LIBERAC_API size_t LIBERAC_HMAC_TAG_SIZE(LiberaCAlgID ALG);

/**
 * @brief Compute an HMAC tag with a runtime-selected fixed-output hash.
 *
 * @param[out] TAG Destination for the requested tag prefix.
 * @param[in]  TAG_CAPACITY Size of @p TAG in bytes.
 * @param[in]  TAG_LENGTH Requested tag length in bytes; it must be between one
 *                        byte and LIBERAC_HMAC_TAG_SIZE(@p ALG), inclusive.
 * @param[in]  MESSAGE Message to authenticate. It may be NULL only when
 *                     @p MESSAGE_LENGTH is zero.
 * @param[in]  MESSAGE_LENGTH Message length in bytes.
 * @param[in]  KEY Secret HMAC key. It may be NULL only when @p KEY_LENGTH is
 *                 zero; applications should use a suitably strong non-empty
 *                 key generated or derived for HMAC.
 * @param[in]  KEY_LENGTH Key length in bytes.
 * @param[in]  ALG SHA-1, a fixed-output SHA-2 identifier, or a fixed-output
 *                 SHA-3 identifier.
 *
 * @retval LIBERAC_SUCCESS The requested tag was produced.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not accepted by HMAC.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer or tag length is invalid.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p TAG_CAPACITY is too small.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE A selected hash length limit was
 *         exceeded.
 */
LIBERAC_API LiberaCError LIBERAC_HMAC(
    uint8_t *TAG, size_t TAG_CAPACITY, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Verify an HMAC tag in constant time with respect to tag contents.
 *
 * Parameters have the same meaning and constraints as LIBERAC_HMAC(), except
 * that @p TAG is the tag to verify and no output capacity is required.
 *
 * @retval LIBERAC_SUCCESS The tag is valid.
 * @retval LIBERAC_ERROR_AUTHENTICATION_FAILED The tag does not match.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not accepted by HMAC.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer or tag length is invalid.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE A selected hash length limit was
 *         exceeded.
 */
LIBERAC_API LiberaCError LIBERAC_HMAC_VERIFY(
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Return the full CMAC tag size for a supported block-cipher identifier.
 *
 * AES ECB identifiers return 16 and three-key Triple-DES EDE ECB returns 8.
 * Other modes and algorithms return zero.
 *
 * @param[in] ALG AES-128/192/256 ECB or three-key Triple-DES EDE ECB.
 * @return Full CMAC tag size in bytes, or zero when @p ALG is not accepted by
 *         CMAC.
 */
LIBERAC_API size_t LIBERAC_CMAC_TAG_SIZE(LiberaCAlgID ALG);

/**
 * @brief Compute a CMAC tag with runtime-selected AES or three-key Triple-DES.
 *
 * @param[out] TAG Destination for the requested tag prefix.
 * @param[in]  TAG_CAPACITY Size of @p TAG in bytes.
 * @param[in]  TAG_LENGTH Requested tag length in bytes; it must be between one
 *                        byte and LIBERAC_CMAC_TAG_SIZE(@p ALG), inclusive.
 * @param[in]  MESSAGE Message to authenticate. It may be NULL only when
 *                     @p MESSAGE_LENGTH is zero.
 * @param[in]  MESSAGE_LENGTH Message length in bytes.
 * @param[in]  KEY Master key for the selected block cipher.
 * @param[in]  KEY_LENGTH Key size in bytes; it must match @p ALG exactly.
 * @param[in]  ALG AES-128/192/256 ECB or three-key Triple-DES EDE ECB.
 *
 * @retval LIBERAC_SUCCESS The requested tag was produced.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not accepted by CMAC.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer or tag length is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH does not match @p ALG.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p TAG_CAPACITY is too small.
 */
LIBERAC_API LiberaCError LIBERAC_CMAC(
    uint8_t *TAG, size_t TAG_CAPACITY, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Verify a CMAC tag in constant time with respect to tag contents.
 *
 * Parameters have the same meaning and constraints as LIBERAC_CMAC(), except
 * that @p TAG is the tag to verify and no output capacity is required.
 *
 * @retval LIBERAC_SUCCESS The tag is valid.
 * @retval LIBERAC_ERROR_AUTHENTICATION_FAILED The tag does not match.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not accepted by CMAC.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer or tag length is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH does not match @p ALG.
 */
LIBERAC_API LiberaCError LIBERAC_CMAC_VERIFY(
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Return the Poly1305 tag size for its algorithm identifier.
 *
 * @param[in] ALG LIBERAC_ALG_POLY1305.
 * @return 16 for LIBERAC_ALG_POLY1305, otherwise zero.
 */
LIBERAC_API size_t LIBERAC_POLY1305_TAG_SIZE(LiberaCAlgID ALG);

/**
 * @brief Compute a complete Poly1305 tag with a one-time key.
 *
 * A Poly1305 key must be uniformly generated for one message only. Reusing the
 * same key for another message destroys the authenticator's security. Protocols
 * should normally use a standardized key-generation construction such as
 * ChaCha20-Poly1305 instead of managing one-time keys directly.
 *
 * @param[out] TAG Destination for the complete 16-byte tag.
 * @param[in]  TAG_CAPACITY Size of @p TAG in bytes.
 * @param[in]  MESSAGE Message, or NULL when @p MESSAGE_LENGTH is zero.
 * @param[in]  MESSAGE_LENGTH Message length in bytes.
 * @param[in]  KEY Exactly 32 bytes of one-time key material.
 * @param[in]  KEY_LENGTH Size of @p KEY in bytes.
 * @param[in]  ALG LIBERAC_ALG_POLY1305.
 *
 * @retval LIBERAC_SUCCESS The tag was produced.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not Poly1305.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A required pointer is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH is not 32 bytes.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p TAG_CAPACITY is less than 16.
 */
LIBERAC_API LiberaCError LIBERAC_POLY1305(
    uint8_t *TAG, size_t TAG_CAPACITY,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Verify a complete Poly1305 tag in constant time.
 *
 * @p TAG_LENGTH must be exactly LIBERAC_POLY1305_TAG_BYTES. Other parameters
 * have the same meaning and constraints as LIBERAC_POLY1305().
 *
 * @retval LIBERAC_SUCCESS The tag is valid.
 * @retval LIBERAC_ERROR_AUTHENTICATION_FAILED The tag does not match.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not Poly1305.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer or tag length is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH is not 32 bytes.
 */
LIBERAC_API LiberaCError LIBERAC_POLY1305_VERIFY(
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Compute GMAC by applying AES-GCM authentication to an unencrypted
 *        message.
 *
 * @param[out] TAG Destination for the GMAC tag.
 * @param[in]  TAG_CAPACITY Size of @p TAG in bytes.
 * @param[in]  TAG_LENGTH Requested tag length: 4, 8, or 12 through 16 bytes.
 * @param[in]  MESSAGE Unencrypted message to authenticate. It may be NULL only
 *                     when @p MESSAGE_LENGTH is zero.
 * @param[in]  MESSAGE_LENGTH Message length in bytes.
 * @param[in]  KEY AES master key.
 * @param[in]  KEY_LENGTH Key size in bytes; it must match @p ALG exactly.
 * @param[in]  IV Non-empty GCM initialization vector. A 12-byte IV is the
 *               usual interoperable choice and must be unique for the key.
 * @param[in]  IV_LENGTH IV length in bytes.
 * @param[in]  ALG AES-128, AES-192, or AES-256 GCM.
 *
 * @retval LIBERAC_SUCCESS The requested tag was produced.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not accepted by GMAC.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, IV, or tag length is
 *         invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH does not match @p ALG.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p TAG_CAPACITY is too small.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE A GCM length limit was exceeded.
 */
LIBERAC_API LiberaCError LIBERAC_GMAC(
    uint8_t *TAG, size_t TAG_CAPACITY, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Verify a GMAC tag using the constant-time AES-GCM verification path.
 *
 * Parameters have the same meaning and constraints as LIBERAC_GMAC(), except
 * that @p TAG is the tag to verify and no output capacity is required.
 *
 * @retval LIBERAC_SUCCESS The tag is valid.
 * @retval LIBERAC_ERROR_AUTHENTICATION_FAILED The tag does not match.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not accepted by GMAC.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, IV, or tag length is
 *         invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH does not match @p ALG.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE A GCM length limit was exceeded.
 */
LIBERAC_API LiberaCError LIBERAC_GMAC_VERIFY(
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    LiberaCAlgID ALG);

LIBERAC_END_DECLS

#endif

/** @} */
