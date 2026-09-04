# Algorithm selection

LiberaCrypt selects concrete algorithms and parameter sets at runtime through `LiberaCAlgID`. The selector normally appears as the final argument of an operation-oriented API.

The selector does not remove algorithm-specific rules. Each API family validates the constraints that belong to the selected algorithm.

## Block and stream encryption

The unauthenticated block-cipher dispatcher accepts:

- AES-128, AES-192, and AES-256 in ECB, CBC, and CTR modes.
- Three-key Triple-DES EDE in ECB and CBC modes for legacy interoperability.

ECB and CBC require block-aligned input; padding is left to the caller. CTR accepts arbitrary byte lengths.

AES-GCM and AES-CCM are rejected by the block-cipher dispatcher and must be used through the authenticated-encryption API.

Standalone ChaCha20 follows the RFC 8439 construction with a 32-byte key, 32-bit initial counter, and 12-byte nonce. A key/nonce pair must not be reused, and counter ranges for the same pair must not overlap.

## Authenticated encryption

AES-GCM, AES-CCM, and ChaCha20-Poly1305 use the AEAD dispatcher.

| Family | Nonce length | Tag length |
| --- | --- | --- |
| AES-GCM | Any non-empty length; 12 bytes recommended | 4, 8, or 12 through 16 bytes |
| AES-CCM | 7 through 13 bytes | Even lengths from 4 through 16 bytes |
| ChaCha20-Poly1305 | Exactly 12 bytes | Exactly 16 bytes |

`LIBERAC_AEAD_KEY_SIZE()`, `LIBERAC_AEAD_NONCE_LENGTH_VALID()`, and `LIBERAC_AEAD_TAG_LENGTH_VALID()` allow callers to validate the selected configuration before an operation.

Authentication failure returns `LIBERAC_ERROR_AUTHENTICATION_FAILED`. Decryption paths are designed not to expose unauthenticated plaintext as successful output.

## Hashes and XOFs

The hash family includes:

- SHA-1 for legacy compatibility.
- SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.
- SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256.
- LSH-256-224, LSH-256-256, LSH-512-224, LSH-512-256, LSH-512-384, and LSH-512-512.

Fixed-output hashes require their standard digest size. SHAKE uses caller-selected output length and supports repeated squeeze operations after finalization.

## Message authentication

- HMAC accepts fixed-output SHA-1, SHA-2, and SHA-3 identifiers.
- CMAC accepts AES-128/192/256 and three-key Triple-DES EDE selectors appropriate to CMAC.
- GMAC accepts AES-GCM selectors and the GCM tag-length rules.
- Poly1305 accepts only the Poly1305 selector, an exactly 32-byte one-time key, and the complete 16-byte tag.

Verification APIs use the shared constant-time byte-equality helper and report authentication failure explicitly.

## Key derivation

HKDF and PBKDF2-HMAC use the same runtime-selected HMAC layer. Both support fixed-output SHA-1, SHA-2, and SHA-3 HMAC selectors subject to the protocol using them.

See [Key derivation](../key-derivation.md) for standards, bounds, overlap rules, and retained test vectors.

## CTR_DRBG

The stateful CTR_DRBG API supports AES-128/192/256 and legacy three-key TDEA configurations, with and without `Block_Cipher_df`. AES configurations are the modern default; TDEA selectors exist for standards-era compatibility and test-vector reproduction.

## Public-key and post-quantum families

Current families include RSA, ElGamal, ECDH, X25519, ECDSA, Ed25519, ML-KEM, NTRU+, SMAUG-T, ML-DSA, AIMer, HAETAE, and SLH-DSA. Parameter-specific builds are not required for the runtime-dispatched families.

Use the public size-query APIs rather than hard-coding key, ciphertext, or signature sizes when a query helper is available.
