# API overview

LiberaCrypt exposes a small set of operation-oriented API families and performs concrete algorithm selection at runtime with `LiberaCAlgID`.

The API is intentionally organized by cryptographic operation rather than by implementation directory. This prevents parameters that only make sense for one operation from leaking into unrelated calls.

## Family boundaries

- **Block cipher** — unauthenticated AES ECB/CBC/CTR and three-key Triple-DES ECB/CBC.
- **Stream cipher** — standalone ChaCha20.
- **Authenticated encryption** — AES-GCM, AES-CCM, and ChaCha20-Poly1305.
- **Hash / XOF** — SHA-1, SHA-2, SHA-3, SHAKE, and LSH through one runtime-selected hash interface.
- **Message authentication** — HMAC, CMAC, GMAC, and Poly1305.
- **Key derivation** — HKDF and PBKDF2-HMAC.
- **Random generation** — OS random bytes and stateful CTR_DRBG.
- **Asymmetric encryption/signature/key agreement/KEM** — operation-specific interfaces with runtime-selected parameter sets where applicable.

AES-GCM and AES-CCM are deliberately not accepted by the raw block-cipher API. Their nonce, AAD, and authentication-tag semantics belong to the authenticated-encryption interface. Likewise, standalone ChaCha20 and ChaCha20-Poly1305 remain distinct because the latter reserves counter zero for Poly1305-key derivation and imposes AEAD-specific nonce/tag rules.

## One-shot and incremental operations

Where an operation naturally benefits from streaming, LiberaCrypt exposes an incremental state machine in addition to a one-shot helper. Hashing is the clearest example: the one-shot operation is built on the same init/update/finalize/squeeze path used by incremental callers.

This avoids maintaining separate implementations for identical cryptographic state transitions.

## Size and parameter queries

Key, ciphertext, signature, nonce, tag, and related size helpers use the same runtime algorithm identifiers. Applications should query or validate sizes instead of duplicating parameter tables whenever a public helper exists.

## Error handling

Public APIs return `LiberaCError`. Invalid algorithm identifiers, invalid lengths, authentication failures, and other rejected requests are reported explicitly. Security-sensitive operations clear partially produced plaintext or output where exposing an unauthenticated or failed intermediate would be unsafe.

## Function-level reference

Markdown documents describe intended use and design boundaries. Generated Doxygen documentation from the public headers is the authoritative function-level reference for signatures, arguments, declarations, and return values.
