# Algorithm families

This page is a map of the algorithms exposed by LiberaCrypt. It is not a substitute for the underlying standards or the generated public API reference.

| Family | Implementations |
| --- | --- |
| Block ciphers | AES-128/192/256; three-key Triple-DES EDE |
| Stream cipher | ChaCha20 |
| Authenticated encryption | AES-GCM, AES-CCM, ChaCha20-Poly1305 |
| Hash / XOF | SHA-1, SHA-2, SHA-3, SHAKE, LSH |
| Message authentication | HMAC, CMAC, GMAC, Poly1305 |
| Key derivation | HKDF, PBKDF2-HMAC |
| Random generation | OS random bytes, CTR_DRBG |
| Public-key encryption | RSAES-OAEP, raw RSA primitive, ElGamal |
| Key agreement | ECDH over NIST P-256/P-384/P-521, X25519 |
| Digital signatures | RSASSA-PSS, ECDSA, Ed25519, ML-DSA, SLH-DSA, AIMer, HAETAE |
| Key encapsulation | ML-KEM-512/768/1024, NTRU+768/864/1152, SMAUG-T-128/192/256 |
| Utility arithmetic | Bignum, prime generation, ECC and shared arithmetic helpers |

## Symmetric encryption and AEAD

Raw block/stream encryption and authenticated encryption are intentionally separate API families. New application protocols should normally prefer an authenticated-encryption construction instead of composing unauthenticated encryption and authentication ad hoc.

## Hashes, MACs, and KDFs

Hash, message-authentication, and key-derivation APIs share the runtime-selection model while keeping operation-specific parameter validation separate. HKDF and PBKDF2-HMAC are documented in more detail in [Key derivation](../key-derivation.md).

## Classical public-key algorithms

RSA encryption should use RSAES-OAEP and RSA signatures should use RSASSA-PSS. Raw textbook RSA remains available for primitive-level tests and compatibility and must not be treated as a secure encryption or signature scheme by an application.

ECDH and ECDSA support the NIST P-256, P-384, and P-521 curves. X25519 and Ed25519 use their dedicated encodings and interfaces rather than being represented as parameter choices of the NIST-curve API.

## Post-quantum algorithms

LiberaCrypt provides multiple KEM and signature families through portable C backends. Vendored components retain their upstream notices and licenses; see the repository-level `THIRD_PARTY_NOTICES.md` for provenance and pinned versions or package hashes.

## Legacy compatibility

SHA-1 and Triple-DES/TDEA are retained for interoperability and standards-era compatibility. They are not recommended as new protocol defaults. See [Legacy and compatibility algorithms](../security/legacy-algorithms.md).
