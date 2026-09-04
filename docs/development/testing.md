# Testing and validation

LiberaCrypt combines unit tests, known-answer tests, compatibility regressions, public-header checks, sanitizer/warning builds, and focused benchmark/validation workflows.

## General test scope

When `LIBERAC_BUILD_TESTS` is enabled, the generated test set covers areas including:

- public-header isolation;
- operation-level key generation, encryption/decryption, encapsulation/decapsulation, and signing/verification;
- block-cipher and AEAD known-answer/round-trip cases across supported parameter choices;
- SHA-1, SHA-2, SHA-3, SHAKE, and LSH vectors;
- HMAC, CMAC, GMAC, and Poly1305 generation/verification behavior;
- HKDF and PBKDF2-HMAC standard vectors, boundary handling, overlap rejection, and invalid arguments;
- AES and legacy TDEA CTR_DRBG vectors and lifecycle behavior;
- operation tests and KATs for supported post-quantum KEM/signature parameter sets;
- Ed25519 standard vectors and negative tests;
- RSA OAEP/PSS regression and interoperability-oriented validation; and
- HAETAE compatibility vectors alongside the current retained KAT set.

## KAT randomness boundary

PQC KAT executables use test-only deterministic initialization for vector reproduction. The normal shared/static LiberaCrypt target does not expose that KAT control interface and continues to obtain normal operational randomness through the operating-system entropy path.

This separation prevents deterministic test plumbing from becoming part of the production public API.

## Cross-toolchain validation

Mainline CI builds on Windows, Linux, and macOS. Focused workflows may be used for component-specific validation and benchmark stages.

Portability is not defined solely by this matrix. Warning-oriented builds, sanitizers, explicit range/representation reasoning, and non-mainstream platform considerations remain part of the portability policy described in [Portability](../design/portability.md).

## Development oracles

External implementations may be used during development to cross-check retained vectors or randomized interoperability cases. They are test/development oracles, not runtime dependencies of LiberaCrypt, unless explicitly identified otherwise in component provenance.

## Documentation-only changes

Documentation-only changes do not require cryptographic build/test execution when they do not modify source code, build configuration, generated API declarations, test vectors, or workflow behavior. Such changes should still be reviewed for broken links, stale names, and claims that no longer match the codebase.
