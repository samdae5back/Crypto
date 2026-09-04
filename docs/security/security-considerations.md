# Security considerations

LiberaCrypt provides cryptographic primitives and validates operation-level inputs, but correct protocol use remains the caller's responsibility.

## Use the appropriate API family

Prefer authenticated-encryption APIs for new application protocols when both confidentiality and integrity are required. Raw block or stream encryption APIs are intentionally separate from authenticated encryption.

Algorithm-specific nonce, tag, key-size, and message-size rules are validated by the corresponding public API where possible. Application-wide requirements such as nonce uniqueness, key lifecycle, replay handling, and protocol negotiation remain outside the scope of the library.

## Authentication failures

Authentication and verification failures are returned explicitly. Callers must treat failed authentication as a hard failure and must not process data as trusted after verification fails.

## Key derivation and randomness

Key-derivation APIs implement their documented standards and bounds. Applications remain responsible for choosing appropriate inputs, password policy, work factors, and protocol-specific restrictions.

Random-byte and DRBG APIs depend on correct lifecycle and parameter use. Legacy configurations exist for compatibility and should not automatically be selected for new protocols.

## Public-key primitives

High-level standardized encodings and schemes should be preferred over raw mathematical primitives. Raw primitives are retained where useful for testing and compatibility but do not by themselves define a secure application protocol.

## Legacy algorithms

Some algorithms are included for interoperability with older systems rather than as recommendations for new designs. See [Legacy and compatibility algorithms](legacy-algorithms.md).

## Side channels

Selected secret-dependent arithmetic uses dedicated fixed-width timing-oriented paths. This does not amount to a claim that every operation, compiler output, host environment, or complete application is free from all side channels. See [Constant-time policy](../design/constant-time.md) for the implementation boundary.

## Secret lifetime

The implementation clears many sensitive temporary buffers and internal states when they are no longer needed. This reduces residual data but cannot control copies created elsewhere by the application, compiler, operating system, or hardware.

## Protocol responsibility

A primitive library cannot infer the security goals of the surrounding system. Applications remain responsible for protocol selection, key management, message framing, domain separation, negotiation policy, replay handling, and the threat model of the complete deployment.
