# Architecture

LiberaCrypt separates the public operation API from concrete algorithms and from narrow platform-specific boundaries.

```text
application
    |
    v
public headers in inc/
    |
    v
operation/category dispatcher in src/*.c
    |
    v
algorithm implementation directories
    |
    v
shared arithmetic / endian / ECC / NTT / core utilities
    |
    v
narrow OS and toolchain boundaries
```

## Public API layer

Only headers under `inc/` are installed. They define operation-oriented interfaces, common errors, public types, size queries, and `LiberaCAlgID` selectors.

The public naming convention is:

- `LIBERAC_` for public C functions, macros, constants, and selectors.
- `LiberaC` for public type names.
- `LiberaCrypt.h` as the umbrella header.
- `LiberaCrypt::LiberaCrypt` as the exported CMake target.

## Dispatch layer

Entry-point sources directly under `src/` implement category-level dispatch. Their job is to validate the public request, resolve the runtime algorithm identifier, and call the concrete implementation without forcing applications to use parameter-specific builds.

The operation boundary is deliberate. For example, authenticated-encryption selectors do not pass through the raw block-cipher API because AAD, nonce, and tag semantics belong to AEAD rather than block encryption.

## Algorithm implementations

Concrete implementations live under category directories such as:

```text
src/AsymmetricCipher/
src/AuthenticatedEncryption/
src/BlockCipher/
src/DigitalSignature/
src/HashFunction/
src/KeyAgreement/
src/KeyEncapsulation/
src/MessageAuthentication/
src/RandomNumberGeneration/
src/StreamCipher/
```

Private declarations stay with the implementation rather than being exported through `inc/`.

## Shared implementation layer

`src/Util/` contains shared bignum, bit, core, ECC, endian, NTT, prime, and related implementation support. These are internal building blocks, not a second public API.

Shared helpers are preferred when they reduce duplication of security-sensitive logic, such as constant-time byte comparison or overflow-aware overlap validation.

## Platform boundaries

Cryptographic code is intended to remain independent of an external cryptographic runtime. Platform-specific behavior is isolated to narrow areas such as operating-system entropy acquisition and shared-library symbol export.

The canonical public-symbol allowlist is `cmake/liberacrypt_exports.txt`. The build applies it through the native mechanism for each platform, including Windows DLL declarations, ELF version scripts, macOS exported-symbol lists, Solaris mapfiles, AIX export files, and HP-UX linker export options.

## Why this structure

The architecture is designed to keep three concerns separate:

1. **What the caller wants to do** — encrypt, authenticate, derive, sign, encapsulate, and so on.
2. **Which concrete algorithm/parameter set performs it** — selected at runtime where appropriate.
3. **How the implementation remains portable and safe on the host** — handled internally without leaking platform assumptions into the public API.

This separation lets portability, constant-time behavior, and algorithm optimization evolve without multiplying public interfaces.
