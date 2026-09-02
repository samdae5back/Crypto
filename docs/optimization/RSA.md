# Portable RSAES-OAEP and RSASSA-PSS

LiberaCrypt layers the PKCS #1 v2.2 schemes RSAES-OAEP and RSASSA-PSS over its
managed RSA key objects and raw RSA primitives. The implementation follows
[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html), including the
OS2IP/I2OSP widths, MGF1 counter encoding, OAEP message bound, PSS
`emBits = modBits - 1` rule, and single-octet `0xbc` trailer.

## Public API and encodings

`LIBERAC_RSA_PUBLIC_MODULUS_SIZE` and
`LIBERAC_RSA_PRIVATE_MODULUS_SIZE` return the fixed RSA octet width `k`.
`LIBERAC_RSA_OAEP_MAX_MESSAGE_SIZE` returns `k - 2*hLen - 2` when the
modulus and hash permit OAEP.

RSA keys are scheme-independent. `LIBERAC_RSA_KEYGEN` therefore accepts the
raw, OAEP, and PSS RSA identifiers while producing the same `N`, `E`, and
`D` material. Generated public exponents remain 65537. OAEP and PSS byte
outputs are fixed at `k` bytes; no ASN.1 key or AlgorithmIdentifier encoding
is added by these APIs.

The schemes accept SHA-1 and the fixed-output SHA-2 family. SHA-1 is retained
for legacy interoperability. SHA-3, SHAKE, and LSH identifiers are rejected:
the API does not silently create an encoding profile outside the implemented
PKCS #1 parameter set. Hash and MGF1 always use the same selector.

## MGF1

MGF1 hashes `mgfSeed || I2OSP(counter, 4)` for counters beginning at zero.
The implementation uses the incremental public hash API, encodes the counter
explicitly in big-endian order, checks the RFC block-count limit, and XORs each
digest directly into the target region. It does not allocate a concatenated
seed/counter buffer or rely on host byte order.

## RSAES-OAEP

Encryption builds:

`EM = 0x00 || maskedSeed || maskedDB`

where `DB = Hash(label) || PS || 0x01 || message`. The label may be empty, but
its hash is always present. A fresh `hLen`-byte seed comes directly from the
operating-system random source. The plaintext length is rejected before any
encoding write when it exceeds `k - 2*hLen - 2`.

Decryption requires exactly `k` ciphertext bytes and an output buffer large
enough for the maximum plaintext. After the fixed-schedule private operation it
unmasks the seed and data block, compares the label hash without an early
byte mismatch, and scans the complete padding/delimiter region. The scan tracks
the first `0x01` with masks and does not return early for a nonzero padding
byte, missing delimiter, label mismatch, or nonzero leading byte.

All ciphertext representatives outside `[0, N)` and all OAEP-format failures
collapse to `LIBERAC_ERROR_AUTHENTICATION_FAILED`. The maximum output region is
cleared before the private operation and on every failure, and the reported
message length is reset to zero. Public argument errors such as an undersized
destination remain distinct so callers can fix their buffer contract before
processing attacker-controlled ciphertexts.

## RSASSA-PSS

Signing hashes the message, obtains an explicit number of random salt bytes,
builds `M' = 0x00...00 (8 bytes) || mHash || salt`, and encodes the data block
at `emBits = bit_length(N) - 1`. Unused high bits are cleared before the
private operation.

Verification requires an exact `k`-byte signature and the caller's exact
salt-length policy. The digest-length sentinel resolves to `hLen`; it is not
an auto-detect mode. Verification checks the recovered representative width,
unused high bits, trailer byte, exact zero-padding length, delimiter, and
recomputed hash. A mismatch returns `LIBERAC_ERROR_SIGNATURE_INVALID`.

## Exponentiation schedules

Private operations use the existing modulus-width Montgomery ladder-like
schedule: for every modulus-width exponent bit, both square and multiply
candidates are computed and mask-selected. The private exponent is stored at
the complete modulus limb width.

OAEP encryption starts from a randomized encoding that contains confidential
plaintext. Its public exponent is not secret, but using the general
variable-time public bignum path would still allow encoded-base-dependent
Montgomery reductions. The OAEP path therefore uses a separate helper that:

- loads and compares the full fixed-width encoded base without early exit;
- uses masked Montgomery final subtraction;
- branches only on public exponent bits; and
- clears the fixed-width intermediate allocation.

PSS verification and the retained raw public primitive operate on public
values and continue to use the faster variable-time sliding-window path.

The implementation makes source-level fixed-schedule claims only. ISO C cannot
guarantee equal physical instruction latency, compiler transformations, cache
behavior, or platform-wide side-channel resistance. The current implementation
also performs full-width RSA exponentiation rather than CRT recombination.

## Validation

The focused RSA test uses a fixed 2048-bit RSA key and OpenSSL 3.0.13-generated
interoperability artifacts:

- RSAES-OAEP with SHA-256 and MGF1-SHA-256 decrypts to the expected plaintext;
- RSASSA-PSS with SHA-256, MGF1-SHA-256, and a 32-byte salt verifies;
- fresh OAEP encrypt/decrypt and PSS sign/verify round trips succeed;
- repeated OAEP encryption produces independently randomized ciphertexts;
- wrong labels, malformed ciphertexts, wrong messages, wrong salt lengths,
  modified signatures, and non-exact wire lengths fail;
- OAEP failures reset the output length and leave the maximum plaintext region
  cleared; and
- overlap, capacity, unsupported-hash, and algorithm-selector contracts are
  exercised.

The RSA workflow builds and runs this target on Ubuntu, macOS, and Windows and
runs the same test with AddressSanitizer and UndefinedBehaviorSanitizer on
Ubuntu. A separate Ubuntu job generates a fresh 2048-bit OpenSSL key, imports
its modulus/private exponent into LiberaCrypt, and checks both directions:
OpenSSL encrypt/sign to LiberaCrypt decrypt/verify, then LiberaCrypt
encrypt/sign to OpenSSL decrypt/verify. The normal full test matrix remains the
final merge gate.
