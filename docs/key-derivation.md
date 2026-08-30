# Key derivation

LiberaCrypt's key-derivation layer is built directly on the public HMAC layer so
hash selection remains runtime-dispatched and no hash-specific KDF copies are
required.

## HKDF

The `LIBERAC_HKDF_EXTRACT`, `LIBERAC_HKDF_EXPAND`, and `LIBERAC_HKDF` APIs
implement RFC 5869. `LIBERAC_HKDF_PRK_SIZE` returns the selected HMAC digest
size.

Supported selectors are the same fixed-output SHA-1, SHA-2, and SHA-3
identifiers accepted by `LIBERAC_HMAC`. SHAKE and LSH are rejected. SHA-1 is
kept for legacy interoperability rather than new protocol design.

The implementation follows the RFC limits and semantics:

- an omitted/zero-length salt is treated as `HashLen` zero octets;
- `HKDF-Expand` requires a PRK of at least `HashLen` octets;
- output is limited to `255 * HashLen` octets;
- temporary PRK, block state, and dynamically allocated message workspace are
  explicitly erased before release.

Known-answer tests use RFC 5869 Appendix A test cases 1 and 3, covering
SHA-256, explicit salt/info, the default salt, zero-length info, separate
Extract/Expand calls, and the combined API.

Reference: <https://www.rfc-editor.org/rfc/rfc5869>

## PBKDF2-HMAC

`LIBERAC_PBKDF2_HMAC` implements PBKDF2 as specified by PKCS #5 / RFC 8018,
using the existing HMAC implementation as the PRF. The API takes a runtime hash
selector, a positive 64-bit iteration count, and a caller-supplied output
buffer.

The implementation:

- encodes the PBKDF2 block number as the required four-byte big-endian integer;
- enforces the `(2^32 - 1) * HashLen` derived-key bound through the block-count
  limit;
- accepts empty passwords and salts for protocol compatibility and vector
  testing, while leaving deployment policy to the caller;
- rejects output/input overlap rather than depending on undocumented in-place
  behavior;
- erases intermediate `U_j` values and XOR accumulators on every exit path.

RFC 8018 defines standard PBKDF2 PRF identifiers for HMAC with SHA-1 and the
SHA-2 family. LiberaCrypt additionally permits its fixed-output SHA-3 HMAC
selectors through the generic API. Applications that serialize PBKDF2
parameters or must follow a specific profile are responsible for choosing only
PRFs permitted by that profile.

Known-answer coverage includes RFC 6070 PBKDF2-HMAC-SHA1 vectors with iteration
counts 1, 2, and 4096 and the 64-byte PBKDF2-HMAC-SHA256 vector from RFC 7914.
A small SHA3-256 case provides regression coverage for LiberaCrypt's generic
runtime-dispatch extension.

References:

- <https://www.rfc-editor.org/rfc/rfc8018>
- <https://www.rfc-editor.org/rfc/rfc6070>
- <https://www.rfc-editor.org/rfc/rfc7914>
- <https://csrc.nist.gov/pubs/sp/800/132/final>

## Portability and optimization notes

The first KDF implementation deliberately favors a small, auditable composition
of the already-tested HMAC API. It uses only C11/library-local facilities and
explicit big-endian byte encoding, with no host-endian or word-width
assumptions.

HKDF allocates one temporary buffer large enough for `T(n-1) || info || n`, and
PBKDF2 allocates one buffer for `salt || INT(i)`. Allocation sizes are checked
for `size_t` overflow and allocation failure is reported through
`LIBERAC_ERROR_ALLOCATION_FAILED`.

PBKDF2 currently invokes the public one-shot HMAC operation for every PRF call.
That is intentionally simple but causes the HMAC key normalization and ipad/opad
setup to be repeated for every iteration. A future optimization can add an
internal reusable prepared-HMAC state and benchmark it without changing the
public KDF API or derived bytes. Such a change should be treated as a measured
throughput optimization, not as part of the initial correctness milestone.
