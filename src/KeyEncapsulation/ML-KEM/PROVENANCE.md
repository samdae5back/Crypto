# ML-KEM implementation provenance

LiberaCrypt's ML-KEM implementation is an original, standards-based
implementation written from the algorithm definitions and pseudocode in NIST
FIPS 203. It was not copied, ported, or adapted from the reference
implementations linked below, and those codebases are not source-code
provenance for the implementation in this directory.

## Primary specification

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*:
  <https://csrc.nist.gov/pubs/fips/203/final>

FIPS 203 is the primary implementation reference for the ML-KEM-512,
ML-KEM-768, and ML-KEM-1024 code under this directory.

## Reference code for comparison

The following implementations are provided as external reference points for
readers who want to compare design choices or implementation structure:

- CRYSTALS-Kyber official reference implementation, the reference-code lineage
  from which ML-KEM was standardized:
  <https://github.com/pq-crystals/kyber/tree/main/ref>
- `mlkem-native`, a maintained FIPS 203 implementation from the PQ Code Package:
  <https://github.com/pq-code-package/mlkem-native>

These links are informational only. LiberaCrypt's ML-KEM source was implemented
independently from the FIPS 203 specification rather than by consulting,
copying, or adapting either implementation above.

## Local implementation

The implementation is contained under `src/KeyEncapsulation/ML-KEM/` and uses
LiberaCrypt's project-local SHA3/SHAKE, random-byte, endian, and utility code.
Runtime selection exposes all three FIPS 203 parameter sets from one library
build.

Because this ML-KEM implementation is LiberaCrypt original source rather than a
vendored third-party component, it is licensed under the project's
`AGPL-3.0-only` license.
