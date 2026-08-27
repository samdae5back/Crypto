# Post-quantum known-answer vectors

These files are the unmodified known-answer test corpus supplied by the
repository owner together with the project's `PQC` and `PQC_TEST` reference
implementation. No separate generator revision or license metadata accompanied
the corpus; the recorded SHA-256 values therefore define the exact test-data
revision used here. The Crypto test suite uses the 18 parameter sets implemented
by the current module:

- ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- ML-DSA-44, ML-DSA-65, and ML-DSA-87
- all twelve SHA2- and SHAKE-based SLH-DSA parameter sets

Every file contains 100 records. Each 48-byte `seed` initializes AES-256
CTR-DRBG without a derivation function. The module's test-only KAT build then
routes PQC randomness through that DRBG while preserving the original request
boundaries. Normal library builds continue to read PQC randomness directly
from the operating system.

`SHA256SUMS` records the exact files consumed by CTest. Other files in the
supplied corpus target algorithms that the current public API does not
implement; they are intentionally excluded from CTest and the tracked release
corpus.
