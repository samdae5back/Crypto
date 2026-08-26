# Common cryptographic primitives

Portable C11 helpers shared by the algorithms in this repository.

- `sha3.[ch]`: self-contained Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128 and SHAKE256, including incremental SHAKE absorb/squeeze.
- `endian.h`: unaligned-safe 16/32/64-bit little- and big-endian byte load/store helpers.
- `entropy.[ch]`: operating-system entropy collection.
  - Linux: `getrandom(2)` with `/dev/urandom` fallback for kernels lacking the syscall.
  - Other Unix/POSIX systems: `/dev/urandom`.
  - Windows: `BCryptGenRandom(..., BCRYPT_USE_SYSTEM_PREFERRED_RNG)`.
- `random.[ch]`: common `crypto_random_bytes()` API backed directly by the OS CSPRNG.
- `ntt.[ch]`: reusable radix-2 cyclic NTT for prime moduli where `n | (q - 1)`.

The generic NTT is intentionally separate from ML-KEM's specialized negacyclic NTT. ML-KEM uses algorithm-specific twiddle ordering and multiplication rules, so replacing it with the generic cyclic NTT would change the algorithm.

The entropy API deliberately does not treat timestamps, process IDs, cycle counters or similar predictable values as cryptographic entropy.
