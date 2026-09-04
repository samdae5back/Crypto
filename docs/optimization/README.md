# Optimization notes

Optimization documents record implementation decisions, not changes to the underlying cryptographic standards or wire formats.

A *reference-shaped baseline* means a direct translation of standard pseudocode or an earlier straightforward LiberaCrypt implementation. It does not imply that an official upstream or NIST implementation was used as the benchmark baseline unless the document says so explicitly.

## Component notes

- [Bignum](Bignum.md) — public-data and secret-data arithmetic paths, exponentiation, Montgomery work, and measured stages.
- [ECC](ECC.md) — elliptic-curve arithmetic implementation and optimization stages.
- [Ed25519](Ed25519.md) — Ed25519-specific arithmetic and implementation choices.
- [RSA](RSA.md) — RSA arithmetic and OAEP/PSS-related implementation work.
- [ML-KEM](ML-KEM.md) — ML-KEM implementation/optimization record and final selected path.
- [ML-KEM Barrett experiment](ML-KEM-Barrett.md) — focused comparison of Barrett-only, hybrid Montgomery, and full-Montgomery approaches.

## Shared and legacy work

Not every improvement is a raw throughput optimization. LiberaCrypt also makes measured or justified changes for cache behavior, memory traffic, code size, duplicate implementation removal, timing behavior, and portability.

Examples include:

- SHA-1 uses a circular message schedule and can process complete streaming blocks without copying each one through the context staging buffer.
- Triple-DES avoids secret-indexed S-box table access and retains a fixed-index Boolean implementation; hot permutation work was reorganized to avoid generic bit-by-bit table walks and redundant intermediate permutations.
- AES uses an algebraic S-box/inverse-S-box path instead of secret-derived table indexing in the portable implementation.
- SHA-2 and LSH streaming paths process complete input blocks directly after draining a partial context block.
- The one-shot hash API reuses the same incremental state machine rather than duplicating padding/finalization logic.
- Shared constant-time byte equality and overflow-aware overlap helpers replace duplicate security-sensitive loops across algorithm families.
- Portable PQC integration favors one runtime-dispatched library build over unnecessary parameter-specialized compilation where the backend permits it.

Where a reproducible benchmark is not retained, documentation should not claim a throughput improvement merely because the implementation was reorganized.

## ML-KEM reduction decision

The project compared Barrett-only, hybrid Montgomery, and full-Montgomery ML-KEM implementations across Ubuntu, Windows, and macOS runners. In the retained comparison, hybrid Montgomery was slower overall than Barrett-only, and full Montgomery regressed further on the tested runners. The default portable ML-KEM path therefore keeps Barrett reduction.

The focused methodology and per-runner measurements belong in [ML-KEM Barrett experiment](ML-KEM-Barrett.md), not in the repository landing page.

## Documentation format for new optimization work

New component notes should follow this structure where applicable:

1. **Baseline implementation** — what the code did before the change.
2. **Optimization goal** — throughput, allocation, memory traffic, code size, portability, timing behavior, or maintainability.
3. **Implementation changes** — the concrete transformation.
4. **Correctness and timing constraints** — invariants that the optimization must preserve.
5. **Portability considerations** — assumptions about integer width, representation, compiler behavior, or architecture.
6. **Benchmark methodology** — hardware/runner, compiler, build flags, repetitions, and comparison baseline.
7. **Results** — retained measurements without overstating generality.
8. **Final decision** — why the selected implementation remains in the default path.

This format is intended to preserve engineering reasoning even when an attempted optimization is ultimately rejected.
