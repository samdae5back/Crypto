# LiberaCrypt documentation

LiberaCrypt keeps the repository `README.md` intentionally short. The README is the project landing page; detailed usage, design rationale, security notes, optimization records, and benchmark interpretation live here.

## Start here

- [Building LiberaCrypt](getting-started/building.md)
- [Integrating LiberaCrypt](getting-started/integration.md)
- [API overview](api/overview.md)
- [Algorithm selection](api/algorithm-selection.md)
- [Algorithm families](algorithms/overview.md)

## Design

- [Architecture](design/architecture.md)
- [Portability](design/portability.md)
- [Constant-time policy](design/constant-time.md)

These documents describe engineering policy rather than the mathematical definitions of the underlying standards. In particular, portability and timing behavior are treated as implementation properties that must be reasoned about explicitly.

## Security

- [Security considerations](security/security-considerations.md)
- [Legacy and compatibility algorithms](security/legacy-algorithms.md)

Applications should read these notes before choosing an algorithm or using low-level primitives directly.

## Algorithms

- [Algorithm-family overview](algorithms/overview.md)
- [Key derivation](key-derivation.md)

The generated Doxygen reference is the source for function signatures, parameters, return values, and public declarations. The Markdown documentation explains how the pieces are intended to be used together.

## Optimization and benchmarks

- [Optimization index](optimization/README.md)
- [Bignum optimization](optimization/Bignum.md)
- [ECC optimization](optimization/ECC.md)
- [Ed25519 optimization](optimization/Ed25519.md)
- [ML-KEM optimization](optimization/ML-KEM.md)
- [ML-KEM Barrett/Montgomery experiment](optimization/ML-KEM-Barrett.md)
- [RSA optimization](optimization/RSA.md)
- [Benchmark organization](benchmarks/README.md)

Optimization documents record the baseline, the change, the validation constraints, and the reason the final implementation was selected. Raw benchmark programs remain under the repository-level `benchmarks/` directory.

## Development

- [Testing and validation](development/testing.md)

Third-party provenance and license information remain in the repository-level `THIRD_PARTY_NOTICES.md` file.
