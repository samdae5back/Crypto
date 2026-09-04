# Benchmarks

Benchmark source code and benchmark interpretation have different roles in LiberaCrypt.

## Repository organization

```text
benchmarks/          benchmark programs and fixtures
docs/benchmarks/     benchmark organization and result-reading guidance
docs/optimization/   component-specific measurements and implementation decisions
```

The repository-level `benchmarks/` directory currently contains focused Bignum and ECC benchmark programs. Algorithm-specific result tables and the reasoning that follows from them should be stored with the corresponding optimization document rather than copied into the main README.

## Reporting policy

A benchmark record should identify enough context to make the comparison meaningful:

- compared revisions or implementation stages;
- operation and parameter set;
- compiler/toolchain and relevant build configuration;
- operating system or hosted runner;
- repetition/aggregation method;
- whether values are absolute throughput/latency or relative percentage changes; and
- whether the comparison is same-host, hosted-runner, or cross-library.

A result measured on one platform must not be presented as a universal property of the algorithm.

## Negative results matter

An optimization experiment that is slower can still be a useful engineering result. The ML-KEM Montgomery experiments are retained for this reason: they explain why the portable default stayed with Barrett reduction instead of leaving the rejected alternative undocumented.

## Where results belong

- Bignum results: [Bignum optimization](../optimization/Bignum.md)
- ECC results: [ECC optimization](../optimization/ECC.md)
- ML-KEM results: [ML-KEM optimization](../optimization/ML-KEM.md) and [ML-KEM Barrett experiment](../optimization/ML-KEM-Barrett.md)
- RSA results/decisions: [RSA optimization](../optimization/RSA.md)
- Ed25519 results/decisions: [Ed25519 optimization](../optimization/Ed25519.md)

The top-level README should summarize only that optimization work is documented and measured; detailed tables belong here or in the component optimization notes.
