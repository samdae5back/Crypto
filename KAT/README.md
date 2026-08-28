# Post-quantum known-answer vectors

The `.kat` files in this directory are regression vectors used by LiberaCrypt's
post-quantum test suite. Except where a companion provenance note explicitly
identifies a byte-for-byte copy of an official response file, these project
vectors were generated with independent implementations that had first been
cross-checked against other published or reference vectors.

They should therefore be treated as reproducible regression data, not as an
authoritative or normative source of expected values. A bug in a generator,
its integration, or the conversion into this repository's test format is still
possible. When an official response corpus is available, it remains the
preferred external source of truth. `HAETAE-1.2.0.md` and `SMAUG-T-1.2.0.md`
record the official-release provenance for those versioned response files.

The current PQC KAT coverage includes:

- ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- NTRU+768, NTRU+864, and NTRU+1152
- SMAUG-T-128, SMAUG-T-192, and SMAUG-T-256
- ML-DSA-44, ML-DSA-65, and ML-DSA-87
- AIMer 128/192/256 fast and small parameter sets
- HAETAE-120, HAETAE-180, and HAETAE-260
- all twelve SHA2- and SHAKE-based SLH-DSA parameter sets
- legacy HAETAE verification vectors retained for compatibility regression

## Deterministic replay

The generic PQC KAT path uses a test-only randomness provider. Normal
LiberaCrypt builds do not expose this control surface and continue to obtain
randomness from the operating system.

For each ordinary project-format KAT record:

1. The runner reads the record's 48-byte `seed` and expected outputs.
2. Any previous KAT state is cleared, then a fresh AES-256 CTR_DRBG instance is
   created with `LIBERAC_ALG_CTR_DRBG_AES_256_NO_DF`. The 48-byte `seed` is
   supplied as the instantiate entropy input; no personalization string or
   additional input is used.
3. While the KAT instance is active, PQC random-byte requests are served from
   that DRBG. Key generation and then encapsulation or signature generation
   consume the deterministic byte stream in the same request order as the
   vector generator.
4. The KAT DRBG is cleared after the randomized operations for that record.
   The current replay path does not call the CTR_DRBG reseed operation; the
   next record starts from a newly instantiated DRBG using that record's next
   48-byte seed.
5. The generated public/private keys and ciphertext/shared secret or signature
   are compared byte-for-byte with the record. Decapsulation or signature
   verification is then checked as a separate round-trip/verification step.

Some official formats require family-specific replay details. For example,
HAETAE 1.2.0 derives context-related values from its seeded random stream; those
rules are documented in `HAETAE-1.2.0.md` and handled by its dedicated runner.

## Running the vectors

Configure a test build and run all tests carrying the `kat` label:

```sh
cmake -S . -B build -DLIBERAC_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release -L kat --output-on-failure
```

A single family or parameter set can be selected with CTest's `-R` regular
expression, for example:

```sh
ctest --test-dir build -C Release \
  -R 'LiberaCrypt.KeyEncapsulation.ML-KEM-512.KAT' \
  --output-on-failure
```

`SHA256SUMS` records the exact KAT files tracked by the repository so accidental
changes to the corpus can be detected independently of the test results.
