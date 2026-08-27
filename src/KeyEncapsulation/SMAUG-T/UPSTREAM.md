# SMAUG-T source provenance

This implementation is derived from the official Team SMAUG-T reference
implementation, pinned to version 1.2.0.

- Official release page:
  <https://sites.google.com/view/smaug-and-haetae/smaug-t>
- Official 1.2.0 archive:
  <https://drive.usercontent.google.com/download?id=1L6wLwZu65OHFDz2iPqZdEQOwcqJ-9xxX&export=download&confirm=t>
- Archive SHA-256:
  `ccb58f42043296174e10fc7af520f0a49076d8c2245bd8e66d1b88bcae568c90`

Version 1.2.0 is used because the official release page identifies
implementation errors in version 1.1.1 and directs users to version 1.2.0.

The upstream mode1, mode3, and mode5 build-time configurations are
consolidated into one runtime-parameter implementation for the
`ALG_SMAUG_T_128`, `ALG_SMAUG_T_192`, and `ALG_SMAUG_T_256` identifiers.
Upstream Keccak and random-byte implementations are not included. The port
uses Crypto's private shared SHA3/SHAKE, random-byte, endian, constant-time,
and secure-zeroization utilities instead. Internal non-static symbols use the
`crypto_smaug_t_` namespace.

Official version 1.2.0 response-file provenance and hashes are recorded in
`KAT/SMAUG-T-1.2.0.md` at the repository root.

The upstream MIT license is reproduced in [LICENSE](LICENSE).
