# NTRU+ source provenance

This implementation is derived from the official NTRU+ reference
implementation distributed by the NTRU+ project.

- Official homepage: <https://www.ntruplus.org/>
- Official reference implementation, pinned to the vendored revision:
  <https://github.com/ntruplus/ntruplus/tree/3991b2ae08d6f0008d37e41b8aceaaab27b4ec89/Reference_Implementation>
- Pinned implementation commit:
  `3991b2ae08d6f0008d37e41b8aceaaab27b4ec89`

The upstream `Reference_Implementation/NTRU+768`, `NTRU+864`, and
`NTRU+1152` sources were consolidated into one runtime-parameter
implementation. Upstream Keccak and random-byte implementations are not
included; the LiberaCrypt library's private SHA3/SHAKE and random-byte providers
are used instead. Internal symbols use the `crypto_ntru_plus_` namespace.

The upstream MIT license is reproduced in [LICENSE](LICENSE).
