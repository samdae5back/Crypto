# Third-party notices

This repository vendors and adapts upstream implementations for its
post-quantum cryptography backends. They are kept inside the corresponding
private algorithm directories so a normal source checkout is directly
buildable. The license grants and notices in those upstream trees continue to
apply to their respective files and are not replaced by the top-level project
license.

Where applicable, the entries below distinguish the algorithm's official
specification or project page from the exact implementation revision vendored
by LiberaCrypt. A Git repository listed as the vendored implementation source
should not be read as replacing the algorithm's official specification or
project provenance.

## mldsa-native

- Algorithm standard: NIST FIPS 204, Module-Lattice-Based Digital Signature
  Standard: <https://csrc.nist.gov/pubs/fips/204/final>
- Vendored implementation: `pq-code-package/mldsa-native`:
  <https://github.com/pq-code-package/mldsa-native>
- Pinned implementation commit: `6d661fd1865b38d8612692c52160cf76193785fb`
- Reference-code lineage documented by mldsa-native: CRYSTALS-Dilithium
  reference implementation:
  <https://github.com/pq-crystals/dilithium/tree/master/ref>
- Purpose: FIPS 204 ML-DSA-44, ML-DSA-65, and ML-DSA-87 backend
- Upstream SPDX expression: `Apache-2.0 OR ISC OR MIT`
- Vendored source-code files are used under the MIT licensing alternative.
- Documentation files marked `CC-BY-4.0` retain that license.

Vendored path: `src/DigitalSignature/ML-DSA/Backend/`

The adapter in `src/DigitalSignature/ML-DSA/` builds the portable upstream
source in a multi-level configuration and supplies randomness through this
library's private operating-system entropy adapter.

## slhdsa-c

- Algorithm standard: NIST FIPS 205, Stateless Hash-Based Digital Signature
  Standard: <https://csrc.nist.gov/pubs/fips/205/final>
- Algorithm predecessor/project: SPHINCS+ official site:
  <https://sphincs.org/>
- SPHINCS+ reference code accompanying the NIST submission:
  <https://github.com/sphincs/sphincsplus/tree/master/ref>
- Vendored implementation: `pq-code-package/slhdsa-c`:
  <https://github.com/pq-code-package/slhdsa-c>
- Pinned implementation commit: `174c02e42257f95c210963272877c49dbb50070f`
- Purpose: FIPS 205 SLH-DSA SHA2/SHAKE 128/192/256 small/fast parameter sets
- Upstream SPDX expression: `Apache-2.0 OR ISC OR MIT`
- Vendored source-code files are used under the MIT licensing alternative.

Vendored path: `src/DigitalSignature/SLH-DSA/Backend/`

FIPS 205 standardizes SLH-DSA based on SPHINCS+. The source actually vendored by
LiberaCrypt is the pinned `slhdsa-c` implementation above; the SPHINCS+ links
are recorded separately as the official algorithm/reference-code lineage.

## AIMer

- Project: AIMer
- Official homepage: <https://aimer-signature.org/>
- Official reference code: <https://github.com/samsungsds-opensource/AIMer>
- Pinned reference-code commit: `e47c497f3552c234e0ca8368df9bb629af9608ce`
- Pinned reference package:
  <https://github.com/samsungsds-opensource/AIMer/blob/e47c497f3552c234e0ca8368df9bb629af9608ce/AIMer-package.zip>
- Package SHA-256: `d7bbdb28e70dad021da2057bc0b4802585770cbc2d7449acfcd770d8bc624521`
- Purpose: AIM2-based AIMer 128/192/256 fast and small signature parameter sets
- Upstream license: MIT, Copyright 2022-2025 Samsung SDS

Vendored path: `src/DigitalSignature/AIMer/Backend/`

The upstream `Open Source Notice.txt` is preserved as `Backend/NOTICE`. It
records material from PQClean and SMAUG-T under MIT, CRYPTOGAMS under either
the 3-Clause BSD license or its GPL alternative, and NIST-developed software
under the NIST software notice. This integration uses the permissive
3-Clause BSD alternative for any CRYPTOGAMS material, not the GPL alternative.
The complete CRYPTOGAMS and NIST notices must remain intact in source and
binary distributions. NIST-derived modified works must also identify the
date and nature of their changes and acknowledge NIST as their source, as
required by that notice.

## NTRU+

- Project: NTRU+
- Official homepage: <https://www.ntruplus.org/>
- Official reference implementation, pinned to the vendored revision:
  <https://github.com/ntruplus/ntruplus/tree/3991b2ae08d6f0008d37e41b8aceaaab27b4ec89/Reference_Implementation>
- Pinned implementation commit: `3991b2ae08d6f0008d37e41b8aceaaab27b4ec89`
- Purpose: NTRU+768, NTRU+864, and NTRU+1152 KEM parameter sets
- Upstream license: MIT, Copyright 2024-2026 NTRU+ Team

Vendored path: `src/KeyEncapsulation/NTRU-Plus/`

The three upstream build-time configurations are consolidated into one
runtime-parameter implementation. Upstream Keccak and random-byte sources are
not included; the library's private shared implementations are used instead.
The exact source pin and adaptation are recorded in `UPSTREAM.md`, and the
complete MIT text is supplied in `LICENSE`.

## SMAUG-T

- Project: SMAUG-T
- Pinned version: 1.2.0
- Official release/project page:
  <https://sites.google.com/view/smaug-and-haetae/smaug-t>
- Official 1.2.0 reference-implementation archive:
  <https://drive.usercontent.google.com/download?id=1L6wLwZu65OHFDz2iPqZdEQOwcqJ-9xxX&export=download&confirm=t>
- Archive SHA-256: `ccb58f42043296174e10fc7af520f0a49076d8c2245bd8e66d1b88bcae568c90`
- Purpose: SMAUG-T 128/192/256 KEM parameter sets
- Upstream license: MIT, Copyright 2026 Team SMAUG-T

Vendored path: `src/KeyEncapsulation/SMAUG-T/`

Version 1.2.0 is used because the official project identifies implementation
errors in version 1.1.1. The three upstream build-time configurations are
consolidated into one runtime-parameter implementation. Upstream Keccak and
random-byte sources are not included; the library's private shared
implementations are used instead. Full provenance and adaptation details are
recorded in `UPSTREAM.md`, and the complete MIT text is supplied in `LICENSE`.

## HAETAE

- Project: HAETAE
- Pinned version: 1.2.0
- Official release/project page: <https://kpqc.cryptolab.co.kr/haetae>
- Official 1.2.0 reference-implementation archive:
  <https://drive.usercontent.google.com/download?id=1pW6YS1wZ1gm8Neb8pY5EyYTkkdRIDmJ6&export=download&confirm=t>
- Archive SHA-256: `e54f8f962eefadbb2929bca292797bc7ca18769fb9a273c10204f3887fd83e84`
- Purpose: HAETAE-120, HAETAE-180, and HAETAE-260 signature parameter sets
- Upstream license: MIT, Copyright 2026 Team HAETAE

Vendored path: `src/DigitalSignature/HAETAE/`

HAETAE includes the byte-aligned rANS encoder and decoder by Fabian "ryg"
Giesen (2014), published as public-domain software at
<https://github.com/rygorous/ryg_rans>. Its public-domain attribution is
preserved in `haetae_rans_byte.h` and must remain with redistributed copies.
Upstream Keccak and random-byte sources are not included; the library's
private shared implementations are used instead.

The original copyright, license, and notice files identified above must remain
with the applicable vendored sources and distributions. Except for those
separately identified third-party files, the top-level project's original
source is licensed under `AGPL-3.0-only` as declared in `README.md`, with the
complete license text supplied in `LICENSE`.
