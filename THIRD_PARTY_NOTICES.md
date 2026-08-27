# Third-party notices

This repository vendors the following upstream implementations for the FIPS
post-quantum signature backends. They are kept inside the corresponding private
algorithm directories so a normal source checkout is directly buildable. The
license grants and notices in those vendored trees continue to apply to their
respective files and are not replaced by the top-level project license.

## mldsa-native

- Project: `pq-code-package/mldsa-native`
- Pinned commit: `6d661fd1865b38d8612692c52160cf76193785fb`
- Purpose: FIPS 204 ML-DSA-44, ML-DSA-65, and ML-DSA-87 backend
- Upstream SPDX expression: `Apache-2.0 OR ISC OR MIT`
- Vendored source-code files are used under the MIT licensing alternative.
- Documentation files marked `CC-BY-4.0` retain that license.

Vendored path: `src/DigitalSignature/ML-DSA/Backend/`

The adapter in `src/DigitalSignature/ML-DSA/` builds the portable upstream
source in a multi-level configuration and supplies randomness through this
library's private operating-system entropy adapter.

## slhdsa-c

- Project: `pq-code-package/slhdsa-c`
- Pinned commit: `174c02e42257f95c210963272877c49dbb50070f`
- Purpose: FIPS 205 SLH-DSA SHA2/SHAKE 128/192/256 small/fast parameter sets
- Upstream SPDX expression: `Apache-2.0 OR ISC OR MIT`
- Vendored source-code files are used under the MIT licensing alternative.

Vendored path: `src/DigitalSignature/SLH-DSA/Backend/`

The original copyright and license files remain as `Backend/LICENSE` in each
vendored source tree. Except for those separately identified third-party files,
the top-level project's original source is licensed under `AGPL-3.0-only` as
declared in `README.md`, with the complete license text supplied in `LICENSE`.
