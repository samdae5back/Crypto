# AIMer reference backend

This directory is derived from the AIMer reference implementation published
by Samsung SDS at commit `e47c497f3552c234e0ca8368df9bb629af9608ce`
(2026-01-30):
<https://github.com/samsungsds-opensource/AIMer/tree/e47c497f3552c234e0ca8368df9bb629af9608ce>.
The upstream package SHA-256 is
`d7bbdb28e70dad021da2057bc0b4802585770cbc2d7449acfcd770d8bc624521`.

The integration keeps the AIM2/v2.1 parameter sets required by the supplied
known-answer tests. It combines the six upstream build-time configurations
into one runtime-dispatched implementation, namespaces backend symbols, and
uses Crypto's shared SHAKE, endian, random-byte, and zeroization utilities.

The later AIMer v3/AIM3 package is intentionally not used because it changes
the scheme and signature sizes and is not compatible with these vectors.
