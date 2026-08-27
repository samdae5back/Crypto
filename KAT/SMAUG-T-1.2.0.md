# SMAUG-T 1.2.0 known-answer tests

These files are byte-for-byte copies of the official SMAUG-T 1.2.0 KEM
response files for mode1, mode3, and mode5. No line-ending, header, or field
conversion was applied.

- Official release page: <https://sites.google.com/view/smaug-and-haetae/smaug-t>
- Official 1.2.0 archive: <https://drive.usercontent.google.com/download?id=1L6wLwZu65OHFDz2iPqZdEQOwcqJ-9xxX&export=download&confirm=t>
- Archive SHA-256: `ccb58f42043296174e10fc7af520f0a49076d8c2245bd8e66d1b88bcae568c90`

| Repository file | Official archive file | SHA-256 |
| --- | --- | --- |
| `smaugt128_v1_2_0.kat` | `kat/PQCkemKAT_smaugt_mode1.rsp` | `eaa19060fed221b98ec04c204706ba3362141188cb336309768eca969bb6e5ff` |
| `smaugt192_v1_2_0.kat` | `kat/PQCkemKAT_smaugt_mode3.rsp` | `2bcec82347ba297fd70a035f3eeebdf1d7ed461161b5b2b6bda6df9ef5385099` |
| `smaugt256_v1_2_0.kat` | `kat/PQCkemKAT_smaugt_mode5.rsp` | `0ff3723b1aa2c216d45af27b9051f8bdd2d7ccd46fab16ae0337b4d05d192e9e` |

## Why the filenames are versioned

The pre-existing unversioned `smaugt128.kat`, `smaugt192.kat`, and
`smaugt256.kat` files contain the SMAUG-T 1.1.1 vectors. Upstream advises
against using version 1.1.1 because its reference implementation contains
correctness defects. Version 1.2.0 corrects the discrete-Gaussian output
index, the public-vector initialization length, and a packed-polynomial output
initialization length; these corrections change the official KAT responses.

The `_v1_2_0` suffix prevents a 1.2.0 implementation from being tested
against legacy 1.1.1 answers while retaining the older files unchanged for
provenance.
