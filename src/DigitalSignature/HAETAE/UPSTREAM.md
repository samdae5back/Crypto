# HAETAE

Reference source code for HAETAE -- efficient and compact KpqC-winning, lattice-based, post-quantum Digital Signature Algorithm (DSA). Visit our [official website](https://www.kpqc.cryptolab.co.kr/haetae) for more information.

HAETAE is a module lattice-based signature scheme for shorter and easily maskable signatures. While based on the Fiat-Shamir with Aborts paradigm, like the NIST-selected Dilithium signature scheme, our design choices target an improved complexity/compactness compromise that is highly relevant for many space-limited scenarios such as DNSSEC. We primarily focus on reducing signature and verification key sizes so that signatures fit into one TCP or UDP datagram while preserving a high level of security against various attacks.

## Upstream release

This port is based on the official HAETAE 1.2.0 release archive:

- Project: <https://www.kpqc.cryptolab.co.kr/haetae>
- Archive: <https://drive.google.com/file/d/1pW6YS1wZ1gm8Neb8pY5EyYTkkdRIDmJ6/view>
- Archive ID: `1pW6YS1wZ1gm8Neb8pY5EyYTkkdRIDmJ6`
- SHA-256: `e54f8f962eefadbb2929bca292797bc7ca18769fb9a273c10204f3887fd83e84`

## Build

This port is built through the repository's root CMake project. The original
release archive contains separate build instructions for its standalone
reference implementation.

## License

The codes and the specifications are under the MIT license.

## Contributors

- Jung Hee Cheon (Seoul National University (SNU) & CryptoLab Inc.)
- Hyeongmin Choe (University of Luxembourg)
- Julien Devevey (ANSSI)
- Tim Güneysu (Ruhr University Bochum & DFKI)
- Dongyeon Hong (Samsung Electronics)
- Minhyeok Kang (CryptoLab Inc.)
- Taekyung Kim (CryptoLab Inc.)
- Jeongbeen Ko
- Markus Krausz (TÜV Informationstechnik GmbH)
- Georg Land (Intel)
- Marc Möller (Ruhr University Bochum) *
- Junbum Shin (CryptoLab Inc.)
- Damien Stehlé (CryptoLab Inc.)
- MineJune Yi
