# HAETAE known-answer vectors

The `haetae120_v1_2_0.kat`, `haetae180_v1_2_0.kat`, and
`haetae260_v1_2_0.kat` files are byte-for-byte copies of the response files
distributed with the official HAETAE 1.2.0 reference implementation:

- Project page: <https://kpqc.cryptolab.co.kr/haetae>
- Official archive identifier: `1pW6YS1wZ1gm8Neb8pY5EyYTkkdRIDmJ6`
- Archive SHA-256:
  `e54f8f962eefadbb2929bca292797bc7ca18769fb9a273c10204f3887fd83e84`

The copied response-file hashes are:

| File | SHA-256 |
| --- | --- |
| `haetae120_v1_2_0.kat` | `508e9664a36eb992d011702cfdbb4816d17b3ea5755c0728ffa84219b8244348` |
| `haetae180_v1_2_0.kat` | `bb388a12deeb953205429ad1281b38467678f9ebc21aa9d8c8486f20bd02d31a` |
| `haetae260_v1_2_0.kat` | `3923b6a811942205accb75fff688bbe6cbc4bf3ee031ff1b190ca1e80f7a79d1` |

The official response format omits the per-record context even though the
generator derives it from the seeded AES-256 CTR-DRBG. The test runner replays
the documented call sequence for every record: a 32-byte key-generation seed,
a 32-byte signature randomizer, one context-length byte, and the context bytes.
It then compares the public key, private key, and signature exactly.

The unsuffixed `haetae120.kat`, `haetae180.kat`, and `haetae260.kat` files are
project-generated context-explicit regression vectors for HAETAE 1.1.2. The
generating implementation had been cross-checked against other reference
vectors, but these files are not authoritative or byte-for-byte official 1.2.0
response files and a generator or integration error cannot be ruled out.
HAETAE 1.2.0 changed the hyperball sampler while retaining verification
compatibility, so these files remain unchanged and are exercised as legacy
signature-verification regressions. Their hashes are:

| File | SHA-256 |
| --- | --- |
| `haetae120.kat` | `4715d8a3cc11574cbac34ed821f24bb33db90876e3048abb15dffb0568e36d99` |
| `haetae180.kat` | `de61eecf10fd9e4fed830bc36f0ea404bd53ca9f777577748f64d50bc83513b8` |
| `haetae260.kat` | `da0c209b442055aa05e5ef870f7a9626785f602454079319eb13a2ea757cef21` |
