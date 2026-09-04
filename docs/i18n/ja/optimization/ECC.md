# Portable short-Weierstrass ECC 算術

この layer は公開 P-256、P-384、P-521 ECDH/ECDSA 実装で共通に使う prime-field と point arithmetic を提供します。key-agreement と signature API は `KeyAgreement.h` と `DigitalSignature.h` から公開され、lower-level field、point、scalar interface は内部実装のままです。

production arithmetic は意図的に scalar-multiplication policy を 2 つだけ公開します。public scalar 用の optimized variable-time path と、secret scalar 用の fixed-schedule path です。textbook affine 実装は correctness oracle と benchmark baseline として test tree にのみ残し、LiberaCrypt library には link しません。

## 対応 domain parameter

内蔵 parameter record は NIST SP 800-186 の NIST P-256、P-384、P-521 curve をカバーします。いずれも `a = -3` の prime field 上 short-Weierstrass curve です。SEC 1 point-at-infinity、compressed、uncompressed encoding は decoder の明示的 infinity policy のもとで受け付けます。

X25519 は意図的にこの構造で表現しません。Montgomery curve、byte order、clamping、ladder rule は別 backend を使い、short-Weierstrass の別 parameter choice のようには扱いません。

## 算術表現

- 固定最大 storage: little-endian 32-bit limb 17 個（P-521 まで十分）。
- Field representation: curve 固有の `R`、`R^2`、`-p^-1 mod 2^32` 定数を使う Montgomery residue。
- Group-order scalar representation: `n` modulo の別 Montgomery domain と curve 固有定数。portable word arithmetic は共有するが field-modulus 値は再利用しない。
- Multiplication: portable full-width schoolbook multiplication の後に word-by-word Montgomery reduction。
- Inversion: `p - 2` への fixed-exponent powering。
- Square root: `(p + 1) / 4` への fixed-exponent powering。3 つの field prime はすべて modulo 4 で 3。

実装は `unsigned __int128`、compiler intrinsic、assembly、VLA、host-endian cast を意図的に避けます。これにより同じ source を MSVC と legacy 32-bit-oriented C toolchain で使用できます。architecture-specific または 64-bit-limb backend は target-specific measurement で正当化できる場合、将来同じ internal interface の後ろに追加できます。

この小さな固定幅では Karatsuba を追加せず schoolbook multiplication を維持します。Karatsuba は当然の勝ちと仮定せず benchmark-driven option として残します。追加 temporary と carry handling のコストが、特に 32-bit/older target では 8、12、17 limb の小さい幅で節約分を上回る可能性があるためです。

## Point-operation path

### Test-only textbook reference oracle

`tests/ECC/Reference.c` は direct formula を使う affine double-and-add を実装します。scalar bit と exceptional case で branch し、各 affine addition/doubling で field inversion を行います。この実装は独立 correctness oracle と benchmark baseline のためだけに存在し、production source API の一部ではなく LiberaCrypt に link されません。

### Public optimized variable-time path

`ecc_scalar_vartime.c` は Jacobian coordinate と固定 four-bit window を使用します。16 個の public-point multiple を precompute し、leading zero window を skip し、direct public table index を使用します。最後の inversion 1 回で結果を affine form に変換します。この path は ECDSA verification component のような public scalar 専用です。

window width は意図的に控えめです。fixed maximum structure で 16 個の Jacobian point は最大約 3.3 KiB で、より大きな window は legacy environment の stack/table pressure を増やします。別 width は same-target benchmark に基づいて選ぶべきです。

### Secret fixed-schedule path

`ecc_scalar_secret.c` は fixed encoded scalar width を検証し、curve の正確な scalar bit count 全体に Montgomery ladder を実行します。各 bit で complete-behaviour Jacobian addition 1 回、Jacobian doubling 1 回、masked conditional swap 2 回を行います。scalar-indexed table を使わず scalar bit で branch しません。ladder state は変換後に明示的に消去します。

`ecc_projective.c` は exceptional behavior を caller branch から独立させます。generic Jacobian addition と doubling candidate を両方評価し、equal point、opposite point、いずれか input が infinity の場合に mask-select で正しい結果を選びます。したがって generic addition formula 自体が数学的 complete unified formula でなくても、operation boundary では *complete-behaviour* になります。

既存 bignum policy と同様、これは普遍的な物理 constant-time 保証ではなく fixed source-level schedule と説明します。ISO C はすべての compiler/processor に同じ instruction/arithmetic latency を強制できず、power、EM、speculative、fault、compiler-introduced side channel への耐性も主張しません。

## ECDH 統合

`src/KeyAgreement/ecdh.c` は private-key operation に fixed-schedule secret-scalar path だけを使用します。private key は `1 <= d < n` の fixed-width big-endian scalar で、key generation は OS から uniformly random candidate を取得し、unused high bit を mask し、group order に対して rejection-sample します。

generated public key は uncompressed SEC 1 point です。agreement は compressed/uncompressed SEC 1 peer point を受け付け、common decoder で infinity と invalid curve point を拒否し、`dQ` の fixed-width big-endian x-coordinate を返します。対応する NIST curve は cofactor 1 なので accepted finite on-curve peer point は prime-order group に属します。

raw x-coordinate は ECDH 内部で KDF に通しません。public API はこれを HKDF のような protocol-appropriate KDF に入力すべき key-agreement material と文書化します。

## ECDSA 統合

`src/DigitalSignature/ECDSA/ecdsa.c` は P-256、P-384、P-521 の ECDSA をサポートします。private key は fixed-width big-endian scalar、generated public key は uncompressed SEC 1 point で、verification は compressed point も受け付けます。signature は ASN.1 DER ではなく fixed-width raw `r || s` encoding を使い、signing は low-s normalization を適用しません。

message hash は ECDSA left-truncation と conditional reduction rule で変換します。public API は選択 curve の security strength 以上の collision strength を持つ fixed-output SHA-2/SHA-3 を受け付けます。per-message nonce は選択 message hash を HMAC に使う RFC 6979 に従います。16 個の nonce candidate を固定 batch で生成し、最初の valid candidate を mask-select することで normal signing path の scalar-dependent early exit を避けます。

private-key public derivation と nonce-point multiplication は fixed-schedule secret-scalar ladder を使用します。group order modulo 算術は専用 scalar Montgomery domain を使い、`n - 2` fixed-exponent inversion を含みます。verification は public value のみを扱うため `uG` と `vQ` に four-bit variable-time multiplication path を使用します。

## X25519 backend

`src/KeyAgreement/x25519.c` は RFC 7748 を 16 個の little-endian radix-2^16 limb で別実装します。product は portable `uint64_t` に accumulate し、reduction は `2^256 = 38 (mod 2^255 - 19)` を使用します。`unsigned __int128` や target-specific intrinsic を使わず同じ source を MSVC と portability-oriented build matrix で利用できます。

scalar input は内部で copy/clamp します。Montgomery ladder は masked conditional swap で 255 scalar bit 全部を scan し、inversion は固定公開 exponent を使用します。peer u-coordinate は high input bit masking と non-canonical encoding を field prime modulo へ reduce する動作を含む RFC 7748 decoding rule に従います。shared-secret derivation は all-zero result を拒否し、caller が low-order peer input を暗黙に受け入れないようにします。

## エンコーディングと検証

SEC 1 decoder は次を拒否します。

- 不正な長さまたは未対応 prefix;
- non-canonical coordinate (`x >= p` または `y >= p`);
- right-hand side が quadratic residue でない compressed point;
- curve equation を満たさない point;
- caller が明示的に許可していない infinity。

secret scalar validation は fixed encoded width を scan し、argument/length validation 後に scalar-dependent early return をせず `1 <= k < n` の checks を統合します。optimized public path は timing が明示的に secret-safe でないため、短い encoding を許可し leading zero byte を trim できます。reference oracle も同様に単純な variable-time semantics を持ちますが test のみです。

## 検証

focused ECC arithmetic test は次をカバーします。

- P-256、P-384、P-521 で standard generator が on-curve finite point として accept されること;
- SEC 1 compressed/uncompressed generator round trip;
- 3 curve すべての独立 `2G` affine coordinate を test-only textbook reference result と比較;
- zero、`n - 1`、`n` の scalar validity boundary;
- 全対応 order の scalar Montgomery multiplication、modular addition、fixed-exponent inversion、canonical import、one-step reduced import;
- scalar 1 と 2 で test-only affine oracle、four-bit windowed Jacobian、fixed-schedule ladder multiplication が一致;
- curve ごとに 96 個の non-zero scalar value で test oracle と両 production multiplication path の deterministic differential comparison。

public key-agreement test は RFC 7748 Alice/Bob X25519 vector、3 NIST curve の bilateral ECDH agreement、compressed SEC 1 peer key、invalid zero ECDH scalar、X25519 all-zero rejection、OS-random key-generation round trip もカバーします。ECDSA test は RFC 6979 P-256/SHA-256、P-384/SHA-384、P-521/SHA-512 vector、SHA-3 key-generation/sign/verify round trip、deterministic repeatability、compressed public key、malformed key/signature、output clearing、buffer/overlap validation を含みます。

ECC validation workflow は hosted Ubuntu、macOS、Windows runner で focused arithmetic と ECDSA test を build/run し、Ubuntu ASan/UBSan run を追加します。通常 repository CI は同じ 3 OS で public key-agreement と ECDSA test を build します。

## Benchmarking

repository benchmark は test/benchmark target でもあるため、textbook oracle を production library に追加せず link できます。3 curve で test-only reference baseline と 2 production path の multiplication あたり median CPU microseconds を出力します。scalar は意図的に full-width かつ group order に近く、tiny scalar により public implementation が人工的に速く見えないようにします。affine reference path は timing sample ごとに 1 回、より高速な Jacobian path は timer noise を減らすため repeated operation を使います。

benchmark はすべての processor に対する performance promise ではなく comparative evidence です。hosted-runner result は、より攻撃的な field representation、大きな window、Karatsuba、architecture-specific backend を選ぶ前に pull request とともに保持してください。
