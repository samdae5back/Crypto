# ML-KEM 最適化記録

## 状態と範囲

この文書は LiberaCrypt の original FIPS 203 ML-KEM 実装に対する最初の focused optimization pass を記録します。同じ runtime-dispatched source が引き続き ML-KEM-512、ML-KEM-768、ML-KEM-1024 を実装します。

この pass の優先事項は次です。

- ISO C portability と単一の runtime-selected implementation を維持する;
- architecture-specific intrinsic や assembly を避ける;
- secret-indexed table や secret-dependent control flow を追加しない;
- FIPS 203 encoding、rejection-sampling order、API behavior、failure handling を維持する;
- NTT arithmetic representation を変更したり複雑な reduction scheme を導入する前に、構造的に大きな利得を先に取る。

再現可能な benchmark が保持されるまで、この文書では throughput 数値を主張しません。以下の operation-count/loop-count reduction は source transformation から直接導ける場合にのみ記載します。

## Baseline の観察

最適化前の実装には目立つ portable hot path が 4 つありました。

1. `ByteEncode` と `ByteDecode` が encoded coefficient の各 bit を一つずつ処理していました。一般的な 10-, 11-, 12-bit polynomial encoding では polynomial ごとに数千回の小さな loop iteration が生じます。
2. `SampleNTT` は rejection-sampling candidate 2 個ごとに SHAKE128 から 3 byte だけ要求していました。underlying XOF は byte stream なので、小さい request は stream 生成に必要な Keccak work を減らさず helper/loop overhead だけを増やします。
3. K-PKE decryption は `k` 個の secret/ciphertext polynomial pair を NTT domain で個別に掛け、それぞれの product を独立に inverse-transform した後で coefficient-domain polynomial を足していました。
4. NTT path は 7-bit bit reversal を division/modulo loop で毎回再計算し、`Multiply_NTT` は各 two-coefficient product を別 helper call に通していました。

inner NTT butterfly と base multiplication にはまだ多くの一般 `% 3329` operation が残ります。この reduction の置き換えは意図的に延期します。transform 全体の coefficient range/representation invariant を変えるため proof/validation cost が高いからです。

## 1. Packed bit-reservoir encoding/decoding

### Baseline / 問題

`ByteEncode` と `ByteDecode` は coefficient bit を一つずつ処理し、inner loop で byte/bit position を再計算していました。

### 変更

両関数は `uint32_t` little-endian bit reservoir を使います。coefficient を現在の bit offset に append し、8 bit 以上利用可能になったら whole byte を emit/consume します。

総 encoded size は変わりません。256 coefficient × public `bit_width` で、全対応 width は最大 12 bit です。新しい coefficient を append する直前には reservoir に 8 bit 未満しか残らないので meaningful bit は最大 19 個です。したがって 32-bit unsigned reservoir で十分です。

### Correctness

以前の loop は coefficient bit を increasing bit order で emit/consume しました。reservoir もまったく同じ concatenation/extraction を行い、単に 1 回の C operation で複数 bit を処理します。12-bit decoding では既存 modulo `q` reduction を維持し、より小さい width では既存 power-of-two modulus semantics を維持します。

### セキュリティへの影響

loop count と shift は coefficient value ではなく public encoding width に依存します。secret-indexed memory access や coefficient-dependent branch は追加しません。

### Portability への影響

reservoir は type-punning や native-endian word load ではなく fixed-width unsigned arithmetic と byte access を使います。`mlkem_power_of_two` も small validated result を `int` に変換する前に unsigned fixed-width left shift を使います。

### 期待効果

全 ML-KEM polynomial serialization/deserialization から bit-at-a-time inner loop を除きます。最大の利得は 10-, 11-, 12-bit encoding で期待されます。まだ測定 speedup は主張しません。

## 2. SHAKE128 rate-block matrix sampling

### Baseline / 問題

`SampleNTT` は 3 byte ずつ squeeze し、12-bit candidate 2 個を parse し、256 個の accepted coefficient が得られるまで繰り返していました。

### 変更

sampler は 168-byte SHAKE128 rate block を一度に squeeze し、同じ連続 3-byte group で parse します。168 は 3 で割り切れるため candidate group が local buffer boundary をまたぎません。

### Correctness

SHAKE128 は一つの連続 output byte stream を提供します。successive squeeze size を変更しても stream は変わりません。したがって `[0..2], [3..5], ...` group で parse すると、以前と同じ candidate が同じ順序で同じ `< 3329` rejection test に渡されます。

### セキュリティへの影響

matrix generation は public matrix seed から導出されます。FIPS 203 で要求される standard rejection sampler 以外の secret-dependent index/branch を追加しません。

### Portability / memory への影響

最適化は byte array と既存 portable SHAKE API のみを使います。`SampleNTT` に 168-byte automatic buffer を追加しますが、既存 heap workspace と比べて小さく、architecture-specific vector code を避けます。

### 期待効果

sampled matrix polynomial あたりの XOF squeeze helper 呼び出しが candidate pair ごと 1 回程度から、少数の full-rate request へ減ります。Keccak output stream と必要 permutation は変わりません。削減されるのは cryptographic round ではなく周囲の helper/byte-loop overhead です。まだ benchmark 値は主張しません。

## 3. K-PKE decryption inner product の inverse NTT 1 回化

### Baseline / 問題

以前の K-PKE decryption は vector component ごとに

```text
InvNTT(s_i_hat * u_i_hat)
```

を計算し、その coefficient-domain polynomial を accumulate していました。つまり `k` 回 inverse NTT を実行していました。

### 変更

product を NTT domain で先に accumulate し、その後 inverse NTT を一度だけ行います。

```text
InvNTT(sum_i (s_i_hat * u_i_hat))
```

### Correctness

inverse NTT は ML-KEM coefficient ring 上で linear なので:

```text
sum_i InvNTT(x_i) = InvNTT(sum_i x_i).
```

pointwise base multiplication と addition は引き続き modulo `q` です。sum に対する linear inverse transform の位置だけが変わります。

### セキュリティへの影響

loop count は public parameter `k` のままです。secret-dependent branch、table lookup、early exit を追加しません。むしろ transform schedule は短くなり、引き続き parameter-determined です。

### Portability への影響

既存 NTT implementation を使う algebraic reordering だけなので、新しい integer-width、endian、alignment、compiler assumption は追加しません。

### 期待効果

K-PKE decryption ごとに正確に `k - 1` 個の inverse NTT call を削除します。

| Parameter set | 以前の inverse NTT | 現在の inverse NTT | 削除 |
| --- | ---: | ---: | ---: |
| ML-KEM-512 (`k = 2`) | 2 | 1 | 1 |
| ML-KEM-768 (`k = 3`) | 3 | 1 | 2 |
| ML-KEM-1024 (`k = 4`) | 4 | 1 | 3 |

first-pass change の中で最も明確な deterministic operation-count reduction で、decapsulation に最も直接効くと期待されます。

## 4. 小さな NTT helper cleanup

### Baseline / 問題

hot NTT path は 7-bit index を反転するため 2 で繰り返し division/modulo し、7-element temporary array を使っていました。`Multiply_NTT` もすべての pair で out-of-line basic multiplication helper を呼んでいました。

### 変更

internal transform code は fixed unsigned mask/shift operation で 7 bit を reverse します。`Multiply_NTT` が使う base two-coefficient multiplication は local `static inline` helper として利用できます。既存 `bit_rev` と `Multiply_basic` entry point は他の internal user との source-level compatibility のため維持します。

### Correctness

mask/shift network は low 7 bit の直接 permutation で、ML-KEM transform range 内の index にのみ使います。base multiplication equation は変わりません。

### セキュリティと portability への影響

bit reversal は fixed instruction-shaped source sequence を持ち、unsigned arithmetic のみを使用します。secret data で index される lookup table を追加せず、compiler extension も不要です。

### 期待効果

NTT と base multiplication 全体で繰り返される小さな arithmetic/helper overhead を削減します。inverse-NTT elimination と packing change に比べ secondary improvement と期待されます。

## 検証

repository にはすでに 3 parameter set すべてに対する ML-KEM unit coverage があります。successful key generation/encapsulation/decapsulation、implicit-rejection behavior、non-canonical public key、embedded-public-key hash validation、output clearing、overlap rejection を含みます。また ML-KEM-512、ML-KEM-768、ML-KEM-1024 KAT target もあります。

この optimization branch の acceptance evidence は:

1. 3 parameter set すべてで既存 unit suite が通る;
2. 3 ML-KEM KAT suite が byte-for-byte で通る;
3. Linux、Windows、macOS の通常 CI build/test matrix が green のまま;
4. numerical speedup を公表する前に reproducible local benchmark を保持;
5. 後の reduction rewrite はより厳密な overflow/range review と、可能な sanitizer/differential coverage を受ける。

開発中、packed codec は対応 width 全体で byte-for-byte round-trip/equivalence を確認し、7-bit reversal は 128 input 全部を確認し、inverse-NTT reordering は `k = 2, 3, 4` で以前の algebraic ordering と比較しました。これらは repository KAT/CI evidence を補助しますが代替しません。

## Benchmark 計画

ML-KEM-512/768/1024 それぞれで key generation、encapsulation、decapsulation を個別 benchmark します。compiler/version、optimization flag、host CPU/OS、warm-up policy、iteration count、median のような robust statistic を記録します。同じ build/host で pre-optimization main commit とこの branch を比較します。hosted-runner variance は制御できないため CI-host timing を published performance claim に使わないでください。

## Deferred optimization: modular reduction と NTT representation

残る最大の arithmetic question は、NTT butterfly と base multiplication で頻繁な一般 `% MLKEM_Q` operation を bounded Montgomery/Barrett-style reduction とより厳密な coefficient-range invariant に置き換えるかどうかです。

これは追加 micro-cleanup より大きな throughput opportunity の可能性がありますが、arithmetic representation/range argument を変えるため low-risk pass には意図的に含めません。portable version は AVX2/NEON や secret-dependent behavior なしに ISO C で書けますが、explicit range proof、KAT、strict warning/sanitizer build、before/after benchmark 後にのみ採用すべきです。

推奨順序:

1. この first-pass branch を benchmark して残る profile を確認;
2. NTT/base reduction が依然 dominant なら別 commit/branch で portable bounded reduction path を実装;
3. 新 path が independent validation を受けるまで現在の simple arithmetic を comparison baseline として保持;
4. architecture-specific AVX2/NEON backend は portable implementation の置き換えではなく別 future layer として検討。

別の memory trade-off も残っています。現在は maximum-sized heap workspace を使い full matrix を materialize します。on-the-fly matrix generation や tighter parameter-sized workspace は memory を減らせますが、追加 SHAKE work、allocator behavior、code complexity、zeroization consideration との trade-off があります。この trade-off は現在の throughput pass に混ぜず独立に測定すべきです。
