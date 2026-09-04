# ML-KEM portable Barrett reduction

## 範囲

この文書は 2 回目の portable ML-KEM arithmetic optimization pass を記録します。すでに merge 済みの hot-path optimization を出発点とし、portable NTT 実装が使う ordinary-domain modular arithmetic だけを変更します。Montgomery representation は別の測定可能な変更として意図的に先送りします。

目標は次です。

- `q = 3329` で全 NTT coefficient を canonical `[0, q)` に保つ;
- NTT butterfly と base multiplication から一般の signed `% 3329` を除く;
- fixed-width unsigned ISO C arithmetic のみを使用する;
- secret-dependent table index や source-level branch を避ける;
- reduction bound と correctness argument を明示する。

再現可能な benchmark が保持されるまでは数値的 speedup を主張しません。compiler は constant division を strength-reduce でき、64-bit reciprocal multiply のコストは 32-bit と 64-bit target で異なり得ます。division/remainder operation と cleanup loop における deterministic source-level reduction は measured throughput と分けて記録します。

## Canonical coefficient invariant

最適化された transform は各 butterfly boundary で次の invariant を維持します。

```text
0 <= coefficient < q
```

canonical `a` と `b` に対し:

```text
0 <= a + b < 2q
0 <= a + q - b < 2q
```

したがって modular addition/subtraction は固定形の conditional correction を一度行うだけでよく、一般 reduction は不要です。

twiddle multiplication は次の範囲です。

```text
0 <= z * a <= (q - 1)^2 = 11,075,584.
```

現在の base multiplication が reduce する最大値は、この bounded term 2 個の和です。

```text
2 * (q - 1)^2 = 22,151,168.
```

これは `2^31` と `2^32` を大きく下回ります。それでも実装は unsigned fixed-width intermediate を使うため、signed overflow や negative-remainder semantics は proof に含まれません。

## Barrett 構成

次のように置きます。

```text
B  = 2^32
q  = 3329
mu = floor(B / q) = 1,290,167.
```

任意の `uint32_t` 値 `x` に対し:

```text
qhat = floor(x * mu / B)
r    = x - qhat * q.
```

次が成り立つため:

```text
B/q - 1 < mu <= B/q
```

`0 <= x < B` のもとで `x/B` を掛けると:

```text
x/q - x/B < x*mu/B <= x/q.
```

`0 <= x/B < 1` なので floor を取ると `qhat` は

```text
floor(x/q)
```

または正確に 1 小さい値です。したがって:

```text
0 <= r < 2q.
```

最後に `q` を一度引き、subtraction が underflow したときだけ復元すれば、modulo `q` の congruence を保ったまま `[0, q)` の一意な representative が得られます。

実装は `x * mu` を `uint64_t` で計算し 32 bit 右 shift した後、`uint32_t` で final correction を行います。LiberaCrypt はすでに他の箇所で正確な 64-bit unsigned arithmetic を必要とし利用しているため、新しい integer width requirement は追加されません。

## Fixed-shape final correction

入力が `[0, 2q)` にあると分かっている場合、`uint32_t` で次を計算します。

```text
reduced = value - q
mask    = 0 - (reduced >> 31)
result  = reduced + (q & mask)
```

`value >= q` なら `reduced` は `[0, q)` で high bit は 0 です。`value < q` なら unsigned subtraction は `2^32` 付近へ wrap し、`q < 2^31` のため high bit が 1 になります。mask が正確に 1 個の `q` を復元します。

source には coefficient-dependent `if` はありません。LiberaCrypt の他の箇所と同様、これはすべての compiler/processor に対する普遍的な物理 constant-time 保証ではなく constant-schedule source construction と説明します。

## NTT の同値性

以前の forward butterfly は次と同値でした。

```text
t = z*b mod q
b = a-t mod q
a = a+t mod q
```

途中で負の C remainder が生じ得て、最後に normalization pass を行っていました。新しい形は同じ residue class を計算しながら、その butterfly ですぐ両出力を canonicalize します。

```text
t = Barrett(z*b)
b = canonical_sub(a, t)
a = canonical_add(a, t)
```

inverse butterfly も

```text
z * (b-a) mod q
```

を

```text
z * canonical_sub(b, a) mod q.
```

へ置き換えます。`canonical_sub(b,a) == b-a (mod q)` なので ring element は変わりません。`3303 = 128^-1 mod q` の final multiplication も同じ ordinary-domain Barrett helper で reduce するため Montgomery factor は入りません。

## Base multiplication の同値性

次に対して:

```text
(a0 + a1 X)(b0 + b1 X) mod (X^2 - r)
```

実装は引き続き

```text
c0 = a0*b0 + a1*b1*r mod q
c1 = a0*b1 + a1*b0   mod q.
```

を計算します。`a1*b1` は `r` を掛ける前に canonical residue へ reduce されます。intermediate を congruent residue に置き換えても modulo `q` の最終結果は変わりません。final wide value は `2(q-1)^2` 以下なので、上の 32-bit Barrett input bound をそのまま使えます。

## セキュリティへの影響

この最適化は `Z_q` の同じ element に対する integer representative だけを変更します。ML-KEM parameter、NTT root、wire encoding、rejection sampling、key/ciphertext format、decapsulation rejection logic は変わりません。

全 transform loop bound と twiddle index は引き続き public で parameter-determined です。新しい reduction helper は secret-indexed lookup も source-level coefficient-dependent branch も追加しません。

## Portability への影響

以前の実装は butterfly 内で負になり得る値に signed `% q` を使い、最後に negative representative を修正していました。新しい実装は NTT 全体で arithmetic を non-negative canonical に保ち、defined wrap/shift semantics を持つ `uint32_t`/`uint64_t` operation を使います。そのため hot transform path から negative remainder handling への依存を除き、signed right shift、type punning、alignment assumption、native-endian word load、compiler intrinsic、SIMD、assembly を使用しません。

主な performance caveat は意味論ではなく architecture に関するものです。一部 32-bit target では 64-bit reciprocal multiplication が native 64-bit target より高価な場合があります。explicit Barrett multiply が各代表 platform で throughput 上有利かは benchmark で判断する必要があります。canonical add/sub transformation は butterfly addition/subtraction から一般 reduction を除くため、それとは独立して有用です。

## Repository CI 前に行った検証

reduction formula は 0 から現在の ML-KEM wide intermediate 最大値まで、通常の integer `% 3329` と機械的に比較しました。

```text
0 .. 22,151,168
```

mismatch はありませんでした。

canonical addition/subtraction は次の全 pair に対して数学的 modulo と exhaustive に比較しました。

```text
a, b in [0, 3329).
```

old/new forward/inverse NTT formula も 1,000 個の random canonical 256-coefficient polynomial で比較し mismatch はありませんでした。

これらの development check は repository evidence を補助しますが置き換えません。acceptance には既存 ML-KEM-512/768/1024 KAT と unit test、通常の Linux/Windows/macOS CI build matrix が引き続き必要です。

## Montgomery を分離する理由

Montgomery reduction も `q = 3329` に対して数学的には有効ですが、`REDC(x)` は `x * R^-1 mod q` を計算します。したがって twiddle と transform scaling factor を適切な Montgomery domain で追跡せず ordinary `% q` の代わりに直接使うと誤りです。

この Barrett pass はすべての table と coefficient を既存 ordinary representation のままにします。将来の Montgomery pass は explicit domain invariant、変換済み twiddle constant、forward/inverse scaling proof、KAT validation、before/after benchmark を備えた別 commit にすべきです。この分離により、後の performance comparison と regression diagnosis がはるかに明確になります。
