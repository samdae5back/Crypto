# Constant-time ポリシー

LiberaCrypt は、すべての算術 primitive を `_ct` と `_vartime` の二重実装にすることはしません。secret-dependent loop count、branch、table index、normalization、operand length が秘密情報を露出し得る箇所で timing-sensitive behavior を分離します。

一般の bignum layer は ordinary/public data 向けに最適化されたまま維持し、より強い timing behavior が必要な call site では専用の fixed-width secret path を使用します。

## Public exponentiation と secret exponentiation

public/non-secret exponentiation は adaptive sliding window、odd-power precomputation、direct table lookup、zero-bit skipping、trivial-value early exit などの variable-time 最適化を使用できます。

secret exponentiation は fixed-width Montgomery path を使用します。

- secret exponent の significant length ではなく、公開されている modulus の全幅を走査します。
- スケジュールされた各 bit で必要な square/multiply candidate を計算します。
- secret-dependent table index や multiply branch の代わりに mask で結果を選択します。
- secret residue を fixed-width Montgomery storage に保持します。
- secret result には fixed-count normalization を使用します。
- 解放前に secret temporary storage を消去します。

RSA private operation と ElGamal secret exponentiation はこのポリシーを使用します。

## Secret storage の境界

通常の `LiberaCBignum` はすでに significant `LENGTH` を表現しています。既存の variable-length object を fixed-width secret storage に変換する処理を、その既存表現に対して真に constant-schedule と呼ぶことはできません。

そのため LiberaCrypt は fixed-width secret storage への promotion を明示的な境界として扱います。RSA `D` や ElGamal `X` のような persistent secret は確立時に promotion され、その後の secret copy と serialization は caller が選んだ公開された全幅を走査できます。

この区別により、実際には secret object の significant length に従っている helper を constant-time と誤って呼ぶことを避けます。

## その他の算術

- public data では generic add/subtract、reduction、compare、normalization、serialization は variable-time のままで構いません。
- fixed-width secret helper は、使われない重複算術スタックを維持するのではなく、実際の secret call site が必要としたときに追加します。
- secret modular arithmetic は secret residue を generic division-style remainder path に通すより fixed-width Montgomery representation を優先します。
- prime generation と Miller-Rabin は意図的に variable-time です。candidate と witness の control flow は persistent secret exponent state として扱いません。

## 認証比較

authentication-tag verification は、アルゴリズムごとの early-exit comparison loop ではなく共通の constant-time byte-equality helper を使用します。

## 主張の範囲

constant-time 実装は、選択された software timing side channel を減らすためのものです。ライブラリの全操作、compiler output、OS、hardware、完全な application があらゆる attacker model で side-channel resistant であるという主張ではありません。

新しい constant-time の主張を追加する場合は、次を明示してください。

1. どの値が secret か;
2. どの公開 width または iteration bound が schedule を固定するか;
3. どの branch、memory index、loop count から secret dependence を除いたか;
4. variable-length generic helper に暗黙に fallback していないことをどう検証したか。
