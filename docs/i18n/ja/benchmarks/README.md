# ベンチマーク

LiberaCrypt では、ベンチマークのソースコードとベンチマーク結果の解釈は異なる役割を持ちます。

## リポジトリ構成

```text
benchmarks/          ベンチマークプログラムと fixture
docs/benchmarks/     ベンチマーク構成と結果の読み方
docs/optimization/   コンポーネント別の測定結果と実装判断
```

リポジトリ直下の `benchmarks/` には現在、Bignum と ECC に焦点を当てたベンチマークプログラムがあります。アルゴリズム別の結果表や、その結果に基づく判断は main README に複製せず、対応する optimization 文書に保存してください。

## 報告ポリシー

ベンチマーク記録には、比較を意味のあるものにするため十分な文脈を含める必要があります。

- 比較した revision または実装段階;
- 操作とパラメータセット;
- compiler/toolchain と関連する build configuration;
- OS または hosted runner;
- 反復/集約方法;
- 値が絶対 throughput/latency なのか相対 percentage change なのか;
- 比較が same-host、hosted-runner、cross-library のどれか。

一つのプラットフォームで測定した結果を、アルゴリズム全体の普遍的な性質として提示してはいけません。

## 負の結果にも価値がある

最適化実験が遅くなった場合でも、有用な engineering result になり得ます。ML-KEM Montgomery 実験を保持しているのはこのためです。portable default が Montgomery ではなく Barrett reduction を維持した理由を、却下した代替案を文書化せずに残すことなく説明できます。

## 結果を置く場所

- Bignum 結果: [Bignum 最適化](../../optimization/Bignum.md)
- ECC 結果: [ECC 最適化](../../optimization/ECC.md)
- ML-KEM 結果: [ML-KEM 最適化](../../optimization/ML-KEM.md) および [ML-KEM Barrett 実験](../../optimization/ML-KEM-Barrett.md)
- RSA の結果/判断: [RSA 最適化](../../optimization/RSA.md)
- Ed25519 の結果/判断: [Ed25519 最適化](../../optimization/Ed25519.md)

トップレベル README は、最適化作業が文書化され測定されていることだけを要約すべきです。詳細な表はこの文書階層または各コンポーネントの optimization note に置きます。
