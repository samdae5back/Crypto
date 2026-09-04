# LiberaCrypt ドキュメント

LiberaCrypt のリポジトリ `README.md` は、プロジェクトの性格と使い始めるための情報をすばやく把握できるよう、意図的に簡潔に保っています。詳しい使用方法、設計上の理由、セキュリティ上の注意、最適化の記録、ベンチマークの解釈は個別の文書で扱います。

## はじめに

- [LiberaCrypt のビルド](../../getting-started/building.md)
- [LiberaCrypt の組み込み](../../getting-started/integration.md)
- [API 概要](../../api/overview.md)
- [アルゴリズム選択](../../api/algorithm-selection.md)
- [アルゴリズム・ファミリ](../../algorithms/overview.md)

## 設計

- [アーキテクチャ](../../design/architecture.md)
- [移植性](../../design/portability.md)
- [Constant-time ポリシー](../../design/constant-time.md)

これらの文書は、基礎となる標準アルゴリズムの数学的定義ではなく、LiberaCrypt の実装をどのような方針で構成しているかを説明します。特に、移植性と timing 特性は付加的な機能ではなく、明示的に検討すべき実装上の性質として扱います。

## セキュリティ

- [セキュリティ上の考慮事項](../../security/security-considerations.md)
- [レガシーおよび互換性アルゴリズム](../../security/legacy-algorithms.md)

アルゴリズムを選択したり、低レベルの primitive を直接利用したりする前に、これらの文書を確認することを推奨します。

## アルゴリズム

- [アルゴリズム・ファミリ概要](../../algorithms/overview.md)
- [鍵導出](../../key-derivation.md)

関数シグネチャ、引数、戻り値、公開宣言については、生成される Doxygen API reference を基準とします。Markdown 文書では、各構成要素をどのように組み合わせて利用することを想定しているかを説明します。

## 最適化とベンチマーク

- [最適化文書インデックス](../../optimization/README.md)
- [Bignum 最適化](../../optimization/Bignum.md)
- [ECC 最適化](../../optimization/ECC.md)
- [Ed25519 最適化](../../optimization/Ed25519.md)
- [ML-KEM 最適化](../../optimization/ML-KEM.md)
- [ML-KEM Barrett/Montgomery 実験](../../optimization/ML-KEM-Barrett.md)
- [RSA 最適化](../../optimization/RSA.md)
- [ベンチマーク構成](../../benchmarks/README.md)

最適化文書には、基準実装、変更内容、検証条件、そして最終実装を選択した理由を記録します。実際のベンチマーク・プログラムは、リポジトリ直下の `benchmarks/` ディレクトリに置きます。

## 開発

- [テストと検証](../../development/testing.md)

サードパーティ・コードの出典とライセンス情報は、リポジトリ直下の `THIRD_PARTY_NOTICES.md` に記録します。
