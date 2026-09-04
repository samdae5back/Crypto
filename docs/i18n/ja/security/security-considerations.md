# セキュリティ上の考慮事項

LiberaCrypt は cryptographic primitive を提供し operation-level input を検証しますが、プロトコルを正しく使用する責任は caller にあります。

## 適切な API ファミリを使う

機密性と完全性の両方が必要な新しいアプリケーションプロトコルでは authenticated-encryption API を優先してください。raw block/stream encryption API は認証付き暗号と意図的に分離されています。

アルゴリズム固有の nonce、tag、key size、message size ルールは可能な範囲で対応する public API が検証します。nonce uniqueness、key lifecycle、replay handling、protocol negotiation のようなアプリケーション全体の要件はライブラリの範囲外です。

## 認証失敗

認証および検証の失敗は明示的に返されます。caller は authentication failure を hard failure として扱い、検証失敗後のデータを信頼済みとして処理してはいけません。

## 鍵導出と乱数

key-derivation API は文書化された標準と制限を実装します。適切な入力、password policy、work factor、protocol-specific restriction の選択はアプリケーションの責任です。

random-byte および DRBG API は正しい lifecycle と parameter 使用に依存します。legacy configuration は互換性のために存在し、新しいプロトコルで自動的に選択すべきではありません。

## 公開鍵 primitive

raw mathematical primitive より、高水準の標準化された encoding と scheme を優先してください。raw primitive はテストや互換性に有用な場合のために残されていますが、それ自体で安全な application protocol を定義するものではありません。

## レガシーアルゴリズム

一部のアルゴリズムは新しい設計の推奨ではなく、古いシステムとの相互運用のために含まれます。[レガシーおよび互換性アルゴリズム](legacy-algorithms.md) を参照してください。

## Side channel

一部の secret-dependent arithmetic は専用の fixed-width timing-oriented path を使用します。これは、ライブラリの全操作、compiler output、host environment、完全な application があらゆる side channel から安全だという主張ではありません。実装境界については [Constant-time ポリシー](../../design/constant-time.md) を参照してください。

## Secret lifetime

実装は不要になった多くの sensitive temporary buffer と internal state を消去します。これは残留データを減らしますが、application、compiler、OS、hardware が別の場所に作成したコピーまでは制御できません。

## プロトコル責任

primitive library は周囲のシステムの security goal を推測できません。protocol selection、key management、message framing、domain separation、negotiation policy、replay handling、完全な deployment の threat model はアプリケーションの責任です。
