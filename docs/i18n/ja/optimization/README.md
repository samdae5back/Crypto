# 最適化ノート

最適化文書は、基礎となる暗号標準や wire format の変更ではなく、実装上の判断を記録します。

*reference-shaped baseline* は標準 pseudocode を直接移した実装、または LiberaCrypt の初期の単純な実装を意味します。文書で明示されない限り、公式 upstream または NIST 実装を benchmark baseline に使ったことを意味しません。

## コンポーネント別ノート

- [Bignum](Bignum.md) — public-data と secret-data の算術経路、exponentiation、Montgomery 作業、測定された段階。
- [ECC](ECC.md) — elliptic-curve arithmetic 実装と最適化段階。
- [Ed25519](Ed25519.md) — Ed25519 固有の算術と実装選択。
- [RSA](RSA.md) — RSA 算術および OAEP/PSS 関連の実装作業。
- [ML-KEM](ML-KEM.md) — ML-KEM 実装/最適化記録と最終的に選択された経路。
- [ML-KEM Barrett 実験](ML-KEM-Barrett.md) — Barrett-only、hybrid Montgomery、full-Montgomery の集中比較。

## 共通およびレガシー作業

すべての改善が純粋な throughput 最適化とは限りません。LiberaCrypt は cache behavior、memory traffic、code size、重複実装の削減、timing behavior、portability のための測定済みまたは根拠ある変更も行います。

例:

- SHA-1 は circular message schedule を使い、complete streaming block を一つずつ context staging buffer にコピーせず直接処理できます。
- Triple-DES は secret-indexed S-box table access を避け、fixed-index Boolean 実装を維持します。hot permutation 処理は generic bit-by-bit table walk と重複 intermediate permutation を避けるよう再構成されています。
- portable AES 実装は secret-derived table indexing の代わりに algebraic S-box/inverse-S-box path を使います。
- SHA-2 と LSH streaming path は partial context block を処理した後、complete input block を直接処理します。
- one-shot hash API は padding/finalization logic を複製せず、同じ incremental state machine を再利用します。
- 共通 constant-time byte equality と overflow-aware overlap helper が algorithm family ごとの重複 security-sensitive loop を置き換えます。
- portable PQC integration は backend が許す場合、不必要な parameter-specialized compilation より一つの runtime-dispatched library build を優先します。

再現可能な benchmark が保持されていない場合、実装を再構成しただけで throughput 改善を主張してはいけません。

## ML-KEM reduction の判断

プロジェクトは Ubuntu、Windows、macOS runner で Barrett-only、hybrid Montgomery、full-Montgomery ML-KEM 実装を比較しました。保持された比較では hybrid Montgomery は全体として Barrett-only より遅く、full Montgomery はテストした runner でさらに大きな regression を示しました。そのため default portable ML-KEM path は Barrett reduction を維持します。

詳細な methodology と runner ごとの測定値は repository landing page ではなく [ML-KEM Barrett 実験](ML-KEM-Barrett.md) に置きます。

## 新しい最適化作業の文書形式

新しいコンポーネントノートは、適用可能な場合、次の構造に従うことを推奨します。

1. **Baseline implementation** — 変更前のコードが何をしていたか。
2. **Optimization goal** — throughput、allocation、memory traffic、code size、portability、timing behavior、maintainability のどれが目的か。
3. **Implementation changes** — 具体的な transformation。
4. **Correctness and timing constraints** — 最適化が保持すべき invariant。
5. **Portability considerations** — integer width、representation、compiler behavior、architecture に関する前提。
6. **Benchmark methodology** — hardware/runner、compiler、build flag、repetition、comparison baseline。
7. **Results** — 一般性を誇張しない保持された測定値。
8. **Final decision** — 選択した実装を default path に残す理由。

この形式は、試した最適化が最終的に却下された場合でも engineering reasoning を保持することを目的とします。
