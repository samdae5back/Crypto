# Bignum 最適化記録

この文書は LiberaCrypt の第 2 段階 arbitrary-precision arithmetic 最適化に関する統合 engineering record です。

## 概要

| Stage | Baseline | 採用した変更 | 測定結果 |
|---|---|---|---|
| Stage 1 | bit-at-a-time generic reduction, repeated-doubling `R^2`, shifted CIOS | normalized base-2^32 remainder, direct `R^2`, integrated-shift CIOS | `mod` 約 **49x-83x**、`mod-mul` 約 **26x-55x** 高速; CIOS 自体は **0.7%-17.1%** 高速 |
| Stage 2 | allocate/replace 型 add/sub/mul/square、従来 schoolbook/square loop | 安全な output reuse、より厳密な schoolbook carry 処理、doubled-cross square accumulation 1 回 | add/sub 約 **38%-66%**、square **15%-62%** 高速; generic mul はより小さく混在する **-2%-18%** の変化 |
| Stage 3 | Stage-2 schoolbook multiplication | 同一幅 operand に対し **96 limbs / 3072 bits 以上**で測定に基づく one-level portable Karatsuba dispatch | 最終 production path の 3072-bit: **+6.0% Linux, +25.2% macOS, +12.5% Windows**; より大きいサイズで利得増加 |

以下の performance claim はすべて **同一 run 内の pairwise comparison** です。reference と candidate は同じ hosted runner で同じ deterministic input を使って実行されます。別 workflow run の absolute timing を組み合わせて人工的な cumulative speedup を作りません。

portable baseline は 32-bit limb と 32x32-to-64 arithmetic のままです。これらの stage は `__uint128_t`、compiler intrinsic、assembly、host-endian word cast を必要としません。

## セキュリティ境界

一般 bignum layer は意図的に performance-oriented variable-time です。secret-sensitive protocol arithmetic は fixed-width constant-schedule path に残します。

- Stage 1 は CIOS accumulation machinery を共有しますが、secret path は fixed loop count と masked final reduction を維持します。
- Stage 2 は generic add/sub/mul/square path を変更しますが、fixed-width secret exponentiation schedule を置き換えません。
- Stage 3 は generic multiplication API のみを dispatch します。fixed-width secret Montgomery arithmetic は Karatsuba に通しません。
- Stage-3 Karatsuba workspace は free 前に secure zeroize されます。使用される全 sub-buffer が arithmetic helper により完全に初期化されることを確認した後、冗長な initialization pass だけを削除し、final zeroization は残しています。

---

# Stage 1 - public reduction と Montgomery core

## 変更内容

Stage 1 前の `crypto_bignum_mod()` は dividend を bit ごとに scan し、temporary remainder を shift、1 bit append、compare、条件付き subtract していました。Stage 1 はこれを次で置き換えました。

1. normalized base-2^32 long-division remainder;
2. `2^(64n)` を一度 reduce して直接構成する Montgomery `R^2`;
3. integrated-shift CIOS Montgomery multiplication;
4. public/secret final-reduction policy の分離を維持。

正確な pre-Stage-1 formulation は benchmark reference としてのみ残ります。

## Benchmark 結果

### Generic remainder - 元の bitwise reducer に対する speedup

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 83.4x | 55.5x | 71.8x |
| 3072 | 69.5x | 48.6x | 60.0x |
| 4096 | 81.3x | 51.9x | 66.9x |

### Multiply then reduce - 元の path に対する speedup

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 55.3x | 32.3x | 44.2x |
| 3072 | 46.3x | 25.8x | 37.7x |
| 4096 | 52.8x | 30.3x | 42.6x |

### Montgomery `R^2` setup - repeated doubling に対する speedup

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 78.0x | 47.0x | 62.8x |
| 3072 | 67.4x | 41.7x | 57.1x |
| 4096 | 78.0x | 49.2x | 60.7x |

### Raw CIOS core - integrated shift 後の percent faster

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 4.1% | 3.4% | 8.1% |
| 3072 | 0.7% | 9.9% | 17.1% |
| 4096 | 4.5% | 11.9% | 15.0% |

Stage 1 の支配的な改善は小さな CIOS loop optimization ではなく algorithmic reduction/setup の変更です。

## 検証記録

- 最終 accurate benchmark run: `33740787602`
- validated head: `3c929f18ff207f9d7aa7357e8380632d856cbe62`
- artifact:
  - `bignum-stage1-accurate-Linux`
  - `bignum-stage1-accurate-macOS`
  - `bignum-stage1-accurate-Windows`

同じ Stage-1 head は merge 前に complete CI matrix、RSA validation、ECC validation、Bignum Validation、sanitizer check をすべて通過しました。

---

# Stage 2 - output reuse と multiply/square inner loop

## 変更内容

Stage 2 は Stage 1 後に残った allocator と inner-loop overhead を対象にします。

1. add/sub が destination capacity を再利用し safe same-index alias もサポート;
2. non-aliased multiplication が destination capacity を再利用;
3. schoolbook multiplication は正確な maximum product width を使い各 row の final carry を直接書き込む;
4. squaring は各 doubled cross product を portable base-2^32 piece として一度だけ accumulate;
5. non-aliased square operation が destination capacity を再利用。

破壊的な multiply/square alias は temporary を保持します。`bignum_reserve()` も、後で private material を保持し得る speculative capacity を残さず exact-size growth を維持します。

## Benchmark 結果

Stage 2 は正確な Stage-1 add/sub/mul/square 実装と比較します。

### 1024/2048/3072/4096-bit case 全体の改善範囲

| Operation | Linux | macOS | Windows |
|---|---:|---:|---:|
| `add` | +47.1% to +59.4% | +46.1% to +66.1% | +40.7% to +55.6% |
| `sub` | +45.4% to +60.1% | +43.7% to +65.5% | +38.5% to +50.0% |
| `mul` | +2.8% to +18.1% | +3.2% to +10.1% | -2.0% to +10.7% |
| `square` | +54.8% to +61.8% | +15.3% to +27.5% | +41.8% to +53.9% |

Windows 3072-bit multiplication の小さな regression (`-2.0%`) も隠さず記録しています。Stage 2 の最も強く一貫した利得は linear operation の output reuse と square-specific rewrite です。

### 代表的な 4096-bit raw timing

| Operation | Linux | macOS | Windows |
|---|---:|---:|---:|
| `add` | 0.516 -> 0.273 us (+47.1%) | 0.479 -> 0.258 us (+46.1%) | 0.540 -> 0.320 us (+40.7%) |
| `sub` | 0.560 -> 0.306 us (+45.4%) | 0.471 -> 0.265 us (+43.7%) | 0.520 -> 0.320 us (+38.5%) |
| `mul` | 11.700 -> 11.369 us (+2.8%) | 24.191 -> 23.056 us (+4.7%) | 20.600 -> 18.400 us (+10.7%) |
| `square` | 50.926 -> 20.101 us (+60.5%) | 47.180 -> 39.960 us (+15.3%) | 50.200 -> 29.200 us (+41.8%) |

## 検証記録

- 最終 accurate benchmark run: `33800902324`
- validated code head: `293d736b22d807b554d8688dbd23849a97d7cfde`
- artifact:
  - `bignum-stage2-accurate-Linux`
  - `bignum-stage2-accurate-macOS`
  - `bignum-stage2-accurate-Windows`

Stage 2 は merge 前に complete CI、RSA validation、ECC validation、dedicated Bignum Validation、Ubuntu ASan/UBSan check を通過しました。

---

# Stage 3 - 測定に基づく Karatsuba dispatch

## 判断プロセス

Stage 3 は Karatsuba の asymptotic complexity が良いという理由だけで追加せず、意図的に benchmark-first で進めました。

experimental benchmark は 512-8192-bit operand で Stage-2 schoolbook multiplication と portable one-level Karatsuba split を比較し、reusable scratch と one-shot allocation の両方を測定しました。結果、小さな operand では Karatsuba を正当化できず、3072 bit 以上では Linux、macOS、Windows すべてで有望でした。

その後 production implementation を追加して再測定しました。この 2 回目の測定には実際の dispatch、per-call workspace allocation、secure workspace zeroization が含まれるため、採用 threshold はこの結果で決まります。

## 採用実装

`crypto_bignum_mul()` は現在:

- 96 limb 未満: **Stage-2 schoolbook**;
- 同一幅 operand が **96 limbs / 3072 bits 以上**: **one-level Karatsuba**;
- 測定済み Karatsuba domain 外の unbalanced operand: Stage-2 schoolbook;
- Karatsuba workspace allocation ができない場合の安全な fallback: Stage-2 schoolbook。

元の Stage-2 multiplication 実装は重複/再実装せず、内部 `crypto_bignum_mul_stage2()` baseline/fallback として保持します。generic `crypto_bignum_mod_mul()` は reduction 前に production multiplication dispatch を通るため、適用可能な public/general modular multiplication も Stage-3 の利得を受けられます。

## 最終 production benchmark

正の percentage は同一 process で最終 Stage-3 production dispatch が正確な Stage-2 schoolbook reference より速いことを意味します。

### Production threshold 以上の改善

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 3072 | **+6.0%** | **+25.2%** | **+12.5%** |
| 4096 | **+13.1%** | **+30.9%** | **+17.9%** |
| 6144 | **+18.5%** | **+29.5%** | **+16.0%** |
| 8192 | **+17.2%** | **+28.1%** | **+15.4%** |

### Raw timing (`Stage 2 -> Stage 3`, multiplication あたり microseconds)

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 3072 | 7.140 -> 6.710 | 12.348 -> 9.239 | 12.000 -> 10.500 |
| 4096 | 13.178 -> 11.454 | 23.107 -> 15.973 | 23.333 -> 19.167 |
| 6144 | 28.607 -> 23.310 | 55.987 -> 39.452 | 41.667 -> 35.000 |
| 8192 | 50.320 -> 41.657 | 102.397 -> 73.626 | 74.286 -> 62.857 |

したがって threshold は最終 production 測定でも成立します。**allocation と secure zeroization のコストを含めても 3072 bit で 3 hosted OS すべて高速です。** operand size が大きくなるにつれて margin も増えます。

threshold 未満では production dispatcher が Stage-2 function を選択します。反復 timing の小さな差は別 arithmetic implementation の差ではなく runner/timer noise です。

## Stage-3 検証記録

最終 production code head:

- `b8752b6608708fedd618180e51f6146eb6f4bf75`

Validation:

- Bignum Validation run `33818440244`: Linux/macOS/Windows complete test suite、3 OS runner の final production benchmark、Ubuntu ASan/UBSan;
- RSA validation run `33818440271`;
- ECC validation run `33818440257`;
- general CI run `33818440245`.

最終 benchmark artifact:

- `bignum-stage3-production-Linux`
- `bignum-stage3-production-macOS`
- `bignum-stage3-production-Windows`

benchmark は timing 前に 1-160 equal-width limb で production dispatcher と正確な Stage-2 multiplier を differential-check し、destructive left/right alias case も検証します。

---

# 最適化履歴の読み方

意図された stage snapshot は次です。

| Tag | 意味 |
|---|---|
| `bignum-stage0-baseline` | Stage 1 直前の repository |
| `bignum-stage1-reduction-montgomery` | 採用された Stage-1 reduction/Montgomery 実装 |
| `bignum-stage2-mul-square` | 採用された Stage-2 output-reuse/mul/square 実装 |
| `bignum-stage3-karatsuba` | 採用された Stage-3 production Karatsuba dispatch |

正確な historical source comparison には tag を、測定根拠には benchmark artifact を使ってください。異なる stage の speedup ratio を掛け合わせてはいけません。Stage 1、Stage 2、Stage 3 は異なる operation を測定し、別々の hosted-runner job で実行されています。
