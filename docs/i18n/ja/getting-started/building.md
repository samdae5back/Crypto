# LiberaCrypt のビルド

LiberaCrypt は CMake でビルドする C11 ライブラリです。通常のライブラリビルドでは submodule checkout や外部 cryptographic runtime は必要ありません。

## Shared-library ビルド

```sh
cmake -E make_directory build
cmake -E chdir build cmake .. \
  -DBUILD_SHARED_LIBS=ON \
  -DLIBERAC_BUILD_TESTS=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
cmake -E chdir build ctest -C Release --output-on-failure
```

static library の場合は `-DBUILD_SHARED_LIBS=OFF` で構成します。

## インストール

```sh
cmake -E chdir build cmake .. -DCMAKE_INSTALL_PREFIX=/your/prefix
cmake --build build --target install --config Release
```

`inc/` 以下の public header だけがインストールされます。

## CMake package

インストール済み LiberaCrypt を使うプロジェクトは exported target を利用できます。

```cmake
find_package(LiberaCrypt CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE LiberaCrypt::LiberaCrypt)
```

## テスト

standalone checkout ではテストが既定で有効になり、`add_subdirectory()` で LiberaCrypt を取り込む場合は既定で無効になります。embedding project は `-DLIBERAC_BUILD_TESTS=ON` で有効化できます。root-level CTest discovery のため、embedding project の最上位 CMake 構成は `enable_testing()` を呼び出す必要があります。

検証範囲については [テストと検証](../../development/testing.md) を参照してください。

## API リファレンス

Doxygen 1.12 以降をインストールし、optional documentation target を有効にします。

```sh
cmake -E make_directory build-docs
cmake -E chdir build-docs cmake .. -DLIBERAC_BUILD_DOCS=ON
cmake --build build-docs --target liberacrypt_docs
```

生成される開始ページは `build-docs/docs/html/index.html` です。生成リファレンスには `inc/` 以下の public header のみが含まれます。
