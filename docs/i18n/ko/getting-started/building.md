# LiberaCrypt 빌드

LiberaCrypt는 CMake로 빌드하는 C11 라이브러리입니다. 일반적인 라이브러리 빌드에는 submodule checkout이나 외부 cryptographic runtime이 필요하지 않습니다.

## Shared-library 빌드

```sh
cmake -E make_directory build
cmake -E chdir build cmake .. \
  -DBUILD_SHARED_LIBS=ON \
  -DLIBERAC_BUILD_TESTS=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
cmake -E chdir build ctest -C Release --output-on-failure
```

static library를 빌드하려면 `-DBUILD_SHARED_LIBS=OFF`로 구성합니다.

## 설치

```sh
cmake -E chdir build cmake .. -DCMAKE_INSTALL_PREFIX=/your/prefix
cmake --build build --target install --config Release
```

`inc/` 아래의 public header만 설치됩니다.

## CMake package

설치된 LiberaCrypt를 사용하는 프로젝트는 export된 target을 사용할 수 있습니다.

```cmake
find_package(LiberaCrypt CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE LiberaCrypt::LiberaCrypt)
```

## 테스트

standalone checkout에서는 테스트가 기본적으로 활성화되고, `add_subdirectory()`를 통해 LiberaCrypt를 포함한 경우에는 기본적으로 비활성화됩니다. embedding project는 `-DLIBERAC_BUILD_TESTS=ON`으로 테스트를 활성화할 수 있습니다. root-level CTest discovery를 위해 embedding project의 최상위 CMake 설정은 `enable_testing()`을 호출해야 합니다.

검증 범위는 [테스트와 검증](../../development/testing.md)을 참고하세요.

## API 레퍼런스

Doxygen 1.12 이상을 설치하고 optional documentation target을 활성화합니다.

```sh
cmake -E make_directory build-docs
cmake -E chdir build-docs cmake .. -DLIBERAC_BUILD_DOCS=ON
cmake --build build-docs --target liberacrypt_docs
```

생성되는 시작 페이지는 `build-docs/docs/html/index.html`입니다. 생성된 reference에는 `inc/` 아래의 public header만 포함됩니다.
