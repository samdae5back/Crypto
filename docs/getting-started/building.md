# Building LiberaCrypt

LiberaCrypt is a C11 library built with CMake. No submodule checkout or external cryptographic runtime is required for the normal library build.

## Shared-library build

```sh
cmake -E make_directory build
cmake -E chdir build cmake .. \
  -DBUILD_SHARED_LIBS=ON \
  -DLIBERAC_BUILD_TESTS=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
cmake -E chdir build ctest -C Release --output-on-failure
```

For a static library, configure with `-DBUILD_SHARED_LIBS=OFF`.

## Install

```sh
cmake -E chdir build cmake .. -DCMAKE_INSTALL_PREFIX=/your/prefix
cmake --build build --target install --config Release
```

Only public headers under `inc/` are installed.

## CMake package

Installed consumers can use the exported target:

```cmake
find_package(LiberaCrypt CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE LiberaCrypt::LiberaCrypt)
```

## Tests

Tests are enabled by default for a standalone checkout and disabled when LiberaCrypt is included through `add_subdirectory()`. An embedding project may enable them with `-DLIBERAC_BUILD_TESTS=ON`; the embedding project's top-level CMake configuration must call `enable_testing()` for root-level CTest discovery.

See [Testing and validation](../development/testing.md) for the scope of the validation suite.

## API reference

Install Doxygen 1.12 or newer and enable the optional documentation target:

```sh
cmake -E make_directory build-docs
cmake -E chdir build-docs cmake .. -DLIBERAC_BUILD_DOCS=ON
cmake --build build-docs --target liberacrypt_docs
```

The generated entry page is `build-docs/docs/html/index.html`. Only public headers under `inc/` are included in the generated reference.
