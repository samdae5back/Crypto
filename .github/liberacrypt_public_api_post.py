from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TEXT_SUFFIXES = {".c", ".h", ".cmake", ".in", ".md", ".txt", ".yml", ".yaml", ".sh"}


def iter_text_files():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if ".git" in rel.parts or path.suffix == ".kat" or path.name == "SHA256SUMS":
            continue
        if path.name == "CMakeLists.txt" or path.suffix in TEXT_SUFFIXES:
            yield path


replacements = {
    "CryptoTargets": "LiberaCryptTargets",
    "CryptoConfigVersion": "LiberaCryptConfigVersion",
    "CryptoConfig": "LiberaCryptConfig",
    "CryptoExports": "LiberaCryptExports",
    "CRYPTO_IS_TOP_LEVEL": "LIBERAC_IS_TOP_LEVEL",
    "CRYPTO_BUILD_TESTS": "LIBERAC_BUILD_TESTS",
    "CRYPTO_BUILD_DOCS": "LIBERAC_BUILD_DOCS",
    "CRYPTO_PUBLIC_HEADER_NAMES": "LIBERAC_PUBLIC_HEADER_NAMES",
    "CRYPTO_PUBLIC_HEADERS": "LIBERAC_PUBLIC_HEADERS",
    "CRYPTO_PUBLIC_HEADER": "LIBERAC_PUBLIC_HEADER",
    "CRYPTO_SOURCES": "LIBERAC_SOURCES",
    "CRYPTO_CMAKE_INSTALL_DIR": "LIBERAC_CMAKE_INSTALL_DIR",
    "CRYPTO_LICENSE_INSTALL_DIR": "LIBERAC_LICENSE_INSTALL_DIR",
    "CRYPTO_DOXYGEN_": "LIBERAC_DOXYGEN_",
    "^CRYPTO_[A-Z0-9_]+$": "^LIBERAC_[A-Z0-9_]+$",
    "undecorated CRYPTO_ C identifiers": "undecorated LIBERAC_ C identifiers",
    "only undecorated CRYPTO_": "only undecorated LIBERAC_",
    "CRYPTO_ functions": "LIBERAC_ functions",
    "CRYPTO_ C identifiers": "LIBERAC_ C identifiers",
}

for path in iter_text_files():
    text = path.read_text(encoding="utf-8")
    old = text
    for before, after in replacements.items():
        text = text.replace(before, after)
    if text != old:
        path.write_text(text, encoding="utf-8")

# Normalize top-level package/target/install identity exactly.
cmake = ROOT / "CMakeLists.txt"
text = cmake.read_text(encoding="utf-8")
required_replacements = {
    "project(LiberaCrypt VERSION": "project(LiberaCrypt VERSION",
    "add_library(LiberaCrypt::LiberaCrypt ALIAS LiberaCrypt)": "add_library(LiberaCrypt::LiberaCrypt ALIAS LiberaCrypt)",
    "OUTPUT_NAME liberacrypt": "OUTPUT_NAME liberacrypt",
    "include(cmake/LiberaCryptExports.cmake)": "include(cmake/LiberaCryptExports.cmake)",
    "cmake/LiberaCryptConfig.cmake.in": "cmake/LiberaCryptConfig.cmake.in",
}
for needle in required_replacements:
    if needle not in text:
        raise RuntimeError(f"missing CMake identity after rename: {needle}")
cmake.write_text(text, encoding="utf-8")

# CMake package config must include the new exported target file.
config = ROOT / "cmake" / "LiberaCryptConfig.cmake.in"
config_text = config.read_text(encoding="utf-8")
if "LiberaCryptTargets.cmake" not in config_text:
    raise RuntimeError("LiberaCryptConfig.cmake.in does not include LiberaCryptTargets.cmake")

# README should advertise only the new public surface.
readme = ROOT / "README.md"
text = readme.read_text(encoding="utf-8")
for old_name in ("<Crypto.h>", "Crypto::Crypto", "find_package(Crypto", "-DCRYPTO_BUILD_TESTS", "-DCRYPTO_BUILD_DOCS"):
    if old_name in text:
        raise RuntimeError(f"old public package name remains in README: {old_name}")

print("LiberaCrypt package rename post-pass complete")
