from pathlib import Path
import re

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
for needle in (
    "project(LiberaCrypt VERSION",
    "add_library(LiberaCrypt::LiberaCrypt ALIAS LiberaCrypt)",
    "OUTPUT_NAME liberacrypt",
    "include(cmake/LiberaCryptExports.cmake)",
    "cmake/LiberaCryptConfig.cmake.in",
    "LiberaCryptTargets",
    "NAMESPACE LiberaCrypt::",
):
    if needle not in text:
        raise RuntimeError(f"missing CMake identity after rename: {needle}")
cmake.write_text(text, encoding="utf-8")

# CMake package config must include the new exported target file.
config = ROOT / "cmake" / "LiberaCryptConfig.cmake.in"
config_text = config.read_text(encoding="utf-8")
if "LiberaCryptTargets.cmake" not in config_text:
    raise RuntimeError("LiberaCryptConfig.cmake.in does not include LiberaCryptTargets.cmake")

# Normalize README wording after all token/package replacements. Earlier passes
# intentionally operate on exact identifiers, which can leave prose such as a
# bare `CRYPTO_` prefix or the former compatibility paragraph partially renamed.
readme = ROOT / "README.md"
text = readme.read_text(encoding="utf-8")
text = re.sub(
    r"The public C API and CMake package identifiers currently retain the existing\n"
    r"`[^`]+`, `LiberaCrypt\.h`, and `LiberaCrypt::LiberaCrypt` names for compatibility; LiberaCrypt\n"
    r"is the project name\.\n",
    "LiberaCrypt uses `LIBERAC_` for public C functions, macros, constants, and\n"
    "algorithm selectors, `LiberaC` for public type names, `LiberaCrypt.h` as its\n"
    "umbrella header, and the `LiberaCrypt::LiberaCrypt` CMake target.\n",
    text,
)
text = text.replace("`CRYPTO_`", "`LIBERAC_`")
text = text.replace("@c CRYPTO_", "@c LIBERAC_")
text = text.replace("`ALG_", "`LIBERAC_ALG_")
readme.write_text(text, encoding="utf-8")

# Installed headers should not describe the old public namespace even in prose.
for header in (ROOT / "inc").glob("*.h"):
    text = header.read_text(encoding="utf-8")
    text = text.replace("CRYPTO_ functions", "LIBERAC_ functions")
    text = text.replace("CRYPTO_ identifiers", "LIBERAC_ identifiers")
    text = text.replace("@c CRYPTO_", "@c LIBERAC_")
    header.write_text(text, encoding="utf-8")

# README should advertise only the new public surface.
text = readme.read_text(encoding="utf-8")
for old_name in (
    "<Crypto.h>",
    "Crypto::Crypto",
    "find_package(Crypto",
    "-DCRYPTO_BUILD_TESTS",
    "-DCRYPTO_BUILD_DOCS",
    "`CRYPTO_`",
):
    if old_name in text:
        raise RuntimeError(f"old public package name remains in README: {old_name}")

print("LiberaCrypt package rename post-pass complete")
