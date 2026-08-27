from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

TEXT_SUFFIXES = {
    ".c", ".h", ".cmake", ".in", ".md", ".txt", ".yml", ".yaml", ".sh"
}


def iter_text_files():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if ".git" in rel.parts:
            continue
        if path.suffix == ".kat":
            continue
        if path.name == "SHA256SUMS":
            continue
        if path.name == "CMakeLists.txt" or path.suffix in TEXT_SUFFIXES:
            yield path


def read(path):
    return path.read_text(encoding="utf-8")


def write(path, text):
    path.write_text(text, encoding="utf-8")


def pascal_from_upper(name):
    return "".join(part[:1] + part[1:].lower() for part in name.split("_") if part)


# Discover the old installed namespace before changing it. This deliberately
# limits renaming to identifiers that are actually public, so unrelated
# CRYPTO_* names in bundled upstream backends are not rewritten accidentally.
public_header_dir = ROOT / "inc"
public_header_text = "\n".join(read(p) for p in public_header_dir.glob("*.h"))
public_crypto_tokens = set(re.findall(r"\bCRYPTO_[A-Z0-9_]+\b", public_header_text))
public_alg_tokens = set(re.findall(r"\bALG_[A-Z0-9_]+\b", public_header_text))

# Public typedef names use the LiberaC type prefix rather than the LIBERAC_
# symbol prefix.
public_type_aliases = {"AlgID", "CryptoError"}
for match in re.finditer(r"}\s*(CRYPTO_[A-Z0-9_]+)\s*;", public_header_text):
    public_type_aliases.add(match.group(1))
for match in re.finditer(
    r"typedef\s+[^;{}\n]+\s+(CRYPTO_[A-Z0-9_]+|Crypto[A-Za-z0-9_]+|AlgID)\s*;",
    public_header_text,
):
    public_type_aliases.add(match.group(1))


def new_type_name(old):
    if old == "AlgID":
        return "LiberaCAlgID"
    if old == "CryptoError":
        return "LiberaCError"
    if old.startswith("Crypto"):
        return "LiberaC" + old[len("Crypto"):]
    if old.startswith("CRYPTO_"):
        return "LiberaC" + pascal_from_upper(old[len("CRYPTO_"):])
    raise ValueError(old)


type_map = {old: new_type_name(old) for old in public_type_aliases}
for old in public_type_aliases:
    public_crypto_tokens.discard(old)

symbol_map = {
    old: "LIBERAC_" + old[len("CRYPTO_"):]
    for old in public_crypto_tokens
}
# Algorithm selectors are also public C identifiers. Namespace them too so the
# installed API has one coherent LIBERAC_* identifier namespace.
algorithm_map = {
    old: "LIBERAC_" + old
    for old in public_alg_tokens
}

# Apply public C identifier changes everywhere they are consumed. Exact token
# replacement keeps unrelated bundled identifiers untouched.
for path in iter_text_files():
    text = read(path)
    original = text

    for old, new in sorted(type_map.items(), key=lambda item: -len(item[0])):
        text = re.sub(rf"\b{re.escape(old)}\b", new, text)
    for old, new in sorted(symbol_map.items(), key=lambda item: -len(item[0])):
        text = re.sub(rf"\b{re.escape(old)}\b", new, text)
    for old, new in sorted(algorithm_map.items(), key=lambda item: -len(item[0])):
        text = re.sub(rf"\b{re.escape(old)}\b", new, text)

    text = text.replace("Crypto.h", "LiberaCrypt.h")
    text = text.replace("Crypto library", "LiberaCrypt library")

    if text != original:
        write(path, text)

# Rename the umbrella header.
old_header = ROOT / "inc" / "Crypto.h"
new_header = ROOT / "inc" / "LiberaCrypt.h"
if not old_header.exists():
    raise RuntimeError("inc/Crypto.h was not found")
if new_header.exists():
    raise RuntimeError("inc/LiberaCrypt.h already exists")
old_header.rename(new_header)

# Rename CMake support files that form part of the package identity.
cmake_renames = {
    ROOT / "cmake" / "CryptoExports.cmake": ROOT / "cmake" / "LiberaCryptExports.cmake",
    ROOT / "cmake" / "CryptoConfig.cmake.in": ROOT / "cmake" / "LiberaCryptConfig.cmake.in",
    ROOT / "cmake" / "crypto_exports.txt": ROOT / "cmake" / "liberacrypt_exports.txt",
}
for old, new in cmake_renames.items():
    if not old.exists():
        raise RuntimeError(f"expected CMake support file not found: {old.relative_to(ROOT)}")
    if new.exists():
        raise RuntimeError(f"destination already exists: {new.relative_to(ROOT)}")
    old.rename(new)

# CMake project/package/target identity. Internal algorithm object target names
# remain lowercase crypto_* because they are not public package identifiers.
cmake_paths = [ROOT / "CMakeLists.txt"] + list((ROOT / "cmake").glob("*.cmake")) + list((ROOT / "cmake").glob("*.in")) + [ROOT / "tests" / "CMakeLists.txt"]
for path in cmake_paths:
    if not path.exists():
        continue
    text = read(path)
    text = re.sub(r"\bCrypto\b", "LiberaCrypt", text)
    text = text.replace("CRYPTO_IS_TOP_LEVEL", "LIBERAC_IS_TOP_LEVEL")
    text = text.replace("CRYPTO_BUILD_TESTS", "LIBERAC_BUILD_TESTS")
    text = text.replace("CRYPTO_BUILD_DOCS", "LIBERAC_BUILD_DOCS")
    text = text.replace("CRYPTO_PUBLIC_HEADER_NAMES", "LIBERAC_PUBLIC_HEADER_NAMES")
    text = text.replace("CRYPTO_PUBLIC_HEADER", "LIBERAC_PUBLIC_HEADER")
    text = text.replace("CRYPTO_PUBLIC_HEADERS", "LIBERAC_PUBLIC_HEADERS")
    text = text.replace("CRYPTO_SOURCES", "LIBERAC_SOURCES")
    text = text.replace("CRYPTO_CMAKE_INSTALL_DIR", "LIBERAC_CMAKE_INSTALL_DIR")
    text = text.replace("CRYPTO_LICENSE_INSTALL_DIR", "LIBERAC_LICENSE_INSTALL_DIR")
    text = text.replace("CRYPTO_DOXYGEN_", "LIBERAC_DOXYGEN_")
    text = text.replace("crypto_configure_", "liberac_configure_")
    text = text.replace("_crypto_exports_", "_liberac_exports_")
    text = text.replace("_crypto_export_", "_liberac_export_")
    text = text.replace("_crypto_warning_", "_liberac_warning_")
    text = text.replace("_crypto_target_", "_liberac_target_")
    text = text.replace("_crypto_allowlist", "_liberac_allowlist")
    text = text.replace("_crypto_macos_", "_liberac_macos_")
    text = text.replace("_crypto_solaris_", "_liberac_solaris_")
    text = text.replace("_crypto_aix_", "_liberac_aix_")
    text = text.replace("_crypto_elf_", "_liberac_elf_")
    text = text.replace("_crypto_symbol", "_liberac_symbol")
    text = text.replace("_crypto_compiler_", "_liberac_compiler_")
    text = text.replace("_crypto_one_value_args", "_liberac_one_value_args")
    text = text.replace("_crypto_byte_order", "_liberac_byte_order")
    text = text.replace("CRYPTO_ENDIAN", "LIBERAC_ENDIAN")
    text = text.replace("CRYPTO_EXPORTS_DEFAULT_ALLOWLIST", "LIBERAC_EXPORTS_DEFAULT_ALLOWLIST")
    text = text.replace("crypto-exports", "liberacrypt-exports")
    text = text.replace("crypto_exports.txt", "liberacrypt_exports.txt")
    write(path, text)

# Top-level library filename and documentation target.
cmake = ROOT / "CMakeLists.txt"
text = read(cmake)
text = text.replace("OUTPUT_NAME crypto", "OUTPUT_NAME liberacrypt")
text = text.replace("add_custom_target(crypto_docs", "add_custom_target(liberacrypt_docs")
write(cmake, text)

# Package-facing documentation and examples.
for path in iter_text_files():
    text = read(path)
    original = text
    text = text.replace("Crypto::Crypto", "LiberaCrypt::LiberaCrypt")
    text = text.replace("find_package(Crypto", "find_package(LiberaCrypt")
    text = text.replace("libcrypto.so", "libliberacrypt.so")
    text = text.replace("libcrypto.a", "libliberacrypt.a")
    text = text.replace("crypto.dll", "liberacrypt.dll")
    text = text.replace("crypto_docs", "liberacrypt_docs")
    if text != original:
        write(path, text)

# README identity: the old compatibility statement is no longer true after
# this breaking public namespace rename.
readme = ROOT / "README.md"
text = read(readme)
text = text.replace(
    "The public C API and CMake package identifiers currently retain the existing\n"
    "`LIBERAC_`, `LiberaCrypt.h`, and `LiberaCrypt::LiberaCrypt` names for compatibility; LiberaCrypt\n"
    "is the project name.\n",
    "LiberaCrypt uses `LIBERAC_` for public C symbols, macros, and algorithm\n"
    "selectors, `LiberaC` for public type names, `LiberaCrypt.h` as its umbrella\n"
    "header, and the `LiberaCrypt::LiberaCrypt` CMake target.\n",
)
text = text.replace(
    "The public C API and CMake package identifiers currently retain the existing\n"
    "`CRYPTO_`, `Crypto.h`, and `Crypto::Crypto` names for compatibility; LiberaCrypt\n"
    "is the project name.\n",
    "LiberaCrypt uses `LIBERAC_` for public C symbols, macros, and algorithm\n"
    "selectors, `LiberaC` for public type names, `LiberaCrypt.h` as its umbrella\n"
    "header, and the `LiberaCrypt::LiberaCrypt` CMake target.\n",
)
text = text.replace("-DCRYPTO_BUILD_TESTS=ON", "-DLIBERAC_BUILD_TESTS=ON")
text = text.replace("-DCRYPTO_BUILD_DOCS=ON", "-DLIBERAC_BUILD_DOCS=ON")
write(readme, text)

# Documentation branding.
doxy = ROOT / "cmake" / "Doxyfile.in"
if doxy.exists():
    text = read(doxy)
    text = re.sub(r"(?m)^PROJECT_NAME\s*=.*$", 'PROJECT_NAME           = "LiberaCrypt"', text)
    write(doxy, text)

# Public namespace assertions. Package-name assertions that depend on the
# post-pass are intentionally checked by liberacrypt_public_api_post.py.
if (ROOT / "inc" / "Crypto.h").exists():
    raise RuntimeError("old inc/Crypto.h still exists")
if not (ROOT / "inc" / "LiberaCrypt.h").exists():
    raise RuntimeError("inc/LiberaCrypt.h was not created")

new_public_text = "\n".join(read(p) for p in public_header_dir.glob("*.h"))
if re.search(r"\bCryptoError\b|\bAlgID\b", new_public_text):
    raise RuntimeError("old public type name remains in installed headers")
old_public_tokens_left = sorted(
    token for token in public_crypto_tokens
    if re.search(rf"\b{re.escape(token)}\b", new_public_text)
)
if old_public_tokens_left:
    raise RuntimeError(f"old public CRYPTO_ names remain: {old_public_tokens_left[:20]}")
old_alg_tokens_left = sorted(
    token for token in public_alg_tokens
    if re.search(rf"\b{re.escape(token)}\b", new_public_text)
)
if old_alg_tokens_left:
    raise RuntimeError(f"old public ALG_ names remain: {old_alg_tokens_left[:20]}")

# Verify the part of the requested CMake identity established in this pass.
cmake_text = read(ROOT / "CMakeLists.txt")
for item in (
    "project(LiberaCrypt VERSION",
    "add_library(LiberaCrypt ",
    "add_library(LiberaCrypt::LiberaCrypt ALIAS LiberaCrypt)",
    "OUTPUT_NAME liberacrypt",
):
    if item not in cmake_text:
        raise RuntimeError(f"missing requested CMake identity: {item}")

print("Public type mapping:")
for old, new in sorted(type_map.items()):
    print(f"  {old} -> {new}")
print(f"Renamed {len(symbol_map)} installed CRYPTO_ identifiers to LIBERAC_*")
print(f"Renamed {len(algorithm_map)} installed ALG_ selectors to LIBERAC_ALG_*")
