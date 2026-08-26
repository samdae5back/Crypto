cmake_minimum_required(VERSION 3.10)
project(Crypto VERSION 0.6.0 LANGUAGES C)

option(BUILD_SHARED_LIBS "Build Crypto as a shared library" ON)
option(CRYPTO_BUILD_TESTS "Build Crypto tests" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Public symbols are explicitly marked with CRYPTO_API. Everything else is hidden
# on Linux/macOS. Windows exports only __declspec(dllexport) symbols.
if(NOT WIN32)
    set(CMAKE_C_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
endif()

set(MLDSA_NATIVE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mldsa-native)
set(SLHDSA_C_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/slhdsa-c)

if(NOT EXISTS "${MLDSA_NATIVE_DIR}/mldsa/mldsa_native.c" OR
   NOT EXISTS "${SLHDSA_C_DIR}/slh_dsa.c")
    message(FATAL_ERROR "PQ signature submodules are missing. Run: git submodule update --init --recursive")
endif()

set(CRYPTO_SOURCES
    src/Util/Core/core.c
    src/Util/Core/secure_zero.c
    src/BlockCipher/AES/aes.c
    src/BlockCipher/AES/aes_aead.c
    src/RandomNumberGeneration/CTR_DRBG/ctr_drbg.c
    src/Util/Bignum/bignum.c
    src/Util/Prime/prime.c
    src/AsymmetricCipher/RSA/rsa.c
    src/AsymmetricCipher/ElGamal/elgamal.c
    src/HashFunction/SHA3/sha3.c
    src/HashFunction.c
    src/RandomNumberGeneration/Noise/random.c
    src/Util/Endian/endian.c
    src/Util/NTT/ntt.c
    src/KeyEncapsulation/ML-KEM/api.c
    src/DigitalSignature/ML-DSA/ml_dsa.c
    src/DigitalSignature/SLH-DSA/slh_dsa.c
)

list(APPEND CRYPTO_SOURCES
    src/KeyEncapsulation/ML-KEM/K-PKE.c
    src/KeyEncapsulation/ML-KEM/ML-KEM.c
    src/KeyEncapsulation/ML-KEM/NTT_.c
    src/KeyEncapsulation/ML-KEM/auxiliary.c
    src/KeyEncapsulation/ML-KEM/hash.c
)

# Build the pinned mldsa-native source three times inside one local adapter TU.
# This avoids depending on symlinks used by the upstream example directory,
# which makes checkout/build behavior consistent on Windows as well.
add_library(crypto_mldsa OBJECT src/DigitalSignature/ML-DSA/mldsa_backend.c)
set_target_properties(crypto_mldsa PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(crypto_mldsa PRIVATE ${MLDSA_NATIVE_DIR}/mldsa)
target_compile_definitions(crypto_mldsa PRIVATE
    MLD_CONFIG_NO_RANDOMIZED_API
    MLD_CONFIG_MULTILEVEL_BUILD
    MLD_CONFIG_NAMESPACE_PREFIX=mldsa
)

# slhdsa-c exposes all twelve FIPS 205 parameter objects from one portable build.
set(SLHDSA_VENDOR_SOURCES
    ${SLHDSA_C_DIR}/sha2_256.c
    ${SLHDSA_C_DIR}/sha2_512.c
    ${SLHDSA_C_DIR}/sha3_api.c
    ${SLHDSA_C_DIR}/sha3_f1600.c
    ${SLHDSA_C_DIR}/slh_dsa.c
    ${SLHDSA_C_DIR}/slh_prehash.c
    ${SLHDSA_C_DIR}/slh_sha2.c
    ${SLHDSA_C_DIR}/slh_shake.c
)
add_library(crypto_slhdsa OBJECT ${SLHDSA_VENDOR_SOURCES})
set_target_properties(crypto_slhdsa PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(crypto_slhdsa PRIVATE ${SLHDSA_C_DIR})

if(MSVC)
    # slhdsa-c compares GCC byte-order macros directly. When both are absent,
    # MSVC preprocesses them as zero and incorrectly selects big-endian SHA-2.
    target_compile_definitions(crypto_slhdsa PRIVATE
        __BYTE_ORDER__=1234 __ORDER_BIG_ENDIAN__=4321
    )
    target_compile_options(crypto_mldsa PRIVATE /W4)
    target_compile_options(crypto_slhdsa PRIVATE /W4)
else()
    target_compile_options(crypto_mldsa PRIVATE -Wall -Wextra -pedantic)
    target_compile_options(crypto_slhdsa PRIVATE -Wall -Wextra -pedantic)
endif()

add_library(Crypto ${CRYPTO_SOURCES}
    $<TARGET_OBJECTS:crypto_mldsa>
    $<TARGET_OBJECTS:crypto_slhdsa>
)
add_library(Crypto::Crypto ALIAS Crypto)

set_target_properties(Crypto PROPERTIES
    OUTPUT_NAME crypto
    POSITION_INDEPENDENT_CODE ON
    WINDOWS_EXPORT_ALL_SYMBOLS OFF
)

target_include_directories(Crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/DigitalSignature/ML-DSA
        ${MLDSA_NATIVE_DIR}/mldsa
        ${SLHDSA_C_DIR}
)
target_compile_definitions(Crypto PRIVATE
    MLD_CONFIG_NO_RANDOMIZED_API
    MLD_CONFIG_MULTILEVEL_BUILD
    MLD_CONFIG_NAMESPACE_PREFIX=mldsa
)

if(BUILD_SHARED_LIBS)
    target_compile_definitions(Crypto PUBLIC CRYPTO_SHARED PRIVATE CRYPTO_BUILDING_LIBRARY)
endif()

if(WIN32)
    target_link_libraries(Crypto PRIVATE bcrypt)
endif()

if(MSVC)
    target_compile_options(Crypto PRIVATE /W4)
else()
    target_compile_options(Crypto PRIVATE -Wall -Wextra -pedantic)
endif()

include(GNUInstallDirs)
install(TARGETS Crypto
    EXPORT CryptoTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT CryptoTargets NAMESPACE Crypto:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Crypto)

if(CRYPTO_BUILD_TESTS)
    enable_testing()
    add_executable(crypto_unittest tests/test_crypto.c)
    target_link_libraries(crypto_unittest PRIVATE Crypto)
    add_test(NAME crypto_unittest COMMAND crypto_unittest)

    add_executable(crypto_kat tests/test_kat.c)
    target_link_libraries(crypto_kat PRIVATE Crypto)
    add_test(NAME crypto_kat COMMAND crypto_kat)

    add_executable(ctr_drbg_tests tests/test_ctr_drbg.c)
    target_link_libraries(ctr_drbg_tests PRIVATE Crypto)
    add_test(NAME ctr_drbg_tests COMMAND ctr_drbg_tests)

    add_executable(pq_signature_tests tests/test_pq_signatures.c)
    target_link_libraries(pq_signature_tests PRIVATE Crypto)
    add_test(NAME pq_signature_tests COMMAND pq_signature_tests)
endif()
