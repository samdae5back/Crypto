cmake_minimum_required(VERSION 3.10)
project(Crypto VERSION 0.6.0 LANGUAGES C)

if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(CRYPTO_IS_TOP_LEVEL ON)
else()
    set(CRYPTO_IS_TOP_LEVEL OFF)
endif()

option(BUILD_SHARED_LIBS "Build Crypto as a shared library" ON)
option(CRYPTO_BUILD_TESTS "Build Crypto tests" ${CRYPTO_IS_TOP_LEVEL})
option(CRYPTO_BUILD_DOCS "Generate the public API reference with Doxygen" OFF)

set(CRYPTO_PUBLIC_HEADER_NAMES
    AsymmetricCipher.h
    BlockCipher.h
    Crypto.h
    Def.h
    DigitalSignature.h
    HashFunction.h
    KeyEncapsulation.h
    RandomNumberGeneration.h
    Util.h
)
set(CRYPTO_PUBLIC_HEADERS "")
foreach(CRYPTO_PUBLIC_HEADER IN LISTS CRYPTO_PUBLIC_HEADER_NAMES)
    list(APPEND CRYPTO_PUBLIC_HEADERS
        "${CMAKE_CURRENT_SOURCE_DIR}/inc/${CRYPTO_PUBLIC_HEADER}")
endforeach()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(MLDSA_BACKEND_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/DigitalSignature/ML-DSA/Backend)
set(SLHDSA_BACKEND_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/DigitalSignature/SLH-DSA/Backend)

# CMake 3.17 added the supported opt-out for AIX's automatic all-symbol
# export. Set the initializer before creating the shared-library target.
if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    if(CMAKE_VERSION VERSION_LESS "3.17")
        message(FATAL_ERROR
            "Restricted AIX exports require CMake 3.17 or newer")
    endif()
    set(CMAKE_AIX_EXPORT_ALL_SYMBOLS OFF)
endif()

set(CRYPTO_SOURCES
    # Public ABI entry points: one translation unit per operational category.
    src/AsymmetricCipher.c
    src/BlockCipher.c
    src/DigitalSignature.c
    src/HashFunction.c
    src/KeyEncapsulation.c
    src/RandomNumberGeneration.c
    src/Util.c

    # Private implementations grouped by primitive family and algorithm.
    src/Util/Core/secure_zero.c
    src/Util/Core/memory.c
    src/BlockCipher/AES/aes.c
    src/BlockCipher/AES/aes_aead.c
    src/RandomNumberGeneration/CTR_DRBG/ctr_drbg.c
    src/RandomNumberGeneration/KAT/pqc_kat_rng.c
    src/Util/Bignum/bignum.c
    src/Util/Prime/prime.c
    src/AsymmetricCipher/RSA/rsa.c
    src/AsymmetricCipher/ElGamal/elgamal.c
    src/HashFunction/SHA2/sha2.c
    src/HashFunction/SHA3/sha3.c
    src/HashFunction/LSH/lsh.c
    src/RandomNumberGeneration/Noise/random.c
    src/Util/Endian/endian.c
    src/Util/NTT/ntt.c
    src/Util/PQC/pqc.c
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
target_include_directories(crypto_mldsa PRIVATE ${MLDSA_BACKEND_DIR})
target_compile_definitions(crypto_mldsa PRIVATE
    MLD_CONFIG_NO_RANDOMIZED_API
    MLD_CONFIG_MULTILEVEL_BUILD
    MLD_CONFIG_NAMESPACE_PREFIX=mldsa
)

# slhdsa-c exposes all twelve FIPS 205 parameter objects from one portable build.
set(SLHDSA_VENDOR_SOURCES
    ${SLHDSA_BACKEND_DIR}/sha2_256.c
    ${SLHDSA_BACKEND_DIR}/sha2_512.c
    ${SLHDSA_BACKEND_DIR}/sha3_api.c
    ${SLHDSA_BACKEND_DIR}/sha3_f1600.c
    ${SLHDSA_BACKEND_DIR}/slh_dsa.c
    ${SLHDSA_BACKEND_DIR}/slh_prehash.c
    ${SLHDSA_BACKEND_DIR}/slh_sha2.c
    ${SLHDSA_BACKEND_DIR}/slh_shake.c
)
add_library(crypto_slhdsa OBJECT ${SLHDSA_VENDOR_SOURCES})
set_target_properties(crypto_slhdsa PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(crypto_slhdsa PRIVATE ${SLHDSA_BACKEND_DIR})

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
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
        $<INSTALL_INTERFACE:inc>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/DigitalSignature/ML-DSA
        ${MLDSA_BACKEND_DIR}
        ${SLHDSA_BACKEND_DIR}
)
target_compile_definitions(Crypto PRIVATE
    MLD_CONFIG_NO_RANDOMIZED_API
    MLD_CONFIG_MULTILEVEL_BUILD
    MLD_CONFIG_NAMESPACE_PREFIX=mldsa
)

if(WIN32)
    target_link_libraries(Crypto PRIVATE bcrypt)
endif()

include(cmake/CryptoExports.cmake)
crypto_configure_exports(Crypto)
crypto_configure_portable_warnings(Crypto crypto_mldsa crypto_slhdsa)
crypto_configure_vendor_endianness(
    SLHDSA_TARGET crypto_slhdsa
    MLDSA_TARGET crypto_mldsa
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CRYPTO_CMAKE_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/Crypto)
configure_package_config_file(
    cmake/CryptoConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake
    INSTALL_DESTINATION ${CRYPTO_CMAKE_INSTALL_DIR}
    NO_SET_AND_CHECK_MACRO
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(TARGETS Crypto
    EXPORT CryptoTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES ${CRYPTO_PUBLIC_HEADERS} DESTINATION inc)
install(EXPORT CryptoTargets NAMESPACE Crypto:: DESTINATION ${CRYPTO_CMAKE_INSTALL_DIR})
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/CryptoConfigVersion.cmake
    DESTINATION ${CRYPTO_CMAKE_INSTALL_DIR}
)
set(CRYPTO_LICENSE_INSTALL_DIR ${CMAKE_INSTALL_DATADIR}/licenses/Crypto)
install(FILES LICENSE
    DESTINATION ${CRYPTO_LICENSE_INSTALL_DIR}
    RENAME AGPL-3.0-only.txt
)
install(FILES THIRD_PARTY_NOTICES.md
    DESTINATION ${CRYPTO_LICENSE_INSTALL_DIR}
)
install(FILES ${MLDSA_BACKEND_DIR}/LICENSE
    DESTINATION ${CRYPTO_LICENSE_INSTALL_DIR}
    RENAME mldsa-native-LICENSE.txt
)
install(FILES ${SLHDSA_BACKEND_DIR}/LICENSE
    DESTINATION ${CRYPTO_LICENSE_INSTALL_DIR}
    RENAME slhdsa-c-LICENSE.txt
)

if(CRYPTO_BUILD_DOCS)
    find_package(Doxygen 1.12 REQUIRED)
    set(CRYPTO_DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/docs")
    set(CRYPTO_DOXYGEN_INDEX
        "${CRYPTO_DOXYGEN_OUTPUT_DIR}/html/index.html")
    set(CRYPTO_DOXYGEN_WARNINGS
        "${CRYPTO_DOXYGEN_OUTPUT_DIR}/warnings.log")
    configure_file(
        cmake/Doxyfile.in
        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        @ONLY
    )
    add_custom_target(crypto_docs
        COMMAND ${CMAKE_COMMAND} -E make_directory
                ${CRYPTO_DOXYGEN_OUTPUT_DIR}
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        DEPENDS ${CRYPTO_PUBLIC_HEADERS} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        BYPRODUCTS ${CRYPTO_DOXYGEN_INDEX} ${CRYPTO_DOXYGEN_WARNINGS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating Crypto public API documentation"
        VERBATIM
    )
endif()

if(CRYPTO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
