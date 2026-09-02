cmake_minimum_required(VERSION 3.10)
project(LiberaCrypt VERSION 0.6.0 LANGUAGES C)

if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(LIBERAC_IS_TOP_LEVEL ON)
else()
    set(LIBERAC_IS_TOP_LEVEL OFF)
endif()

option(BUILD_SHARED_LIBS "Build LiberaCrypt as a shared library" ON)
option(LIBERAC_BUILD_TESTS "Build LiberaCrypt tests" ${LIBERAC_IS_TOP_LEVEL})
option(LIBERAC_BUILD_DOCS "Generate the public API reference with Doxygen" OFF)

set(LIBERAC_PUBLIC_HEADER_NAMES
    AsymmetricCipher.h
    BlockCipher.h
    LiberaCrypt.h
    Def.h
    DigitalSignature.h
    HashFunction.h
    MessageAuthentication.h
    KeyAgreement.h
    KeyDerivation.h
    KeyEncapsulation.h
    RandomNumberGeneration.h
    Util.h
)
set(LIBERAC_PUBLIC_HEADERS "")
foreach(LIBERAC_PUBLIC_HEADER IN LISTS LIBERAC_PUBLIC_HEADER_NAMES)
    list(APPEND LIBERAC_PUBLIC_HEADERS
        "${CMAKE_CURRENT_SOURCE_DIR}/inc/${LIBERAC_PUBLIC_HEADER}")
endforeach()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(MLDSA_BACKEND_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/DigitalSignature/ML-DSA/Backend)
set(SLHDSA_BACKEND_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/DigitalSignature/SLH-DSA/Backend)
set(AIMER_BACKEND_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/DigitalSignature/AIMer/Backend)
set(HAETAE_SOURCE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/DigitalSignature/HAETAE)

# CMake 3.17 added the supported opt-out for AIX's automatic all-symbol
# export. Set the initializer before creating the shared-library target.
if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    if(CMAKE_VERSION VERSION_LESS "3.17")
        message(FATAL_ERROR
            "Restricted AIX exports require CMake 3.17 or newer")
    endif()
    set(CMAKE_AIX_EXPORT_ALL_SYMBOLS OFF)
endif()

set(LIBERAC_SOURCES
    # Public ABI entry points: one translation unit per operational category.
    src/AsymmetricCipher.c
    src/BlockCipher.c
    src/DigitalSignature.c
    src/HashFunction.c
    src/MessageAuthentication.c
    src/KeyAgreement.c
    src/KeyDerivation.c
    src/KeyEncapsulation.c
    src/RandomNumberGeneration.c
    src/Util.c

    # Private implementations grouped by primitive family and algorithm.
    src/Util/Core/secure_zero.c
    src/Util/Core/memory.c
    src/BlockCipher/AES/aes.c
    src/BlockCipher/AES/aes_aead.c
    src/BlockCipher/TripleDES/triple_des.c
    src/RandomNumberGeneration/CTR_DRBG/ctr_drbg.c
    src/RandomNumberGeneration/KAT/pqc_kat_rng.c
    src/Util/Bignum/bignum.c
    src/Util/Bignum/bignum_secure.c
    src/Util/Bignum/bignum_secret_arith.c
    src/Util/Bignum/bignum_secret_io.c
    src/Util/Bignum/bignum_vartime.c
    src/Util/ECC/ecc_curves.c
    src/Util/ECC/ecc_field.c
    src/Util/ECC/ecc_projective.c
    src/Util/ECC/ecc_reference.c
    src/Util/ECC/ecc_scalar_arith.c
    src/Util/ECC/ecc_scalar_vartime.c
    src/Util/ECC/ecc_scalar_secret.c
    src/Util/ECC/ecc_encoding.c
    src/Util/Prime/prime.c
    src/AsymmetricCipher/RSA/rsa.c
    src/AsymmetricCipher/ElGamal/elgamal.c
    src/DigitalSignature/ECDSA/ecdsa.c
    src/KeyAgreement/ecdh.c
    src/KeyAgreement/x25519.c
    src/HashFunction/SHA2/sha2.c
    src/HashFunction/SHA1/sha1.c
    src/HashFunction/SHA3/sha3.c
    src/HashFunction/LSH/lsh.c
    src/RandomNumberGeneration/Noise/random.c
    src/Util/Endian/endian.c
    src/Util/NTT/ntt.c
    src/Util/PQC/pqc.c
    src/KeyEncapsulation/ML-KEM/api.c
    src/KeyEncapsulation/NTRU-Plus/ntru_plus.c
    src/KeyEncapsulation/NTRU-Plus/ntru_plus_hash.c
    src/KeyEncapsulation/NTRU-Plus/ntru_plus_ntt.c
    src/KeyEncapsulation/NTRU-Plus/ntru_plus_poly.c
    src/KeyEncapsulation/SMAUG-T/smaug_t.c
    src/DigitalSignature/AIMer/aimer.c
    src/DigitalSignature/AIMer/Backend/aimer_aim2.c
    src/DigitalSignature/AIMer/Backend/aimer_backend.c
    src/DigitalSignature/AIMer/Backend/aimer_field.c
    src/DigitalSignature/AIMer/Backend/aimer_field128.c
    src/DigitalSignature/AIMer/Backend/aimer_field192.c
    src/DigitalSignature/AIMer/Backend/aimer_field256.c
    src/DigitalSignature/AIMer/Backend/aimer_poly.c
    src/DigitalSignature/AIMer/Backend/aimer_tree.c
    src/DigitalSignature/HAETAE/haetae.c
    src/DigitalSignature/HAETAE/haetae_decompose.c
    src/DigitalSignature/HAETAE/haetae_encoding.c
    src/DigitalSignature/HAETAE/haetae_fft.c
    src/DigitalSignature/HAETAE/haetae_fixpoint.c
    src/DigitalSignature/HAETAE/haetae_ntt.c
    src/DigitalSignature/HAETAE/haetae_packing.c
    src/DigitalSignature/HAETAE/haetae_poly.c
    src/DigitalSignature/HAETAE/haetae_polyfix.c
    src/DigitalSignature/HAETAE/haetae_polymat.c
    src/DigitalSignature/HAETAE/haetae_polyvec.c
    src/DigitalSignature/HAETAE/haetae_reduce.c
    src/DigitalSignature/HAETAE/haetae_sampler.c
    src/DigitalSignature/ML-DSA/ml_dsa.c
    src/DigitalSignature/SLH-DSA/slh_dsa.c
)

list(APPEND LIBERAC_SOURCES
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

add_library(LiberaCrypt ${LIBERAC_SOURCES}
    $<TARGET_OBJECTS:crypto_mldsa>
    $<TARGET_OBJECTS:crypto_slhdsa>
)
add_library(LiberaCrypt::LiberaCrypt ALIAS LiberaCrypt)

set_target_properties(LiberaCrypt PROPERTIES
    OUTPUT_NAME liberacrypt
    POSITION_INDEPENDENT_CODE ON
    WINDOWS_EXPORT_ALL_SYMBOLS OFF
)

if(WIN32 AND BUILD_SHARED_LIBS)
    # Keep a prefix-free DLL name on every Windows toolchain so MinGW and MSVC
    # install the same runtime filename: liberacrypt.dll.
    set_target_properties(LiberaCrypt PROPERTIES PREFIX "")
endif()

target_include_directories(LiberaCrypt
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
        $<INSTALL_INTERFACE:inc>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/DigitalSignature/ML-DSA
        ${MLDSA_BACKEND_DIR}
        ${SLHDSA_BACKEND_DIR}
)
target_compile_definitions(LiberaCrypt PRIVATE
    MLD_CONFIG_NO_RANDOMIZED_API
    MLD_CONFIG_MULTILEVEL_BUILD
    MLD_CONFIG_NAMESPACE_PREFIX=mldsa
)

if(WIN32)
    target_link_libraries(LiberaCrypt PRIVATE bcrypt)
endif()

include(cmake/LiberaCryptExports.cmake)
liberac_configure_exports(LiberaCrypt)
liberac_configure_portable_warnings(LiberaCrypt crypto_mldsa crypto_slhdsa)
liberac_configure_vendor_endianness(
    SLHDSA_TARGET crypto_slhdsa
    MLDSA_TARGET crypto_mldsa
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(LIBERAC_CMAKE_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/LiberaCrypt)
configure_package_config_file(
    cmake/LiberaCryptConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/LiberaCryptConfig.cmake
    INSTALL_DESTINATION ${LIBERAC_CMAKE_INSTALL_DIR}
    NO_SET_AND_CHECK_MACRO
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/LiberaCryptConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(TARGETS LiberaCrypt
    EXPORT LiberaCryptTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES ${LIBERAC_PUBLIC_HEADERS} DESTINATION inc)
install(EXPORT LiberaCryptTargets NAMESPACE LiberaCrypt:: DESTINATION ${LIBERAC_CMAKE_INSTALL_DIR})
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/LiberaCryptConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/LiberaCryptConfigVersion.cmake
    DESTINATION ${LIBERAC_CMAKE_INSTALL_DIR}
)
set(LIBERAC_LICENSE_INSTALL_DIR ${CMAKE_INSTALL_DATADIR}/licenses/LiberaCrypt)
install(FILES LICENSE
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME AGPL-3.0-only.txt
)
install(FILES THIRD_PARTY_NOTICES.md
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
)
install(FILES ${MLDSA_BACKEND_DIR}/LICENSE
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME mldsa-native-LICENSE.txt
)
install(FILES ${SLHDSA_BACKEND_DIR}/LICENSE
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME slhdsa-c-LICENSE.txt
)
install(FILES src/KeyEncapsulation/NTRU-Plus/LICENSE
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME ntru-plus-LICENSE.txt
)
install(FILES src/KeyEncapsulation/NTRU-Plus/UPSTREAM.md
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME ntru-plus-UPSTREAM.md
)
install(FILES src/KeyEncapsulation/SMAUG-T/LICENSE
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME smaug-t-LICENSE.txt
)
install(FILES src/KeyEncapsulation/SMAUG-T/UPSTREAM.md
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME smaug-t-UPSTREAM.md
)
install(FILES ${AIMER_BACKEND_DIR}/LICENSE
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME aimer-LICENSE.txt
)
install(FILES ${AIMER_BACKEND_DIR}/NOTICE
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME aimer-NOTICE.txt
)
install(FILES ${AIMER_BACKEND_DIR}/README.md
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME aimer-UPSTREAM.md
)
install(FILES ${HAETAE_SOURCE_DIR}/LICENSE
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME haetae-LICENSE.txt
)
install(FILES ${HAETAE_SOURCE_DIR}/NOTICE
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME haetae-NOTICE.txt
)
install(FILES ${HAETAE_SOURCE_DIR}/UPSTREAM.md
    DESTINATION ${LIBERAC_LICENSE_INSTALL_DIR}
    RENAME haetae-UPSTREAM.md
)

if(LIBERAC_BUILD_DOCS)
    find_package(Doxygen 1.12 REQUIRED)
    set(LIBERAC_DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/docs")
    set(LIBERAC_DOXYGEN_INDEX
        "${LIBERAC_DOXYGEN_OUTPUT_DIR}/html/index.html")
    set(LIBERAC_DOXYGEN_WARNINGS
        "${LIBERAC_DOXYGEN_OUTPUT_DIR}/warnings.log")
    configure_file(
        cmake/Doxyfile.in
        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        @ONLY
    )
    add_custom_target(liberacrypt_docs
        COMMAND ${CMAKE_COMMAND} -E make_directory
                ${LIBERAC_DOXYGEN_OUTPUT_DIR}
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        DEPENDS ${LIBERAC_PUBLIC_HEADERS} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        BYPRODUCTS ${LIBERAC_DOXYGEN_INDEX} ${LIBERAC_DOXYGEN_WARNINGS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating LiberaCrypt public API documentation"
        VERBATIM
    )
endif()

if(LIBERAC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
    add_subdirectory(tests/MessageAuthentication)
    add_subdirectory(tests/KeyDerivation)
    add_subdirectory(tests/ECC)
    add_subdirectory(tests/KeyAgreement)
endif()
