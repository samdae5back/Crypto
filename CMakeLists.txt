cmake_minimum_required(VERSION 3.10)
project(Crypto VERSION 0.4.0 LANGUAGES C)

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

set(CRYPTO_SOURCES
    src/CORE/core.c
    src/AES/aes.c
    src/AES/aes_aead.c
    src/BIGNUM/bignum.c
    src/PRIME/prime.c
    src/RSA/rsa.c
    src/ELGAMAL/elgamal.c
    src/SHA3/sha3.c
    src/HASH/hash.c
    src/RANDOM/random.c
    src/ENDIAN/endian.c
    src/NTT/ntt.c
    src/ML_KEM/api.c
)

set(MLKEM_VARIANT_SOURCES
    src/ML_KEM/K-PKE.c
    src/ML_KEM/ML-KEM.c
    src/ML_KEM/NTT_.c
    src/ML_KEM/auxiliary.c
    src/ML_KEM/hash.c
)

function(add_mlkem_variant target suffix kval eta1 eta2 du dv)
    add_library(${target} OBJECT ${MLKEM_VARIANT_SOURCES})
    set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ML_KEM
    )
    target_compile_definitions(${target} PRIVATE
        MLKEM_Q=3329 MLKEM_N=256 MLKEM_K=${kval} MLKEM_ETA1=${eta1} MLKEM_ETA2=${eta2} MLKEM_DU=${du} MLKEM_DV=${dv}
        zeta=zeta_${suffix}
        GenZeta=GenZeta_${suffix} bit_rev=bit_rev_${suffix}
        NTT=NTT_${suffix} NTT_inv=NTT_inv_${suffix}
        Multiply_basic=Multiply_basic_${suffix} Multiply_NTT=Multiply_NTT_${suffix}
        exp_int=exp_int_${suffix} Bit2Byte=Bit2Byte_${suffix} Byte2Bit=Byte2Bit_${suffix}
        ByteEncode=ByteEncode_${suffix} ByteDecode=ByteDecode_${suffix}
        SampleNTT=SampleNTT_${suffix} SamplePolyCBD=SamplePolyCBD_${suffix}
        Comp=Comp_${suffix} Decomp=Decomp_${suffix}
        RBG=RBG_${suffix} sha3_256_hash=sha3_256_hash_${suffix}
        sha3_512_hash=sha3_512_hash_${suffix} shake_256_hash=shake_256_hash_${suffix}
        PRF=PRF_${suffix} H=H_${suffix} J=J_${suffix} G=G_${suffix}
        XOF_init=XOF_init_${suffix} XOF_absorb=XOF_absorb_${suffix}
        XOF_squeeze=XOF_squeeze_${suffix} XOF_clear=XOF_clear_${suffix}
        K_PKE_KeyGen=K_PKE_KeyGen_${suffix} K_PKE_Enc=K_PKE_Enc_${suffix} K_PKE_Dec=K_PKE_Dec_${suffix}
        ML_KEM_KeyGen_internal=ML_KEM_KeyGen_internal_${suffix}
        ML_KEM_Encaps_internal=ML_KEM_Encaps_internal_${suffix}
        ML_KEM_Decaps_internal=ML_KEM_Decaps_internal_${suffix}
        ML_KEM_KeyGen=ML_KEM_KeyGen_${suffix}
        ML_KEM_Encaps=ML_KEM_Encaps_${suffix}
        ML_KEM_Decaps=ML_KEM_Decaps_${suffix}
    )
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -pedantic)
    endif()
endfunction()

add_mlkem_variant(crypto_mlkem512 512 2 3 2 10 4)
add_mlkem_variant(crypto_mlkem768 768 3 2 2 10 4)
add_mlkem_variant(crypto_mlkem1024 1024 4 2 2 11 5)

add_library(Crypto ${CRYPTO_SOURCES}
    $<TARGET_OBJECTS:crypto_mlkem512>
    $<TARGET_OBJECTS:crypto_mlkem768>
    $<TARGET_OBJECTS:crypto_mlkem1024>
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
    add_executable(crypto_tests tests/test_crypto.c)
    target_link_libraries(crypto_tests PRIVATE Crypto)
    add_test(NAME crypto_tests COMMAND crypto_tests)
endif()
