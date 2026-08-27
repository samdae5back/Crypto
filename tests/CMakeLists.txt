function(crypto_add_public_test TARGET_NAME TEST_NAME SOURCE_FILE TEST_LABELS)
    add_executable(${TARGET_NAME} ${SOURCE_FILE})
    target_link_libraries(${TARGET_NAME} PRIVATE Crypto)
    # Keep shared-library tests beside the Crypto DLL on Windows. Otherwise
    # the loader can resolve an unrelated system libcrypto.dll first.
    set_target_properties(${TARGET_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
    crypto_configure_portable_warnings(${TARGET_NAME})
    add_test(NAME ${TEST_NAME} COMMAND ${TARGET_NAME})
    set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${TEST_LABELS}")
endfunction()

crypto_add_public_test(
    crypto_public_headers_test
    Crypto.PublicAPI.Headers
    PublicAPI/PublicHeaders.c
    "unit;public-api"
)

# Compile every installed header in an otherwise empty translation unit. This
# catches accidental reliance on include order while retaining the umbrella
# runtime check above for the public types used together.
foreach(CRYPTO_PUBLIC_HEADER IN ITEMS
        AsymmetricCipher.h
        BlockCipher.h
        Crypto.h
        Def.h
        DigitalSignature.h
        HashFunction.h
        KeyEncapsulation.h
        RandomNumberGeneration.h
        Util.h)
    get_filename_component(
        CRYPTO_PUBLIC_HEADER_STEM "${CRYPTO_PUBLIC_HEADER}" NAME_WE)
    string(TOLOWER
        "${CRYPTO_PUBLIC_HEADER_STEM}" CRYPTO_PUBLIC_HEADER_SUFFIX)
    add_library(crypto_public_header_${CRYPTO_PUBLIC_HEADER_SUFFIX} OBJECT
        PublicAPI/HeaderIsolation.c)
    target_include_directories(
        crypto_public_header_${CRYPTO_PUBLIC_HEADER_SUFFIX} PRIVATE
        ${PROJECT_SOURCE_DIR}/inc)
    target_compile_definitions(
        crypto_public_header_${CRYPTO_PUBLIC_HEADER_SUFFIX} PRIVATE
        CRYPTO_TEST_HEADER="${CRYPTO_PUBLIC_HEADER}")
    crypto_configure_portable_warnings(
        crypto_public_header_${CRYPTO_PUBLIC_HEADER_SUFFIX})
    add_dependencies(crypto_public_headers_test
        crypto_public_header_${CRYPTO_PUBLIC_HEADER_SUFFIX})
endforeach()

crypto_add_public_test(
    crypto_block_cipher_unit
    Crypto.BlockCipher.AES.Unit
    BlockCipher/AES/UnitTest.c
    "unit;block-cipher;aes"
)
crypto_add_public_test(
    crypto_block_cipher_kat
    Crypto.BlockCipher.AES.KAT
    BlockCipher/AES/KAT.c
    "kat;block-cipher;aes"
)

crypto_add_public_test(
    crypto_hash_function_unit
    Crypto.HashFunction.Unit
    HashFunction/UnitTest.c
    "unit;hash-function"
)
crypto_add_public_test(
    crypto_hash_function_streaming
    Crypto.HashFunction.Streaming
    HashFunction/StreamingTest.c
    "unit;hash-function;streaming"
)
crypto_add_public_test(
    crypto_hash_function_kat
    Crypto.HashFunction.KAT
    HashFunction/KAT.c
    "kat;hash-function"
)

crypto_add_public_test(
    crypto_ctr_drbg_unit
    Crypto.RandomNumberGeneration.CTR-DRBG.Unit
    RandomNumberGeneration/CTR-DRBG/UnitTest.c
    "unit;random-number-generation;ctr-drbg"
)
crypto_add_public_test(
    crypto_ctr_drbg_kat
    Crypto.RandomNumberGeneration.CTR-DRBG.KAT
    RandomNumberGeneration/CTR-DRBG/KAT.c
    "kat;random-number-generation;ctr-drbg"
)

crypto_add_public_test(
    crypto_util_unit
    Crypto.Util.Unit
    Util/UnitTest.c
    "unit;util"
)
crypto_add_public_test(
    crypto_asymmetric_cipher_unit
    Crypto.AsymmetricCipher.Unit
    AsymmetricCipher/UnitTest.c
    "unit;asymmetric-cipher"
)
crypto_add_public_test(
    crypto_ml_kem_unit
    Crypto.KeyEncapsulation.ML-KEM.Unit
    KeyEncapsulation/ML-KEM/UnitTest.c
    "unit;pqc;key-encapsulation;ml-kem"
)
crypto_add_public_test(
    crypto_ml_dsa_unit
    Crypto.DigitalSignature.ML-DSA.Unit
    DigitalSignature/ML-DSA/UnitTest.c
    "unit;pqc;digital-signature;ml-dsa"
)
crypto_add_public_test(
    crypto_slh_dsa_unit
    Crypto.DigitalSignature.SLH-DSA.Unit
    DigitalSignature/SLH-DSA/UnitTest.c
    "unit;pqc;digital-signature;slh-dsa;slow"
)

# The normal Crypto target intentionally has no deterministic-randomness
# control surface. Build a test-exclusive static copy whose PQC randomness
# provider can be switched to the KAT AES-256 CTR-DRBG by the private test API.
set(CRYPTO_PQC_KAT_MODULE_SOURCES "")
foreach(CRYPTO_PQC_KAT_SOURCE IN LISTS CRYPTO_SOURCES)
    list(APPEND CRYPTO_PQC_KAT_MODULE_SOURCES
        "${PROJECT_SOURCE_DIR}/${CRYPTO_PQC_KAT_SOURCE}")
endforeach()

add_library(crypto_pqc_kat_module STATIC
    ${CRYPTO_PQC_KAT_MODULE_SOURCES}
    $<TARGET_OBJECTS:crypto_mldsa>
    $<TARGET_OBJECTS:crypto_slhdsa>
)
set_target_properties(crypto_pqc_kat_module PROPERTIES
    POSITION_INDEPENDENT_CODE ON)
target_include_directories(crypto_pqc_kat_module PRIVATE
    ${PROJECT_SOURCE_DIR}/inc
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/DigitalSignature/ML-DSA
    ${MLDSA_BACKEND_DIR}
    ${SLHDSA_BACKEND_DIR}
)
target_compile_definitions(crypto_pqc_kat_module PRIVATE
    CRYPTO_ENABLE_PQC_KAT
    MLD_CONFIG_NO_RANDOMIZED_API
    MLD_CONFIG_MULTILEVEL_BUILD
    MLD_CONFIG_NAMESPACE_PREFIX=mldsa
)
if(WIN32)
    target_link_libraries(crypto_pqc_kat_module PUBLIC bcrypt)
endif()
crypto_configure_portable_warnings(crypto_pqc_kat_module)

add_executable(crypto_ml_kem_kat
    KeyEncapsulation/ML-KEM/KAT.c
    Internal/KatReader.c
)
add_executable(crypto_ml_dsa_kat
    DigitalSignature/ML-DSA/KAT.c
    Internal/KatReader.c
    Internal/SignatureKat.c
)
add_executable(crypto_slh_dsa_kat
    DigitalSignature/SLH-DSA/KAT.c
    Internal/KatReader.c
    Internal/SignatureKat.c
)

foreach(CRYPTO_PQC_KAT_TARGET
        crypto_ml_kem_kat crypto_ml_dsa_kat crypto_slh_dsa_kat)
    target_include_directories(${CRYPTO_PQC_KAT_TARGET} PRIVATE
        ${PROJECT_SOURCE_DIR}/inc
        ${PROJECT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_compile_definitions(${CRYPTO_PQC_KAT_TARGET} PRIVATE
        CRYPTO_ENABLE_PQC_KAT)
    if(MSVC)
        target_compile_definitions(${CRYPTO_PQC_KAT_TARGET} PRIVATE
            _CRT_SECURE_NO_WARNINGS)
    endif()
    target_link_libraries(${CRYPTO_PQC_KAT_TARGET} PRIVATE
        crypto_pqc_kat_module)
    set_target_properties(${CRYPTO_PQC_KAT_TARGET} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
    crypto_configure_portable_warnings(${CRYPTO_PQC_KAT_TARGET})
endforeach()

function(crypto_add_pqc_kat TEST_NAME TARGET_NAME VECTOR_FILE SELECTOR LABELS)
    add_test(NAME ${TEST_NAME}
        COMMAND ${TARGET_NAME}
            "${PROJECT_SOURCE_DIR}/KAT/${VECTOR_FILE}" "${SELECTOR}")
    set_tests_properties(${TEST_NAME} PROPERTIES
        LABELS "kat;pqc;${LABELS}"
        TIMEOUT 1800)
endfunction()

crypto_add_pqc_kat(Crypto.KeyEncapsulation.ML-KEM-512.KAT
    crypto_ml_kem_kat mlkem512.kat ML-KEM-512 "key-encapsulation;ml-kem")
crypto_add_pqc_kat(Crypto.KeyEncapsulation.ML-KEM-768.KAT
    crypto_ml_kem_kat mlkem768.kat ML-KEM-768 "key-encapsulation;ml-kem")
crypto_add_pqc_kat(Crypto.KeyEncapsulation.ML-KEM-1024.KAT
    crypto_ml_kem_kat mlkem1024.kat ML-KEM-1024 "key-encapsulation;ml-kem")

crypto_add_pqc_kat(Crypto.DigitalSignature.ML-DSA-44.KAT
    crypto_ml_dsa_kat mldsa44.kat ML-DSA-44 "digital-signature;ml-dsa")
crypto_add_pqc_kat(Crypto.DigitalSignature.ML-DSA-65.KAT
    crypto_ml_dsa_kat mldsa65.kat ML-DSA-65 "digital-signature;ml-dsa")
crypto_add_pqc_kat(Crypto.DigitalSignature.ML-DSA-87.KAT
    crypto_ml_dsa_kat mldsa87.kat ML-DSA-87 "digital-signature;ml-dsa")

crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHA2-128s.KAT
    crypto_slh_dsa_kat slhdsa_sha2_128s.kat SLH-DSA-SHA2-128s
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHA2-128f.KAT
    crypto_slh_dsa_kat slhdsa_sha2_128f.kat SLH-DSA-SHA2-128f
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHA2-192s.KAT
    crypto_slh_dsa_kat slhdsa_sha2_192s.kat SLH-DSA-SHA2-192s
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHA2-192f.KAT
    crypto_slh_dsa_kat slhdsa_sha2_192f.kat SLH-DSA-SHA2-192f
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHA2-256s.KAT
    crypto_slh_dsa_kat slhdsa_sha2_256s.kat SLH-DSA-SHA2-256s
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHA2-256f.KAT
    crypto_slh_dsa_kat slhdsa_sha2_256f.kat SLH-DSA-SHA2-256f
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHAKE-128s.KAT
    crypto_slh_dsa_kat slhdsa_shake_128s.kat SLH-DSA-SHAKE-128s
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHAKE-128f.KAT
    crypto_slh_dsa_kat slhdsa_shake_128f.kat SLH-DSA-SHAKE-128f
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHAKE-192s.KAT
    crypto_slh_dsa_kat slhdsa_shake_192s.kat SLH-DSA-SHAKE-192s
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHAKE-192f.KAT
    crypto_slh_dsa_kat slhdsa_shake_192f.kat SLH-DSA-SHAKE-192f
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHAKE-256s.KAT
    crypto_slh_dsa_kat slhdsa_shake_256s.kat SLH-DSA-SHAKE-256s
    "digital-signature;slh-dsa;slow")
crypto_add_pqc_kat(Crypto.DigitalSignature.SLH-DSA-SHAKE-256f.KAT
    crypto_slh_dsa_kat slhdsa_shake_256f.kat SLH-DSA-SHAKE-256f
    "digital-signature;slh-dsa;slow")
