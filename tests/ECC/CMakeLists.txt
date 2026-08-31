set(LIBERAC_ECC_SOURCES
    ${PROJECT_SOURCE_DIR}/src/Util/ECC/ecc_curves.c
    ${PROJECT_SOURCE_DIR}/src/Util/ECC/ecc_field.c
    ${PROJECT_SOURCE_DIR}/src/Util/ECC/ecc_projective.c
    ${PROJECT_SOURCE_DIR}/src/Util/ECC/ecc_reference.c
    ${PROJECT_SOURCE_DIR}/src/Util/ECC/ecc_encoding.c
)

function(liberac_configure_ecc_internal_target target source)
    add_executable(${target}
        ${source}
        ${LIBERAC_ECC_SOURCES}
        ${PROJECT_SOURCE_DIR}/src/Util/Core/secure_zero.c
    )
    target_include_directories(${target} PRIVATE
        ${PROJECT_SOURCE_DIR}/inc
        ${PROJECT_SOURCE_DIR}/src
    )
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${PROJECT_BINARY_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${PROJECT_BINARY_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${PROJECT_BINARY_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${PROJECT_BINARY_DIR}"
    )
    liberac_configure_portable_warnings(${target})
endfunction()

if(LIBERAC_BUILD_TESTS)
    liberac_configure_ecc_internal_target(
        crypto_ecc_internal_unit
        ${CMAKE_CURRENT_SOURCE_DIR}/UnitTest.c
    )
    add_test(
        NAME LiberaCrypt.ECC.Internal.Unit
        COMMAND crypto_ecc_internal_unit
    )
    set_tests_properties(
        LiberaCrypt.ECC.Internal.Unit
        PROPERTIES LABELS "unit;internal;ecc"
    )
endif()

if(LIBERAC_BUILD_BENCHMARKS)
    liberac_configure_ecc_internal_target(
        crypto_ecc_benchmark
        ${CMAKE_CURRENT_SOURCE_DIR}/Benchmark.c
    )
endif()
