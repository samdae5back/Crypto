set(LIBERAC_ECC_TEST_SOURCES
    ${CMAKE_SOURCE_DIR}/src/Util/Core/secure_zero.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_curves.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_field.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_projective.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_reference.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_scalar_vartime.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_scalar_secret.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_encoding.c
)

function(liberac_add_ecc_executable target source)
    add_executable(${target} ${source} ${LIBERAC_ECC_TEST_SOURCES})
    target_include_directories(${target} PRIVATE
        ${CMAKE_SOURCE_DIR}/inc
        ${CMAKE_SOURCE_DIR}/src
    )
    if(MSVC)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
    liberac_configure_portable_warnings(${target})
endfunction()

liberac_add_ecc_executable(liberacrypt_ecc_unit UnitTest.c)
add_test(NAME LiberaCrypt.ECC.Unit COMMAND liberacrypt_ecc_unit)
set_tests_properties(LiberaCrypt.ECC.Unit PROPERTIES LABELS "unit;ecc")

liberac_add_ecc_executable(liberacrypt_ecc_differential DifferentialTest.c)
add_test(NAME LiberaCrypt.ECC.Differential COMMAND liberacrypt_ecc_differential)
set_tests_properties(LiberaCrypt.ECC.Differential PROPERTIES LABELS "unit;ecc;differential")

liberac_add_ecc_executable(liberacrypt_ecc_benchmark
    ${CMAKE_SOURCE_DIR}/benchmarks/ECC/Benchmark.c)
