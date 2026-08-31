set(LIBERAC_ECC_TEST_SOURCES
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_curves.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_field.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_projective.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_reference.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_scalar_vartime.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_scalar_secret.c
    ${CMAKE_SOURCE_DIR}/src/Util/ECC/ecc_encoding.c
    ${CMAKE_SOURCE_DIR}/src/Util/Util.c
)

function(liberac_add_ecc_executable target source)
    add_executable(${target} ${source} ${LIBERAC_ECC_TEST_SOURCES})
    target_include_directories(${target} PRIVATE
        ${CMAKE_SOURCE_DIR}/inc
        ${CMAKE_SOURCE_DIR}/src
    )
    if(LIBERAC_BIG_ENDIAN)
        target_compile_definitions(${target} PRIVATE BIG_ENDIAN_SYSTEM)
    else()
        target_compile_definitions(${target} PRIVATE LITTLE_ENDIAN_SYSTEM)
    endif()
    if(MSVC)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
    liberac_configure_warnings(${target})
endfunction()

liberac_add_ecc_executable(liberacrypt_ecc_unit UnitTest.c)
add_test(NAME liberacrypt_ecc_unit COMMAND liberacrypt_ecc_unit)

liberac_add_ecc_executable(liberacrypt_ecc_differential DifferentialTest.c)
add_test(NAME liberacrypt_ecc_differential COMMAND liberacrypt_ecc_differential)

liberac_add_ecc_executable(liberacrypt_ecc_benchmark
    ${CMAKE_SOURCE_DIR}/benchmarks/ECC/Benchmark.c)
