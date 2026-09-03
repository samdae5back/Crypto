cmake_minimum_required(VERSION 3.16)
project(LiberaCryptBignumBenchmark LANGUAGES C)

if(NOT DEFINED LIBERACRYPT_SOURCE_ROOT)
    message(FATAL_ERROR "LIBERACRYPT_SOURCE_ROOT must point to the LiberaCrypt source tree")
endif()

find_package(LiberaCrypt CONFIG REQUIRED)

function(liberac_add_bignum_benchmark TARGET_NAME SOURCE_FILE)
    add_executable(${TARGET_NAME} ${SOURCE_FILE})
    target_link_libraries(${TARGET_NAME} PRIVATE LiberaCrypt::LiberaCrypt)
    target_include_directories(${TARGET_NAME} PRIVATE
        "${LIBERACRYPT_SOURCE_ROOT}/src"
        "${LIBERACRYPT_SOURCE_ROOT}/inc")
    set_target_properties(${TARGET_NAME} PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    if(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(${TARGET_NAME} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
            -Wshadow -Werror)
    endif()
endfunction()

liberac_add_bignum_benchmark(liberacrypt_bignum_benchmark Benchmark.c)
liberac_add_bignum_benchmark(
    liberacrypt_bignum_stage1_accurate_benchmark Stage1AccurateBenchmark.c)
liberac_add_bignum_benchmark(
    liberacrypt_bignum_stage2_benchmark Stage2Benchmark.c)
liberac_add_bignum_benchmark(
    liberacrypt_bignum_stage3_benchmark Stage3Benchmark.c)
