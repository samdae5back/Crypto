cmake_minimum_required(VERSION 3.16)
project(LiberaCryptBignumBenchmark LANGUAGES C)

if(NOT DEFINED LIBERACRYPT_SOURCE_ROOT)
    message(FATAL_ERROR "LIBERACRYPT_SOURCE_ROOT must point to the LiberaCrypt source tree")
endif()

find_package(LiberaCrypt CONFIG REQUIRED)

add_executable(liberacrypt_bignum_benchmark Benchmark.c)
target_link_libraries(liberacrypt_bignum_benchmark PRIVATE LiberaCrypt::LiberaCrypt)
target_include_directories(liberacrypt_bignum_benchmark PRIVATE
    "${LIBERACRYPT_SOURCE_ROOT}/src"
    "${LIBERACRYPT_SOURCE_ROOT}/inc")
set_target_properties(liberacrypt_bignum_benchmark PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO)

if(MSVC)
    target_compile_options(liberacrypt_bignum_benchmark PRIVATE
        /W4 /WX /permissive-)
else()
    target_compile_options(liberacrypt_bignum_benchmark PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
        -Wshadow -Werror)
endif()
