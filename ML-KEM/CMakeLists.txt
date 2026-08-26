cmake_minimum_required(VERSION 3.10)
project(ML_KEM C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../common ${CMAKE_CURRENT_BINARY_DIR}/common)

add_executable(ML-KEM
    test.c
    K-PKE.c
    KAT.c
    ML-KEM.c
    NTT_.c
    auxiliary.c
    hash.c
)

target_include_directories(ML-KEM PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../common
)
target_link_libraries(ML-KEM PRIVATE crypto_common)

if(MSVC)
    target_compile_options(ML-KEM PRIVATE /W4)
else()
    target_compile_options(ML-KEM PRIVATE -Wall -Wextra -pedantic)
endif()

# The KAT runner opens this file by relative path.
configure_file(ml_kem_512.kat ml_kem_512.kat COPYONLY)
