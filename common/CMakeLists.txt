cmake_minimum_required(VERSION 3.10)
project(crypto_common C)

add_library(crypto_common STATIC
    sha3.c
    entropy.c
    random.c
    ntt.c
)

target_include_directories(crypto_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(crypto_common PUBLIC c_std_11)

if(MSVC)
    target_compile_options(crypto_common PRIVATE /W4)
else()
    target_compile_options(crypto_common PRIVATE -Wall -Wextra -pedantic)
endif()

if(WIN32)
    target_link_libraries(crypto_common PUBLIC bcrypt)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(crypto_common_tests tests/test_common.c)
    target_link_libraries(crypto_common_tests PRIVATE crypto_common)
    add_test(NAME crypto_common_tests COMMAND crypto_common_tests)
endif()
