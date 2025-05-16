cmake_minimum_required(VERSION 3.10)
project(ML-KEM C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic")

file(GLOB_RECURSE SOURCES "source/*.c" "source/*.h")
file(GLOB_RECURSE TESTS "test/*.c")

add_executable(${PROJECT_NAME} ${SOURCES})

find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
if (OpenSSL_FOUND)
    include_directories(${OpenSSL_INCLUDE_DIRS})
    message(STATUS "Project Name: ${PROJECT_NAME}")
    target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "Found OpenSSL library")
else()
    message(FATAL_ERROR "OpenSSL library not found")
endif()

if (BUILD_TESTING)
    enable_testing()
    add_executable(runTests ${TESTS} ${SOURCES})
    target_link_libraries(runTests PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    add_test(NAME UnitTests COMMAND runTests)
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(DIRECTORY source/ DESTINATION include)

# 설치 규칙 (선택 사항)
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(DIRECTORY source/ DESTINATION include) # 헤더 파일 설치