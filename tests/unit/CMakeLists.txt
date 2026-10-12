# SPDX-License-Identifier: PostgreSQL
# Unit suite for the server-independent core (src/envelope.c so far; gcm and nonce follow).
# Links libcrypto only: no PostgreSQL header, no server.
cmake_minimum_required(VERSION 3.20)
project(pg_gcm_unit LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Homebrew's OpenSSL is keg-only; point CMake at it unless the caller already did.
if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
  execute_process(COMMAND brew --prefix openssl@3
                  OUTPUT_VARIABLE BREW_OPENSSL OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(BREW_OPENSSL)
    set(OPENSSL_ROOT_DIR "${BREW_OPENSSL}")
  endif()
endif()
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

find_package(GTest QUIET)
if(NOT GTest_FOUND)
  include(FetchContent)
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG 52eb8108c5bdec04579160ae17225d66034bd723) # v1.17.0
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()

# Sanitizers on every unit build; a release build of the extension never has them.
set(SANITIZE -fsanitize=address,undefined -fno-omit-frame-pointer)
set(CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../src)

add_library(pg_gcm_core STATIC
  ${CORE_DIR}/envelope.c)
target_include_directories(pg_gcm_core PUBLIC ${CORE_DIR})
target_compile_options(pg_gcm_core PRIVATE -Wall -Wextra -Werror ${SANITIZE})
target_link_libraries(pg_gcm_core PUBLIC OpenSSL::Crypto)

add_executable(pg_gcm_unit
  main.cc
  alloc_counter.cc
  envelope_test.cc)
target_compile_options(pg_gcm_unit PRIVATE -Wall -Wextra -Werror ${SANITIZE})
target_link_options(pg_gcm_unit PRIVATE ${SANITIZE})
target_link_libraries(pg_gcm_unit PRIVATE pg_gcm_core GTest::gtest GTest::gmock)

# Without enable_testing(), ctest reports "No tests were found" and exits 0.
enable_testing()
include(GoogleTest)
gtest_discover_tests(pg_gcm_unit)
