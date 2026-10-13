# SPDX-License-Identifier: PostgreSQL
# Core micro-benchmarks for the server-independent core (src/gcm.c, envelope.c, nonce.c),
# measured against bare OpenSSL EVP. Links libcrypto and Google Benchmark only: no server.
# Ratios, not nanoseconds, are the gate; the ceilings live in tests/bench/baseline.json.
cmake_minimum_required(VERSION 3.20)
project(pg_gcm_bench LANGUAGES C CXX)

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

find_package(benchmark QUIET)
if(NOT benchmark_FOUND)
  # The build image installs libbenchmark-dev; this is the fallback for a local build, pinned
  # by commit like googletest (tests/unit/CMakeLists.txt).
  include(FetchContent)
  set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG eddb0241389718a23a42db6af5f0164b6e0139af) # v1.9.4
  FetchContent_MakeAvailable(benchmark)
endif()

find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
  include(FetchContent)
  FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG 9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03) # v3.11.3
  FetchContent_MakeAvailable(nlohmann_json)
endif()

# No sanitizers: they would distort what is being measured. A release build never has them.
set(CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../src)

add_library(pg_gcm_bench_core STATIC
  ${CORE_DIR}/gcm.c
  ${CORE_DIR}/envelope.c
  ${CORE_DIR}/nonce.c)
target_include_directories(pg_gcm_bench_core PUBLIC ${CORE_DIR})
target_compile_options(pg_gcm_bench_core PRIVATE -Wall -Wextra -Werror)
target_link_libraries(pg_gcm_bench_core PUBLIC OpenSSL::Crypto)

add_executable(pg_gcm_bench benchmark.cc)
target_compile_options(pg_gcm_bench PRIVATE -Wall -Wextra -Werror)
target_link_libraries(pg_gcm_bench PRIVATE pg_gcm_bench_core benchmark::benchmark
                      nlohmann_json::nlohmann_json)
# The ceilings are read from the file, never copied into the code.
target_compile_definitions(pg_gcm_bench PRIVATE
  PG_GCM_BENCH_BASELINE="${CMAKE_CURRENT_SOURCE_DIR}/baseline.json")
