---
name: unit-tests
description: Writing and running the GoogleTest unit suite for the server-independent C core (gcm, envelope, nonce) against spec/test-vectors.json, with sanitizers, the collision-bound test and the error-path resource test. Use it when adding or changing a core test, or vectors.
---

# unit-tests

Rules: `testing.md` (GWT, no branching, parameterise). Layout:
```
tests/unit/CMakeLists.txt   C11 core + C++17 tests, links libcrypto only, enable_testing()
tests/unit/*_test.cc        extern "C" { #include "gcm.h" }
```
- `enable_testing()` and `gtest_discover_tests` — without `enable_testing()`, `ctest` reports
  "No tests were found" and exits 0, so the gate passes while running nothing. Assert in CI that the test count is non-zero.
- Load `spec/test-vectors.json` once per suite and parameterise over every case (`TEST_P` with
  `INSTANTIATE_TEST_SUITE_P`); a vector that no test consumes is a failure.
- GoogleTest comes from the system (`find_package(GTest)`; `libgtest-dev` in the build image) or,
  when it is absent, from `FetchContent` pinned to a commit.
- Counting allocator (`alloc_counter.{h,cc}`): `CRYPTO_set_mem_functions` before any OpenSSL call in
  `main`, so a test can assert that an error path freed everything it allocated. OpenSSL keeps some
  allocations for the life of the process or thread (the DRBGs, the thread's error state), so `main`
  exercises every operation and every allocation failure once before any test takes a baseline.
  `leak_test.cc` then fails the n-th allocation inside each core call, for every n a call can reach. **Assert that it returned 1**: it returns 0
  once OpenSSL has allocated, and a gate that silently counts nothing is the same failure as the unit
  gate above that ran nothing. It is also the only leak gate there is — it cannot be installed in a backend
  (design §8, O8).
- Run: `cmake -S tests/unit -B build/unit -DCMAKE_BUILD_TYPE=Debug && cmake --build build/unit -j && ctest --test-dir build/unit --output-on-failure`.
- On macOS, also run the suite in the Linux build image (`scripts/unit-in-docker.sh <major>`) — the
  CI compiler is GCC, and that image has the libcrypto the server links.
- Until `spec/test-vectors.json` exists (Phase 1), the known answers are in the test sources with
  the command that produced them; they move to the JSON file then.
- Vectors: `python scripts/check-vectors.py` re-derives every vector with `cryptography` and fails on
  a mismatch with `spec/test-vectors.json`.
