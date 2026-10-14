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
- `spec/test-vectors.json` exists (spec §1.11). A `nist` vector runs against the primitive through a
  test seam that takes the whole associated data; an envelope vector runs through open, and through
  seal with its `nonce_hex` (`vectors.{h,cc}`, `vectors_test.cc`); `nonce_test.cc` runs each derived
  nonce through `gcm_nonce_derive`. The loader ends the run on a kind, an expect, a missing member
  or hexadecimal it cannot read, and `VectorFile` compares the ids the suites run with the ids in
  the file. No test file carries a known answer of its own.
- `gtest_discover_tests(... DISCOVERY_MODE PRE_TEST)`: the cases are listed when `ctest` runs, so a
  vector added to the file is run without a rebuild.
- `collision_test.cc` seals `PG_GCM_COLLISION_N` distinct plaintexts (100,000 by default; CI sets
  1,000,000 on a push and nightly) and counts repeated nonces. Its loop is in a helper, not in the
  test body, and it fails when the variable is not a whole number of at least 100,000.
- GCC warns (`-Wdangling-reference`, an error here) on a `const T &` bound to the result of a
  function that takes a temporary by reference: a lookup helper takes `const char *`, not
  `const std::string &`. clang on macOS says nothing, so run the image too.
- Vectors: `python3 scripts/check-vectors.py` re-derives every vector with `cryptography` and the
  standard library's HMAC, requires the vectors the documents name, and checks the worked examples of
  `spec/envelope.md` against them; `--self-test` breaks its inputs and must catch every break. Both
  need `pip install -r scripts/requirements-lint.txt`. A new vector is written as inputs and derived
  by that second implementation — never pasted from the extension's own output.
