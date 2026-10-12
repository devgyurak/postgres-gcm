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
  seal with its `nonce_hex`. The spike's tests still carry inline known answers from before the spec
  (test cases 13 and 14 of the GCM specification as envelopes, which the spec does not accept as
  such, and nonces derived the old way); replacing them with the file is the first task of Phase 2
  (issue #19).
- Vectors: `python3 scripts/check-vectors.py` re-derives every vector with `cryptography` and the
  standard library's HMAC, requires the vectors the documents name, and checks the worked examples of
  `spec/envelope.md` against them; `--self-test` breaks its inputs and must catch every break. Both
  need `pip install -r scripts/requirements-lint.txt`. A new vector is written as inputs and derived
  by that second implementation — never pasted from the extension's own output.
