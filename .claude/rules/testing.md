---
paths:
  - "tests/**"
  - "test/**"
  - "spec/test-vectors.json"
---
<!-- Generated from .agents/rules/testing.md by scripts/agents-sync.py — edit the source. -->
# Testing rules — GWT and the pyramid

```
        e2e / load        Real servers. e2e: replication; pushes, and PRs that touch what it tests. load: LIKE at scale; nightly and on demand
       bench (gbench)     Core micro-benchmarks. Merges to develop/main + nightly. No server
     regress (pg_regress) Real-server SQL scenarios, every supported major. PR gate
   unit (gtest)           The server-independent core plus vectors. Seconds. PR gate, and run before committing
```

## GWT (Given-When-Then) — mandatory at every layer
- **Body**: mark Given, When and Then in order. One test, one action.
- **No branching or looping** in a test case body (`if`, `else`, `for`, `while`). Split per condition or
  parameterise (`TEST_P`). Do not reimplement the algorithm under test to compute an expected value.
- **Name**: given/when/then visible.
  - gtest: `TEST(Envelope, GivenEmptyInput_WhenParsed_ThenBadEnvelope)`
  - pg_regress: one file per behaviour, starting with `-- Given: ...`, `-- When: ...`, `-- Then: ...`
    comments, which `pg_regress` echoes into `expected/` where a reviewer reads them.
- **Given** builds state, **When** is a single call, **Then** only asserts.

```sql
-- Given: a deterministic envelope of a Korean name, strict on
SET pg_gcm.strict = on;
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
-- When: the decrypted value is filtered with native LIKE
SELECT gcm_decrypt(gcm_encrypt_det('홍길동', :k), :k) LIKE '%길%' AS hit;
-- Then: hit = t (see expected/)
```

## Common
- Every vector lives in `spec/test-vectors.json`. Unit and regression tests read
  every case from it; never copy a value out of it.
- The two layers do not assert the same thing (spec §1.11, §2.8). The **unit** suite consumes every
  vector, bytes compared: a `nist` vector against the primitive through a test seam — it is not an
  envelope, its associated data is NIST's — and an envelope vector through open, and through seal with
  its `nonce_hex` (a `det` vector derives its own, unless `nonce_derived` is false). The **SQL** suite
  consumes the envelope vectors only: `gcm_decrypt` gives the text when `plaintext_class` is `text`
  and the invalid-UTF-8 error (`22021`) when it is `not_utf8` or `contains_nul`; a `det` vector of
  class `text` must also seal to its `envelope_hex`, with `pg_gcm.min_key_bytes` lowered to 16
  (`SET LOCAL`) for the transaction that seals them; a failing vector gives the error of spec §2.5. No SQL
  test seals a `random` vector — there is no nonce argument, by design.
- `python3 scripts/check-vectors.py` re-derives every vector with a second implementation, and
  `--self-test` checks that it notices each of a fixed list of breaks to the file and the spec. Both
  run in the lint workflow. A vector that the checker cannot reproduce does not go in.
- No real keys and no PHI in a fixture. Keys are the public NIST vectors or the `00..1f` pattern.
- For `gcm_encrypt` (non-deterministic), verify properties: length, version byte, two calls differ,
  and the round trip.
- No flakiness, no retries.

## Unit (`tests/unit`)
- Subject: `gcm.c`, `envelope.c`, `nonce.c`, built without PostgreSQL headers, under
  `-fsanitize=address,undefined`.
- Required cases: NIST CAVP KAT, empty plaintext, with and without AAD, one-bit tag and
  nonce flips, truncated envelopes (0, 1, 12, 28 bytes), unknown version, key lengths 0, 15, 16, 24,
  31, 32, 33, deterministic same-in-same-out, the derived nonce of every `det` vector through
  `gcm_nonce_derive` itself, every suite. (`nonce_key_hex` is an intermediate value that
  `scripts/check-vectors.py` reproduces and no C test reads: the nonce key never leaves
  `gcm_nonce_derive`, and a wrong one cannot give a right nonce.)
- The loader refuses a vector whose `kind` or `expect` it does not know, a member its kind must
  carry and does not, and text that is not whole hexadecimal bytes; two tests compare the ids the
  suites are parameterised over with the ids in the file.
- Deterministic nonce collision bound: zero duplicates over random plaintexts (100k in PR CI, 1M
  on a push and nightly). The test fails when asked for fewer than 100k, or for something that is not
  a number.
- Error-path resource test: every core error path releases every OpenSSL object (counting allocator
  through `CRYPTO_set_mem_functions`, called first in `main`, **with its return value asserted to be
  1** — it returns 0, and counts nothing, once OpenSSL has allocated). This is the project's only leak
  gate: neither it nor valgrind can run inside a stock backend (design §8, O8). It executes the paths
  a tag mismatch or a refused allocation reaches — each allocation of each call refused in turn — and
  no other failure of an EVP call; those exits are held by the one-exit-label structure that
  `scripts/check-architecture.py` enforces. Do not describe it as covering more.
- A second executable never calls `gcm_init`, for the state a failed fetch leaves (design §5.8).

## Regression (`test/sql`, `test/expected`)
- Runs with `make installcheck` against a server in the build image, per supported major.
- Required: a NULL in each argument position of each function giving NULL; empty and maximum-length
  behaviour (`54000` is reached from SQL only where a conversion buffer is the limit: a 256 MB text
  in a non-UTF-8 database; the 1 GB limits are not tested); the two- and three-argument forms, and an empty `aad` equal to the two-argument form;
  wrong key lengths; `pg_gcm.min_key_bytes`, including a placeholder set before the library loads;
  `pg_gcm.strict` on and off; a forged tag; a truncated envelope; the Korean `LIKE '%길%'` case; a
  non-UTF-8 database (`EUC_KR`) round trip and an unrepresentable character; an opened plaintext that
  is not UTF-8, and one holding U+0000, each an error whose message carries no byte of it; a parallel
  scan with `pg_gcm.strict = off` (design §8 O9); volatility, strictness and parallel safety read from
  `pg_proc` (**not** `\df+`, whose columns differ on 15, 16–17 and 18); every vector, as above.
- An `expected/` change is explained in the PR.

## E2E (`tests/e2e`) and load (`tests/load`)
- E2E: primary + streaming replica + a Python runner that encrypts and decrypts only through SQL.
  Required: the replica opens what the primary sealed; deterministic values sealed on the primary join
  on the replica; a NULL in any argument gives NULL. Required as well, because the rest proves
  nothing without it: the second node is in recovery and streaming from the primary, and refuses a
  write. A scenario that holds on both nodes is written once and run by a class per node; the
  shared Given is built once, on the primary, and the runner waits for the replica to replay it —
  a bounded wait on a WAL position, not a retry of a scenario.
- Load: decrypt + `LIKE` at 10k/100k/300k rows, p95 compared with `pgcrypto` `decrypt()` on the same
  rows; the gate lives in `tests/load/baseline.json` and is derived from measurements.
