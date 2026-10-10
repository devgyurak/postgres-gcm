---
paths:
  - "tests/**"
  - "test/**"
  - "spec/test-vectors.json"
---
<!-- Generated from .agents/rules/testing.md by scripts/agents-sync.py — edit the source. -->
# Testing rules — GWT and the pyramid

```
        e2e / load        Slow. Nightly and release gate. Real servers: replication, mysql-gcm exchange, LIKE at scale
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
- Every vector lives in `spec/test-vectors.json`, shared with mysql-gcm. Unit and regression tests read
  every case from it; never copy a value out of it.
- The two layers do not assert the same thing. The **unit** suite consumes every vector as the spec's
  table says, bytes compared. The **SQL** suite cannot: `gcm_decrypt` returns `text`, and 1,345 of the
  2,304 vectors (the NIST plaintexts and one deterministic case, at mysql-gcm `2fe2da9`) are not UTF-8.
  For those the SQL expectation is "authenticates, then the invalid-UTF-8 error", fixed in the
  PostgreSQL part of the spec; for the rest it is the plaintext. No SQL test feeds a NIST vector to an
  encryption function — there is no nonce argument, by design.
- No real keys and no PHI in a fixture. Keys are the public NIST vectors or the `00..1f` pattern.
- For `gcm_encrypt` (non-deterministic), verify properties: length, version byte, two calls differ,
  and the round trip.
- No flakiness, no retries.

## Unit (`tests/unit`)
- Subject: `gcm.c`, `envelope.c`, `nonce.c`, built without PostgreSQL headers, under
  `-fsanitize=address,undefined`.
- Required cases, as mysql-gcm: NIST CAVP KAT, empty plaintext, with and without AAD, one-bit tag and
  nonce flips, truncated envelopes (0, 1, 12, 28 bytes), unknown version, key lengths 0, 15, 16, 24,
  31, 32, 33, deterministic same-in-same-out, the nonce_key derivation vector, every suite.
- Deterministic nonce collision bound: zero duplicates over random plaintexts (100k in PR CI, 1M
  nightly).
- Error-path resource test: every core error path releases every OpenSSL object (counting allocator
  through `CRYPTO_set_mem_functions`, called first in `main`, **with its return value asserted to be
  1** — it returns 0, and counts nothing, once OpenSSL has allocated). This is the project's only leak
  gate: neither it nor valgrind can run inside a stock backend (design §8, O8).

## Regression (`test/sql`, `test/expected`)
- Runs with `make installcheck` against a server in the build image, per supported major.
- Required: a NULL in each argument position of each function giving NULL; empty and maximum-length
  behaviour; the two- and three-argument forms, and an empty `aad` equal to the two-argument form;
  wrong key lengths; `pg_gcm.min_key_bytes`, including a placeholder set before the library loads;
  `pg_gcm.strict` on and off; a forged tag; a truncated envelope; the Korean `LIKE '%길%'` case; a
  non-UTF-8 database (`EUC_KR`) round trip and an unrepresentable character; an opened plaintext that
  is not UTF-8, and one holding U+0000, each an error whose message carries no byte of it; a parallel
  scan with `pg_gcm.strict = off` (design §8 O9); volatility, strictness and parallel safety read from
  `pg_proc` (**not** `\df+`, whose columns differ on 15, 16–17 and 18); every vector, as above.
- An `expected/` change is explained in the PR.

## E2E (`tests/e2e`) and load (`tests/load`)
- E2E: primary + streaming replica + a mysql-gcm server + a Python runner that encrypts and decrypts
  only through SQL. Required: the replica opens what the primary sealed; an envelope sealed on MySQL
  opens on PostgreSQL and the reverse; deterministic values join across the two when key and AAD match;
  a NULL in any argument gives NULL on both.
- Load: decrypt + `LIKE` at 10k/100k/300k rows, p95 compared with `pgcrypto` `decrypt()` on the same
  rows; the gate lives in `tests/load/baseline.json` and is derived from measurements, as in mysql-gcm.
