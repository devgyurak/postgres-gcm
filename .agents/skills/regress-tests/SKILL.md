---
name: regress-tests
description: Writing and running the pg_regress suite (test/sql, test/expected) against a real PostgreSQL server per supported major — SQL behaviour, strict, min_key_bytes, encodings, the Korean LIKE case, parallel workers and extension upgrades. Use it when adding a SQL-level test or re-recording expected output.
---

# regress-tests

Rules: `testing.md`. One `.sql` per behaviour under `test/sql/`, its output under `test/expected/`.

## Writing
- Start each file with `-- Given:`, `-- When:`, `-- Then:` comments; they are echoed into the output.
- `\set VERBOSITY terse` at the top, so expected output does not carry line numbers or contexts that
  vary by major.
- Keys from the `00..1f` pattern or the spec vectors, bound through `\set`; never a real key.
- A non-UTF-8 case creates its own database (`CREATE DATABASE ... ENCODING 'EUC_KR' LC_COLLATE 'C'
  LC_CTYPE 'C' TEMPLATE template0`) and connects with `\c`. Three things the recipe needs, or it fails:
  - `SET client_encoding = 'UTF8';` straight after `\c`. `pg_regress` unsets `PGCLIENTENCODING`, so the
    new session's client encoding is the database's, and the file's UTF-8 `'홍길동'` is rejected as an
    invalid EUC_KR sequence.
  - `CREATE EXTENSION pg_gcm;` there — `--load-extension` covers only the database `pg_regress` made.
  - `\c` back and `DROP DATABASE` at the end; `pg_regress` does not clean up databases it did not make.
- Volatility, strictness and parallel safety are read from `pg_proc` (`provolatile`, `proisstrict`,
  `proparallel`, `procost`), never from `\df+`: its columns differ on 15, 16–17 and 18, and it prints
  the owner.
- Forcing a parallel plan: set `parallel_setup_cost = 0`, `parallel_tuple_cost = 0`,
  `min_parallel_table_scan_size = 0` and `max_parallel_workers_per_gather = 2`, which are spelt the
  same on every major. Not `debug_parallel_query`: it is `force_parallel_mode` on 15, and a test may
  not branch on the version. Assert the plan shape in the same file (`EXPLAIN (COSTS OFF)`) so a
  serial plan fails the test instead of passing vacuously.
- The `vectors` file reads `spec/test-vectors.json` (`\set` from a backquoted `cat`, then
  `jsonb_array_elements`) and asserts per `testing.md`: the plaintext where it is UTF-8, the
  invalid-UTF-8 error where it is not.
- Where output legitimately differs by major, use an alternative expected file
  (`name_1.out`), never a branch in the test.

## Running
- `scripts/verify.sh <major>` builds, installs into `postgres:<major>`, runs `make installcheck`, and
  prints `regression.diffs` on failure.
- Re-record only with `PG_GCM_RECORD=1 scripts/verify.sh <major>`, which copies `results/` over
  `test/expected/`. Every changed line is explained in the PR.

## Must always exist
`korean_like` (`LIKE '%길%'` on a decrypted value), `strict_on_off`, `min_key_bytes`, `null_args`,
`aad_forms`, `encoding_euc_kr`, `invalid_text` (non-UTF-8 and U+0000 plaintexts, no bytes in the
message), `parallel_strict`, `volatility` (from `pg_proc`), `vectors`, and — from Phase 3 — the
mysql-gcm envelope fixture opened by `gcm_decrypt`.
