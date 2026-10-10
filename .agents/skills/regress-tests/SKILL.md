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
  LC_CTYPE 'C' TEMPLATE template0`) and connects with `\c`.
- Where output legitimately differs by major, use an alternative expected file
  (`name_1.out`), never a branch in the test.

## Running
- `scripts/verify.sh <major>` builds, installs into `postgres:<major>`, runs `make installcheck`, and
  prints `regression.diffs` on failure.
- Re-record only with `PG_GCM_RECORD=1 scripts/verify.sh <major>`, which copies `results/` over
  `test/expected/`. Every changed line is explained in the PR.

## Must always exist
`korean_like` (`LIKE '%길%'` on a decrypted value), `strict_on_off`, `min_key_bytes`, `encoding_euc_kr`,
`parallel_strict`, `volatility` (`\df+ gcm_*`), `vectors`, and — from Phase 3 — the mysql-gcm envelope
fixture opened by `gcm_decrypt`.
