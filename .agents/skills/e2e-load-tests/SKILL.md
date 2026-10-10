---
name: e2e-load-tests
description: The compose-based end-to-end suite (primary, streaming replica, a mysql-gcm server and a Python SQL runner) and the load harness that gates decrypt + LIKE p95 against pgcrypto. Use it for replication, cross-database envelope exchange, and performance gates.
---

# e2e-load-tests

Rules: `testing.md`, `stack-python.md`.

## E2E (`tests/e2e`)
- `compose.yml`: `primary` (`postgres:<major>` + the extension, `wal_level=replica`), `replica`
  (`pg_basebackup` streaming standby, extension files installed), `mysql` (`mysql:8.4` + mysql-gcm's
  released component), `runner` (Python, `psycopg` and `PyMySQL`).
- The runner only issues SQL with keys as bind parameters. Scenarios, each GWT:
  1. round trip and Korean `LIKE` on the primary;
  2. the replica decrypts rows it never encrypted;
  3. MySQL seals with `gcm_encrypt` and `gcm_encrypt_det`, PostgreSQL opens them, and the reverse;
  4. deterministic values sealed on both sides are equal for equal key, plaintext and AAD;
  5. strict on/off agree across the two on a forged tag;
  6. a NULL in each argument position gives NULL on both.
- `docker compose -f tests/e2e/compose.yml up --exit-code-from runner`.

## Load (`tests/load`)
- `run.py --rows N --baseline pgcrypto`: loads N rows of Korean names sealed by `gcm_encrypt` and by
  `pgcrypto` `encrypt_iv(..., 'aes-cbc')`, then measures p95 of `gcm_decrypt(...) LIKE '%김%'` against
  `convert_from(decrypt_iv(...), 'UTF8') LIKE '%김%'` at 1/8/32 sessions in an interleaved order.
- The gate is a ratio, never milliseconds, written to `tests/load/baseline.json` from three CI runs and
  recorded in `docs/perf.md` with the runner's CPU.
