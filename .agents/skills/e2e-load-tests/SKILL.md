---
name: e2e-load-tests
description: The compose-based end-to-end suite (primary, streaming replica and a Python SQL runner) and the load harness that gates decrypt + LIKE p95 against pgcrypto. Use it for replication and performance gates.
---

# e2e-load-tests

Rules: `testing.md`, `stack-python.md`.

## E2E (`tests/e2e`)
- `compose.yml`: `primary` (`postgres:<major>` + the extension, `wal_level=replica`), `replica`
  (`pg_basebackup` streaming standby, extension files installed), `runner` (Python, `psycopg`).
- The runner only issues SQL with keys as bind parameters. Scenarios, each GWT:
  1. round trip and Korean `LIKE` on the primary;
  2. the replica decrypts rows it never encrypted;
  3. deterministic values sealed on the primary are equal on the replica for equal key, plaintext and
     AAD, and join there;
  4. a forged tag is an error with strict on and NULL with it off, on the primary and the replica;
  5. a NULL in each argument position gives NULL.
- `docker compose -f tests/e2e/compose.yml up --exit-code-from runner`.

## Load (`tests/load`)
- `run.py --rows N --baseline pgcrypto`: loads N rows of Korean names sealed by `gcm_encrypt` and by
  `pgcrypto` `encrypt_iv(..., 'aes-cbc')`, then measures p95 of `gcm_decrypt(...) LIKE '%김%'` against
  `convert_from(decrypt_iv(...), 'UTF8') LIKE '%김%'` at 1/8/32 sessions in an interleaved order.
- The gate is a ratio, never milliseconds, written to `tests/load/baseline.json` from three CI runs and
  recorded in `docs/perf.md` with the runner's CPU.
