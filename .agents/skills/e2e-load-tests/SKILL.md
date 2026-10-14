---
name: e2e-load-tests
description: The compose-based end-to-end suite (primary, streaming replica and a Python SQL runner), the load harness that gates decrypt + LIKE p95 against pgcrypto, and the core micro-benchmarks gated against bare OpenSSL EVP. Use it for replication and performance gates.
---

# e2e-load-tests

Rules: `testing.md`, `stack-python.md`.

## E2E (`tests/e2e`)
- Run: `scripts/build-in-docker.sh <major>`, then `scripts/e2e.sh <major>` (Docker Compose v2.20
  or later; the script refuses an older one). The script takes the
  image from `docker/versions.json`, generates the two passwords of the run, and runs
  `docker compose ... up --exit-code-from runner`; `compose.yml` refuses to start without what it sets.
- `compose.yml`: `primary` and `replica` are the official image with `node.sh` as entrypoint, which
  installs the build mounted at `/pg_gcm-build` where `pg_config` says the server looks, and then
  hands over to the image's own entrypoint. The replica first takes a `pg_basebackup` of the primary
  (`--write-recovery-conf`); `primary-init.sh` creates the role it connects as and the `pg_hba.conf`
  line. `runner` is `runner.Dockerfile` (Python, `psycopg`), built from `tests/e2e/` alone.
- Both servers run with `log_parameter_max_length=0` (docs/ops-constraints.md item 1), on a tmpfs, with health
  checks. `scripts/e2e.sh` removes the containers, the network and the runner image at the end. The
  replication password is in the replica's `postgresql.auto.conf` on that tmpfs while the run lasts.
- `run.py` (argparse; JSON on stdout, one line per scenario on stderr, the gate in the exit status:
  0 only when every scenario unittest ran was recorded as passed, one ran at least, and both nodes
  ran the same shared scenarios; `run.py --self-test` checks that gate without a server and runs
  in the lint workflow) runs `scenarios.py` (stdlib `unittest`, one
  dependency: `psycopg`). The runner only issues SQL with keys as bind parameters. Scenarios, each
  GWT in its name and body:
  1. the replica is in recovery, streams from the primary, refuses a write, and has the catalog
     entry of an extension created on the primary;
  2. round trip (both forms) and Korean `LIKE`, on the primary and on the replica, which never
     encrypted the rows;
  3. deterministic values sealed on the primary are equal on either node for equal key, plaintext
     and AAD, differ for another AAD, and join with no key in the query;
  4. a forged tag is an error with strict on and NULL with it off, on both nodes;
  5. a NULL in each argument position gives NULL.
- A scenario that holds on both nodes goes in `OnEitherNode` and runs through `OnThePrimary` and
  `OnTheReplica`; no test body loops over nodes. New shared state goes in `set_up_cluster`, which
  ends by waiting for the replica to replay it and for its WAL receiver to report `streaming`. A
  change to the gate (`gate`, `same_scenarios`) comes with a case in `self_test` that it must refuse.
  The runner's connections time out after ten seconds (`PGCONNECT_TIMEOUT` in `compose.yml`).
- Lint: `ruff`, `mypy --strict` (the lint workflow installs `tests/e2e/requirements.txt` for
  psycopg's types) and `shellcheck` cover `tests/e2e/`.

## Load (`tests/load`)
- `run.py --rows N --baseline pgcrypto`: loads N rows of Korean names sealed by `gcm_encrypt` and by
  `pgcrypto` `encrypt_iv(..., 'aes-cbc')`, then measures p95 of `gcm_decrypt(...) LIKE '%김%'` against
  `convert_from(decrypt_iv(...), 'UTF8') LIKE '%김%'` at 1/8/32 sessions in an interleaved order.
  `--rows`, `--sessions` and `--samples` (scans per query per cell) default to
  `tests/load/baseline.json`; the whole rows × sessions matrix of those defaults runs, and the gate is
  the worst ratio over the `gated_sessions` cells. A cell at many sessions on few rows is
  scheduling-bound, not crypto-bound, and is recorded but not gated (see the baseline's `note`).
- The two plans must have the same shape: `connect()` sets `SET jit = off` and `SET
  max_parallel_workers_per_gather = 0` (as Phase S does), `load_rows` follows the load with `VACUUM
  (ANALYZE, FREEZE)`, and one warm-up scan of each query is discarded before the timed rounds.
  Without the parallel setting, `gcm_decrypt`'s `COST 50` earns it a gather that `decrypt_iv`'s
  `COST 1` does not, and the ratio flatters GCM.
- The gate is a ratio, never milliseconds, recorded in `docs/perf.md` with the runner's CPU from three
  CI runs; `max_ratio` is then set to the worst observed gated ratio times 1.2, rounded up to one
  decimal, never above the 1.0 the design requires. `PG_GCM_LOAD_JSON` names a host path for the
  runner's JSON of every cell, which the workflow uploads as an artifact.

## Bench (`tests/bench`)
- `scripts/bench.sh <major>` builds `benchmark.cc` (Google Benchmark) in the build image and runs it:
  the core's `gcm_seal` (random and deterministic) and `gcm_open` against a hand-rolled EVP
  AES-256-GCM of the same shape, per plaintext size. Each benchmark runs five times
  (`->Repetitions(5)`) in a random order (`--benchmark_enable_random_interleaving`, set by
  `bench.sh`) and the gate reads the median, so both sides of a ratio meet the same load and one
  noisy repetition cannot move it. The exit status is the gate — 0 only when every ratio is at or
  under its ceiling in `tests/bench/baseline.json`; the binary's `--self-test` checks the verdict,
  the ratio's direction and the gate over a fixed measurement map (each of the three ratio pairs
  gets a failing case, and a high det-over-random does not fail the gate), with no crypto.
- The three gated ratios are like for like: the random seal and the open over bare EVP, and the
  deterministic seal over a **bare deterministic seal** — a hand-rolled EVP seal with the same
  HMAC-SHA256 nonce derivation (spec 1.8) — so both sides of `det` pay the same two HMAC-SHA256
  passes and the same AES-GCM. The deterministic seal over the random one is recorded, never gated:
  it compares a SHA-256-bound seal with an AES-bound one and moves with a runner's relative AES-GCM
  and SHA-256 throughput (an O17 probe found 3.3–9.6 at 65536 bytes). The bare random baseline draws
  a random nonce, as the core's random seal does, so the `seal` ratio charges the core for its own
  envelope and checks, not for a draw only one side pays. The ceilings are per size (`seal`, `open`,
  `det`), because the core's fixed per-call cost is a larger share of a small message; the gate is a
  ratio, never nanoseconds, and the ceilings are a placeholder (`docs/design.md` §8 O17) until three
  runs set them. Set each to the worst observed value across three `bench` runs times 1.2, rounded up
  to one decimal, never above the placeholder, and record it in `docs/perf.md`. No server and no
  PostgreSQL header is involved. `PG_GCM_BENCH_JSON` names a host path for the JSON of ratios and raw
  medians, which the workflow uploads as an artifact.
