# Performance and the load baseline

This document records what `pg_gcm` costs and the two gates that watch it. Every number comes
from a command in this repository; a claim without one is not a fact (`docs/design.md` §8).

## What the gates are

Two, one at the code level and one at scale, and both are **ratios**, never a number of
milliseconds, so they mean the same on a laptop and on a shared CI runner.

| Gate | Harness | Metric | Ceiling |
|---|---|---|---|
| Core micro-benchmarks | `tests/bench` — `scripts/bench.sh <major>` | CPU time of the core's seal and open over bare OpenSSL EVP | `tests/bench/baseline.json` |
| Load | `tests/load` — `scripts/load.sh <major>` | p95 of the decrypt + `LIKE` scan against the same scan in `pgcrypto` AES-CBC | `tests/load/baseline.json` |

## The load gate

`tests/load/run.py` loads N rows of Korean names sealed twice in one table — by `gcm_encrypt`
(AES-256-GCM, random nonce) and by `pgcrypto` `encrypt_iv(..., 'aes-cbc')`, same key — then
times, interleaved so that neither query owns the machine and neither is measured only when the
caches are warm, the scan `gcm_decrypt(name_enc, $1) LIKE '%김%'` against
`convert_from(decrypt_iv(name_cbc, $1, $2, 'aes-cbc'), 'UTF8') LIKE '%김%'`, and reports the p95
of each and their ratio. `--rows`, `--sessions` and `--samples` default to
`tests/load/baseline.json` (`samples` is scans per query per cell). The key is the public `00..1f`
pattern and travels as a bind parameter (`docs/ops-constraints.md` item 1). As in the Phase S
measurement (`docs/design.md` §8): JIT is off; `max_parallel_workers_per_gather = 0`, so both
scans take the same serial plan shape — `gcm_decrypt`'s `COST 50` would otherwise earn it a
parallel gather at 100k rows that `decrypt_iv`'s `COST 1` does not, which flatters GCM; the table
is `VACUUM (ANALYZE, FREEZE)`d after loading; and one warm-up scan of each query is discarded
before the timed rounds.

The gate is the worst per-cell ratio over the matrix, and the exit status closes it: 0 only when
every cell ran and the worst ratio was at or under `max_ratio`. In CI it is the `load` workflow,
on the nightly schedule and on demand — never on a pull request, because it wants a quiet
machine.

### Recorded

Phase S measured the same query shape over 300k rows in one backend: the GCM query took
**0.49–0.63** of the pgcrypto CBC one (`docs/design.md` §8, step 7). With the plan shapes matched
as in Phase S (no parallel workers, `VACUUM`, a discarded warm-up), a local measurement of the
full matrix runs in the same neighbourhood, up to about 0.9 at 32 sessions, so
`tests/load/baseline.json` keeps `max_ratio` at **1.0** — the design's requirement that GCM not be
slower than the `pgcrypto` scan it replaces — rather than tightening it below the noise. The
ratios from the CI runner, with the runner's CPU, are to be recorded here from three runs, and the
ceiling lowered toward the observed worst only when it holds across all three.

| Runner CPU | Rows | Sessions | worst gcm/pgcrypto p95 | When |
|---|---|---|---|---|
| *(to be recorded from the `load` workflow)* | 10k, 100k, 300k | 1, 8, 32 | *(worst ratio)* | — |

## The core micro-benchmarks

`tests/bench/benchmark.cc` (Google Benchmark) measures the core's `gcm_seal` (random and
deterministic) and `gcm_open` against a hand-rolled EVP AES-256-GCM of the same shape, per
plaintext size, and gates three ratios against `tests/bench/baseline.json`: the random seal and
the open over bare EVP at the same size, and the deterministic seal over the random one — the
last is where the two HMAC-SHA256 passes for the nonce show (`docs/design.md` §8, O15).
`scripts/bench.sh <major>` builds and runs it in the build image; the `bench` workflow runs it
on a merge and nightly, one image per libcrypto. The bare baseline draws its nonce with
`RAND_bytes`, exactly as the core's random seal does, so the seal ratio charges the core for its
own envelope and checks rather than for a draw only one side pays — a fixed-nonce baseline made
the seal ratio noisy at the smallest sizes. The ceilings are per size (`seal`, `open`, `det`),
because the core's fixed per-call cost is a larger share of a small message; the placeholder
values run from `1.5/1.5/3.0` at 16 bytes down to `1.3/1.3/4.5` at 65536.

| Runner CPU | Size | seal | open | det | When |
|---|---|---|---|---|---|
| *(to be recorded from the `bench` workflow)* | 16, 256, 4096, 65536 | *(ratio)* | *(ratio)* | *(ratio)* | — |

## What this does not measure

- A database that is not UTF-8: every call looks its conversion up in `pg_catalog` and calls it
  through the function manager, and that cost is not measured before this gate
  (`docs/design.md` §8).
- The `PG_TRY` block's cost: it is at the noise floor (§8, O12). It does not change a gate.
- arm64: CI compiles for it and does not run either gate there (§8). Both were quick on arm64
  while the ceiling was set.
