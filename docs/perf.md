# Performance and the load baseline

This document records what `pg_gcm` costs and the two gates that watch it. Every number comes
from a command in this repository; a claim without one is not a fact (`docs/design.md` §8).

## What the gates are

Two, one at the code level and one at scale, and both are **ratios**, never a number of
milliseconds, so they mean the same on a laptop and on a shared CI runner. The micro-benchmarks
compare like for like — each ratio is the core over a bare EVP operation of the same shape — and
the load gate compares the same query shape over two ciphers.

| Gate | Harness | Metric | Ceiling |
|---|---|---|---|
| Core micro-benchmarks | `tests/bench` — `scripts/bench.sh <major>` | CPU time of the core's seal, open and deterministic seal over a bare EVP operation of the same shape | `tests/bench/baseline.json` |
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

The gate is the worst ratio over the gated (low-concurrency) cells, and the exit status closes it:
0 only when every gated cell ran and the worst ratio was at or under `max_ratio`. `gated_sessions`
in the baseline names them (1 and 8 by default); a higher-session cell is still measured and
reported but not gated, because at 10k rows a whole scan is a few milliseconds and under 32
concurrent sessions the p95 is scheduling tail rather than crypto — local runs of the 10k × 32
cell ran 0.77–1.03 whatever the code did. In CI it is the `load` workflow, on the nightly schedule
and on demand — never on a pull request, because it wants a quiet machine.

### Recorded

Phase S measured the same query shape over 300k rows in one backend: the GCM query took
**0.49–0.63** of the pgcrypto CBC one (`docs/design.md` §8, step 7). With the plan shapes matched
as in Phase S (no parallel workers, `VACUUM`, a discarded warm-up), a local measurement of the
gated cells runs in the same neighbourhood. Three runs of the `load` workflow from the default
branch `main` on 2026-10-14 — `38518507148`, `38518993036` and `38519339009` — passed every gated
cell of the 9-cell matrix on both images, and the worst gated ratio over the six jobs was **0.860**
(10k rows × 8 sessions, the `18` image of `38519339009`). Times 1.2 that is 1.032, rounded up to
1.1, which is above the design's requirement that GCM not be slower than the `pgcrypto` scan it
replaces, so `tests/load/baseline.json` keeps `max_ratio` at **1.0**. A refresh sets the ceiling
the same way — the worst observed gated ratio across the three times 1.2, rounded up to one decimal
— and never above 1.0: the ceiling is only ever lowered.

| Run | Image | Runner CPU (4 vCPU) | worst gated gcm/pgcrypto p95 | When |
|---|---|---|---|---|
| `38518507148` | 17-bookworm (OpenSSL 3.0.22) | AMD EPYC 7763 64-Core | 0.845 | 2026-10-14 |
| `38518507148` | 18 (OpenSSL 3.5.7) | Intel Xeon Platinum 8573C | 0.839 | 2026-10-14 |
| `38518993036` | 17-bookworm (OpenSSL 3.0.22) | AMD EPYC 9V74 80-Core | 0.845 | 2026-10-14 |
| `38518993036` | 18 (OpenSSL 3.5.7) | AMD EPYC 9V45 96-Core | 0.849 | 2026-10-14 |
| `38519339009` | 17-bookworm (OpenSSL 3.0.22) | AMD EPYC 9V74 80-Core | 0.840 | 2026-10-14 |
| `38519339009` | 18 (OpenSSL 3.5.7) | AMD EPYC 9V45 96-Core | 0.860 | 2026-10-14 |

Each row is the worst gated (1- and 8-session) cell of that job, over the rows 10k, 100k and 300k
and both gated session counts together; the recorded 32-session cells ran 0.86–0.91 and are not
gated.

## The core micro-benchmarks

`tests/bench/benchmark.cc` (Google Benchmark) measures the core's `gcm_seal` (random and
deterministic) and `gcm_open` against a hand-rolled EVP AES-256-GCM of the same shape, per
plaintext size, and gates three like-for-like ratios against `tests/bench/baseline.json`: the
random seal and the open over bare EVP at the same size, and the deterministic seal over a bare
deterministic seal — a hand-rolled EVP seal with the same HMAC-SHA256 nonce derivation (spec 1.8)
— so both sides of `det` pay the same two HMAC-SHA256 passes and the same AES-GCM (`docs/design.md`
§8, O15). The deterministic seal over the random one is **recorded, never gated**: it compares a
SHA-256-bound seal with an AES-bound one, and an O17 probe found it ranging from about 1.2 to 9.6
across sizes (about 3.3 to 9.6 at 65536 bytes), because the two operations scale differently across
runner CPU and libcrypto — the fastest 65536-byte AES-GCM cells were about five times the slowest —
so it is not a property of this code.
`scripts/bench.sh <major>` builds and runs it in the build image; the `bench` workflow runs it
on a merge and nightly, one image per libcrypto. Each benchmark runs five times
(`->Repetitions(5)`) and the gate reads the median, so one noisy repetition cannot move a ratio —
a single sample per cell let either side swing about 2x on a busy host. The repetitions run in a
random order (`--benchmark_enable_random_interleaving`), so both sides of a ratio meet the same
load rather than one side a quiet moment and the other a busy one. The bare random baseline draws
its nonce with `RAND_bytes`, exactly as the core's random seal does, so the seal ratio charges the
core for its own envelope and checks rather than for a draw only one side pays — a fixed-nonce
baseline made the seal ratio noisy at the smallest sizes. The ceilings are per size
(`seal`, `open`, `det`), because the core's fixed per-call cost is a larger share of a small
message, and they are set from the three `main` runs recorded below: **1.3** at every size and
ratio except the 256-byte seal, which is **1.4**. The binary writes the ratios and the raw medians
to JSON (`PG_GCM_BENCH_JSON`), which the workflow uploads as an artifact.

### Recorded

Three runs of the `bench` workflow from `main` on 2026-10-14 — `38518367089` (the push that
promoted the branch), `38518733427` and `38518740737` — passed, both images (`18` with OpenSSL
3.5.7 and `17-bookworm` with 3.0.22) in each, on four runner models, every one of them 4 vCPU: AMD
EPYC 7763, AMD EPYC 9V45, AMD EPYC 9V74 and Intel Xeon Platinum 8573C. The worst observed ratio
per size over the six jobs, the recorded `det`/random spread, and the ceiling the rule gives each
gated ratio (worst × 1.2, rounded up to one decimal, never above the placeholder it replaced):

| Size | worst seal | worst open | worst det | det/random (recorded) | ceiling (seal / open / det) |
|---|---|---|---|---|---|
| 16 B | 1.048 | 1.052 | 1.027 | 1.22–1.73 | 1.3 / 1.3 / 1.3 |
| 256 B | 1.090 | 1.036 | 1.027 | 1.26–1.74 | 1.4 / 1.3 / 1.3 |
| 4096 B | 1.024 | 1.019 | 1.012 | 2.12–2.57 | 1.3 / 1.3 / 1.3 |
| 65536 B | 1.011 | 1.005 | 1.005 | 3.34–4.06 | 1.3 / 1.3 / 1.3 |

The first three columns are the ratios the gate closes on; `det`/random is recorded, never gated,
and its range is the spread over the six jobs — the same figure the probe above bounded at about
1.2–9.6. Each run's per-size ratios and raw medians are the workflow's artifact, and the runner's
CPU is beside them in the job summary.

## What this does not measure

- A database that is not UTF-8: every call looks its conversion up in `pg_catalog` and calls it
  through the function manager, and that cost is not measured before this gate
  (`docs/design.md` §8).
- The `PG_TRY` block's cost: it is at the noise floor (§8, O12). It does not change a gate.
- The `det` gate's own slack. A cost shared by both sides of `det` is invisible to it and shows only
  in the recorded `det`/random ratio: the per-call resolution of the digest by name
  (`docs/design.md` §8, O15) is on both sides, so it — and any saving a prepared context would give
  — moves the record, not the gate. A per-call fixed cost added to the core's det path alone moves
  the gate ratio, but not past its ceiling: a temporary patch to the core on an arm64 host (not a
  command in this repository) put an extra `EVP_MAC_fetch` per call (about 100 ns) at a gate ratio
  of 1.03–1.11, under the 1.3 ceiling.
- arm64: CI compiles for it and does not run either gate there (§8). Both were quick on arm64 in the
  local runs the ceilings were first probed with, and the ceilings above come from x86 runners.
