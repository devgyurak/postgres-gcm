#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Run the core micro-benchmarks (tests/bench) inside the build image for one major: the core's
# seal and open over bare OpenSSL EVP, gated as ratios by tests/bench/baseline.json. No server
# is needed, so this is like scripts/unit-in-docker.sh, not like scripts/verify.sh.
# Usage: scripts/bench.sh <major>
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -eq 1 ] || die "usage: scripts/bench.sh <major>"
major="$1"

ensure_build_image "$major"

# --benchmark_min_time is left at its default: a ratio gate is only as steady as the sample, and
# these are the numbers the ceiling was set from. PG_GCM_BENCH_MIN_TIME overrides it; its form is
# the benchmark library's — a bare number on 1.7 (the floor image), a suffixed one ("10s") on 1.9.
#
# --benchmark_enable_random_interleaving runs the repetitions of every benchmark in a random order
# instead of five in a row, so both sides of a ratio meet the same load rather than one side meeting
# a quiet moment and the other a busy one.
#
# PG_GCM_BENCH_JSON names a host path for the JSON of ratios and raw medians (benchmark.cc writes it
# when PG_GCM_BENCH_JSON is set): its directory is mounted into the container and the in-container
# path is passed instead, so the workflow can upload the file as an artifact.
bench_mount=(--volume "$ROOT:/src:ro")
bench_env=(--env PG_GCM_BENCH_MIN_TIME="${PG_GCM_BENCH_MIN_TIME:-}")
if [ -n "${PG_GCM_BENCH_JSON:-}" ]; then
  out_dir="$(cd "$(dirname "$PG_GCM_BENCH_JSON")" && pwd)"
  bench_mount+=(--volume "$out_dir:/out")
  bench_env+=(--env PG_GCM_BENCH_JSON="/out/$(basename "$PG_GCM_BENCH_JSON")")
fi

docker run --rm \
  "${bench_mount[@]}" \
  "${bench_env[@]}" \
  "$(build_image_tag "$major")" \
  bash -euo pipefail -c '
    build="$(mktemp -d)"
    # Quiet when it works; the whole log when it does not.
    quietly() {
      local log
      log="$(mktemp)"
      "$@" >"$log" 2>&1 || { cat "$log"; exit 1; }
    }
    quietly cmake -S /src/tests/bench -B "$build" -DCMAKE_BUILD_TYPE=Release
    quietly cmake --build "$build" -j "$(nproc)"
    openssl version
    # The gate against fixed ratios first, so a broken gate is seen before a slow run.
    "$build/pg_gcm_bench" --self-test
    # The exit status is the gate: 0 only when every ratio was at or under its ceiling.
    flags=(--benchmark_enable_random_interleaving=true)
    if [ -n "$PG_GCM_BENCH_MIN_TIME" ]; then
      "$build/pg_gcm_bench" "${flags[@]}" --benchmark_min_time="$PG_GCM_BENCH_MIN_TIME"
    else
      "$build/pg_gcm_bench" "${flags[@]}"
    fi
  '
echo "== PostgreSQL $major: the benchmark gate passed"
