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
docker run --rm \
  --env PG_GCM_BENCH_MIN_TIME="${PG_GCM_BENCH_MIN_TIME:-}" \
  --volume "$ROOT:/src:ro" \
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
    if [ -n "$PG_GCM_BENCH_MIN_TIME" ]; then
      "$build/pg_gcm_bench" --benchmark_min_time="$PG_GCM_BENCH_MIN_TIME"
    else
      "$build/pg_gcm_bench"
    fi
  '
echo "== PostgreSQL $major: the benchmark gate passed"
