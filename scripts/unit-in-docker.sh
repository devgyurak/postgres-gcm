#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Run the unit suite inside the build image for one major: GCC, and the libcrypto the server
# of that image links. The CI compiler is GCC, so run this as well as the local build on macOS.
# Usage: scripts/unit-in-docker.sh <major>
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -eq 1 ] || die "usage: scripts/unit-in-docker.sh <major>"
major="$1"

ensure_build_image "$major"

# SYS_PTRACE: LeakSanitizer needs it to scan the process at exit.
docker run --rm \
  --cap-add SYS_PTRACE \
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
    quietly cmake -S /src/tests/unit -B "$build" -DCMAKE_BUILD_TYPE=Debug
    quietly cmake --build "$build" -j "$(nproc)"
    openssl version
    "$build/pg_gcm_unit" --gtest_filter="*AllocatesLessThanTheSweepCovers*" | grep "counted"
    ctest --test-dir "$build" --output-on-failure -j "$(nproc)" >"$build/ctest.log" 2>&1 ||
      { cat "$build/ctest.log"; exit 1; }
    tail -3 "$build/ctest.log"
    # A gate that ran nothing is the same failure as one that failed.
    count="$(ctest --test-dir "$build" -N | awk "/Total Tests:/ {print \$3}")"
    [ "${count:-0}" -gt 0 ] || { echo "error: no unit tests were found" >&2; exit 1; }
  '
