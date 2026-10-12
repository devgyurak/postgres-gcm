#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Install the build into the development server, run the regression suite, then the checks of
# scripts/verify.sql with the library loaded lazily and preloaded.
# Usage: scripts/verify.sh <major>
#   Needs scripts/build-in-docker.sh <major> and scripts/dev-up.sh <major> to have run.
#   PG_GCM_RECORD=1 copies the regression results over test/expected/ and stops there: read the
#   diff, explain every line in the PR, and run again without it.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -eq 1 ] || die "usage: scripts/verify.sh <major>"
major="$1"
name="$(dev_container_name "$major")"
preload_name="$name-preload"

[ -f "$ROOT/build/$major/pg_gcm.so" ] ||
  die "build/$major/pg_gcm.so is missing — run scripts/build-in-docker.sh $major"
# A pass on a binary older than the sources is not a pass.
[ "$(cat "$ROOT/build/$major/SOURCE_HASH" 2>/dev/null)" = "$(source_hash)" ] ||
  die "build/$major was not built from the current sources — run scripts/build-in-docker.sh $major"
[ "$(docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null)" = "true" ] ||
  die "$name is not running — run scripts/dev-up.sh $major"

cleanup() {
  docker rm --force "$preload_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

install_extension "$name" "$major"

# --- 1. make installcheck, in the build image, against the server over the shared network -------
regress_out="$ROOT/build/$major/regress"
rm -rf "$regress_out"
mkdir -p "$regress_out"
echo "== make installcheck (PostgreSQL $major)"
regress_status=0
PGPASSWORD="$(docker exec "$name" printenv POSTGRES_PASSWORD)" \
  docker run --rm \
  --user "$(id -u):$(id -g)" \
  --network "$DEV_NETWORK" \
  --env PGHOST="$name" --env PGPORT=5432 --env PGUSER=postgres --env PGPASSWORD \
  --env PG_GCM_RECORD="${PG_GCM_RECORD:-0}" \
  --volume "$ROOT:/src:ro" \
  --volume "$regress_out:/out" \
  "$(build_image_tag "$major")" \
  bash -euo pipefail -c '
    work="$(mktemp -d)"
    # spec/ too: the tests read spec/test-vectors.json from the directory make runs in.
    cp -r /src/Makefile /src/pg_gcm.control /src/src /src/sql /src/test /src/spec "$work/"
    cd "$work"
    if [ "$PG_GCM_RECORD" = "1" ]; then
      # pg_regress stops at the first test that has no expected file; give new tests an empty one.
      mkdir -p test/expected
      for t in test/sql/*.sql; do
        touch "test/expected/$(basename "$t" .sql).out"
      done
    fi
    status=0
    make USE_PGXS=1 installcheck || status=$?
    cp -r results /out/ 2>/dev/null || true
    cp regression.diffs regression.out /out/ 2>/dev/null || true
    exit "$status"
  ' || regress_status=$?

# A suite that ran nothing is the same failure as one that failed: every test file must have
# produced a result, the Korean LIKE case among them.
tests_written="$(find "$ROOT/test/sql" -name '*.sql' | wc -l | tr -d ' ')"
tests_run="$(find "$regress_out/results" -name '*.out' 2>/dev/null | wc -l | tr -d ' ')"
if [ "$tests_written" -eq 0 ] || [ "$tests_run" -ne "$tests_written" ]; then
  die "pg_regress produced $tests_run result(s) for $tests_written test file(s) on PostgreSQL $major"
fi
[ -f "$regress_out/results/korean_like.out" ] || die "the korean_like regression test did not run"

if [ "${PG_GCM_RECORD:-0}" = "1" ]; then
  cp "$regress_out"/results/*.out "$ROOT/test/expected/"
  echo "recorded: test/expected/ now holds this run's results on PostgreSQL $major."
  echo "Nothing was verified. Read the diff, then run scripts/verify.sh $major again without PG_GCM_RECORD."
  exit 0
fi
if [ "$regress_status" -ne 0 ]; then
  cat "$regress_out/regression.diffs" 2>/dev/null || true
  die "make installcheck failed on PostgreSQL $major"
fi

# --- 2. scripts/verify.sql ----------------------------------------------------------------------
# The known answers come from spec/test-vectors.json: the nonce the pattern key derives for
# 홍길동, and an envelope whose authenticated plaintext is not text, with its (public) key.
det_nonce="$(vector_field det-256-korean nonce_hex)"
not_text_envelope="$(vector_field random-256-contains-nul envelope_hex)"
not_text_key="$(vector_field random-256-contains-nul key_hex)"

# run_sql <container> <mode> <probe> [database]
run_sql() {
  docker exec --interactive --env PGCLIENTENCODING=UTF8 "$1" \
    psql --no-psqlrc --quiet --username postgres --dbname "${4:-postgres}" \
    --set mode="$2" --set probe="$3" --set det_nonce="$det_nonce" \
    --set not_text_envelope="$not_text_envelope" --set not_text_key="$not_text_key" \
    <"$ROOT/scripts/verify.sql"
}

failed=0
# check_rows <label> <output> <sentinel>
check_rows() {
  printf '%s\n' "$2"
  case "$2" in
    *'| FAIL'*)
      echo "FAIL: $1 has failing rows" >&2
      failed=1
      ;;
  esac
  case "$2" in
    *"END | "*" | $3 | "*) ;;
    *)
      echo "FAIL: $1 did not run to its end" >&2
      failed=1
      ;;
  esac
}

# nonce_of <probe output> — the first random nonce a backend reported.
nonce_of() {
  printf '%s\n' "$1" | awk -F' [|] ' '/first random nonce/ {print $4}'
}

# verify_mode <container> <mode>
verify_mode() {
  local container="$1" mode="$2" full probe_a probe_b nonce_a nonce_b
  echo "== scripts/verify.sql, $mode (PostgreSQL $major)"
  full="$(run_sql "$container" "$mode" 0)" || {
    printf '%s\n' "$full"
    die "verify.sql failed ($mode)"
  }
  check_rows "$mode" "$full" full

  # Step 5: two separate backends, each starting cold.
  probe_a="$(run_sql "$container" "$mode" 1 pg_gcm_verify)" || {
    printf '%s\n' "$probe_a"
    die "probe failed ($mode)"
  }
  probe_b="$(run_sql "$container" "$mode" 1 pg_gcm_verify)" || {
    printf '%s\n' "$probe_b"
    die "probe failed ($mode)"
  }
  check_rows "$mode, backend A" "$probe_a" probe
  check_rows "$mode, backend B" "$probe_b" probe
  nonce_a="$(nonce_of "$probe_a")"
  nonce_b="$(nonce_of "$probe_b")"
  if [ "${#nonce_a}" -eq 24 ] && [ "${#nonce_b}" -eq 24 ] && [ "$nonce_a" != "$nonce_b" ]; then
    echo "S5 | $mode | the two backends' first random nonces differ | $nonce_a, $nonce_b | ok"
  else
    echo "S5 | $mode | the two backends' first random nonces differ | $nonce_a, $nonce_b | FAIL"
    failed=1
  fi
}

verify_mode "$name" lazy

"$ROOT/scripts/dev-up.sh" "$major" --preload >/dev/null
verify_mode "$preload_name" preload

[ "$failed" -eq 0 ] || die "the checks of scripts/verify.sql failed on PostgreSQL $major"
echo "== PostgreSQL $major: regression and scripts/verify.sql passed"
