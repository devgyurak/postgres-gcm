#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Run the end-to-end suite for one image: a primary, a streaming replica and the SQL runner
# (tests/e2e/compose.yml). Exits 0 only when the runner did: every scenario ran and passed.
# Usage: scripts/e2e.sh <major>
#   Needs scripts/build-in-docker.sh <major> to have run.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -eq 1 ] || die "usage: scripts/e2e.sh <major>"
major="$1"

[ -f "$ROOT/build/$major/pg_gcm.so" ] ||
  die "build/$major/pg_gcm.so is missing — run scripts/build-in-docker.sh $major"
# A pass on a binary older than the sources is not a pass.
[ "$(cat "$ROOT/build/$major/SOURCE_HASH" 2>/dev/null)" = "$(source_hash)" ] ||
  die "build/$major was not built from the current sources — run scripts/build-in-docker.sh $major"

PG_GCM_E2E_IMAGE="$(image_ref "$major")"
PG_GCM_E2E_BUILD="$ROOT/build/$major"
PG_GCM_E2E_DATA_MOUNT="$(data_mount "$major")"
# Generated per run. They reach docker through the environment, are in the containers'
# environment while the run lasts, and the replication password is in the replica's
# postgresql.auto.conf on its tmpfs. Nothing of them is in the repository or in an image, and
# all of it goes with the containers at the end.
PG_GCM_E2E_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
PG_GCM_E2E_REPLICATION_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
export PG_GCM_E2E_IMAGE PG_GCM_E2E_BUILD PG_GCM_E2E_DATA_MOUNT
export PG_GCM_E2E_PASSWORD PG_GCM_E2E_REPLICATION_PASSWORD

compose() {
  docker compose --progress quiet --project-name "pg-gcm-e2e-$major" \
    --file "$ROOT/tests/e2e/compose.yml" "$@"
}
build_log="$(mktemp)"
# Containers, network and the runner image of this project name, whoever left them: a run
# that was killed must not block the next. A run of the same image still going is torn down
# by this, and fails.
cleanup() {
  compose down --volumes --remove-orphans --rmi local >/dev/null 2>&1 || true
  rm -f "$build_log"
}
trap cleanup EXIT
compose down --volumes --remove-orphans >/dev/null 2>&1 || true

echo "== end-to-end suite (PostgreSQL $major)"
# Quiet when it works; the whole log when it does not.
compose build runner >"$build_log" 2>&1 || {
  cat "$build_log" >&2
  die "the runner image did not build"
}
status=0
compose up --no-build --quiet-pull --attach runner --no-log-prefix --exit-code-from runner || status=$?
if [ "$status" -ne 0 ]; then
  # What the servers said, for a failure that is theirs and not a scenario's.
  compose logs --no-color --tail 40 primary replica >&2 || true
  die "the end-to-end suite failed on PostgreSQL $major"
fi
echo "== PostgreSQL $major: the end-to-end suite passed"
