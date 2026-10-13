#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Run the load harness (tests/load) for one image: a development server with the build
# installed, and a Python runner that reaches it over SQL alone. The runner's exit status is
# the gate: 0 only when every cell ran and the worst gcm/pgcrypto ratio was at or under the
# ceiling in tests/load/baseline.json.
# Usage: scripts/load.sh <major> [args for tests/load/run.py]
#   Needs scripts/build-in-docker.sh <major> to have run. Starts pg-gcm-dev-<major> if needed.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -ge 1 ] || die "usage: scripts/load.sh <major> [args for tests/load/run.py]"
major="$1"
shift

[ -f "$ROOT/build/$major/pg_gcm.so" ] ||
  die "build/$major/pg_gcm.so is missing — run scripts/build-in-docker.sh $major"
# A pass on a binary older than the sources is not a pass.
[ "$(cat "$ROOT/build/$major/SOURCE_HASH" 2>/dev/null)" = "$(source_hash)" ] ||
  die "build/$major was not built from the current sources — run scripts/build-in-docker.sh $major"

name="$(dev_container_name "$major")"
"$ROOT/scripts/dev-up.sh" "$major" >/dev/null
install_extension "$name" "$major"

image="pg-gcm-load:$major"
cleanup() {
  docker image rm --force "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== load harness (PostgreSQL $major)"
docker build --quiet --file "$ROOT/tests/load/runner.Dockerfile" --tag "$image" "$ROOT/tests/load" \
  >/dev/null

# The password is read from the container, never written to the repository or a command line.
docker run --rm \
  --network "$DEV_NETWORK" \
  --env PGHOST="$name" --env PGPORT=5432 --env PGUSER=postgres --env PGDATABASE=postgres \
  --env PGPASSWORD="$(docker exec "$name" printenv POSTGRES_PASSWORD)" \
  "$image" "$@"
echo "== PostgreSQL $major: the load gate passed"
