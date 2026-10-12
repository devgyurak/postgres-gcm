#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Phase S measurements for one major (docs/design.md §4 step 7; §8 O6, O8, O12): builds the
# measurement probe, starts a throwaway server, and runs scripts/spike/measure.sql in it.
# Usage: scripts/spike/measure.sh <major>     (needs scripts/build-in-docker.sh <major> first)
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/../lib.sh"

[ $# -eq 1 ] || die "usage: scripts/spike/measure.sh <major>"
major="$1"
ref="$(image_ref "$major")"
name="pg-gcm-spike-$major"
out="$ROOT/build/$major/spike"

# Never leave the throwaway server behind, however the script ends.
cleanup() {
  docker rm --force "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ensure_build_image "$major"
rm -rf "$out"
mkdir -p "$out"
docker run --rm --user "$(id -u):$(id -g)" \
  --volume "$ROOT/scripts/spike/pg_gcm_probe:/src:ro" --volume "$out:/out" \
  "$(build_image_tag "$major")" \
  bash -euo pipefail -c '
    work="$(mktemp -d)"
    cp /src/* "$work/"
    make -C "$work" USE_PGXS=1 >/dev/null
    cp "$work/pg_gcm_probe.so" "$work/pg_gcm_probe.control" "$work"/pg_gcm_probe--*.sql /out/
  '

pkglibdir="$(docker run --rm --entrypoint pg_config "$ref" --pkglibdir)"
sharedir="$(docker run --rm --entrypoint pg_config "$ref" --sharedir)"

# start_server <extra postgres arguments...>
start_server() {
  docker rm --force "$name" >/dev/null 2>&1 || true
  POSTGRES_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(16))')" \
    docker create --name "$name" --env POSTGRES_PASSWORD \
    --tmpfs "$(data_mount "$major")" \
    --health-cmd 'pg_isready -h 127.0.0.1 -U postgres' \
    --health-interval 1s --health-timeout 3s --health-retries 120 \
    "$ref" "$@" >/dev/null
  install_extension "$name" "$major"
  docker cp --quiet "$out/pg_gcm_probe.so" "$name:$pkglibdir/pg_gcm_probe.so"
  docker cp --quiet "$out/pg_gcm_probe.control" "$name:$sharedir/extension/pg_gcm_probe.control"
  docker cp --quiet "$out/pg_gcm_probe--1.0.sql" "$name:$sharedir/extension/pg_gcm_probe--1.0.sql"
  docker start "$name" >/dev/null
  wait_healthy "$name"
}

psql_in() {
  docker exec --interactive --env PGCLIENTENCODING=UTF8 "$name" \
    psql --no-psqlrc --quiet --username postgres --dbname postgres "$@"
}

echo "== O8, preloaded (PostgreSQL $major)"
start_server -c shared_preload_libraries=pg_gcm_probe
psql_in --tuples-only --no-align \
  --command 'CREATE EXTENSION pg_gcm_probe' \
  --command "SELECT 'O8 | CRYPTO_set_mem_functions at library load | ' || probe_set_mem_functions()"
docker logs "$name" 2>&1 | grep 'pg_gcm_probe:' | sort -u

echo "== measurements, library loaded on first call (PostgreSQL $major)"
start_server
psql_in <"$ROOT/scripts/spike/measure.sql" | tee "$out/measure.txt"
docker logs "$name" 2>&1 | grep 'pg_gcm_probe:' | sort -u
