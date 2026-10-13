#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Shared helpers for the development scripts. Sourced, never executed.
# shellcheck shell=bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
# shellcheck disable=SC2034  # used by the scripts that source this file
readonly DEV_NETWORK="pg-gcm-dev"

die() {
  echo "error: $*" >&2
  exit 1
}

# image_ref <major> — the digest-pinned image reference from docker/versions.json.
image_ref() {
  python3 - "$ROOT/docker/versions.json" "$1" <<'PY'
import json
import sys

path, major = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    versions = json.load(f)
# "supported" are the majors; "prerelease" a major not yet released; "openssl-floor" a supported
# major on an image whose server links the oldest OpenSSL in scope (3.0).
images = {name: entry for group in versions.values() for name, entry in group.items()}
if major not in images:
    sys.exit(f"error: {major} is not in docker/versions.json (known: {', '.join(sorted(images))})")
print(f"{images[major]['image']}@{images[major]['digest']}")
PY
}

# source_hash — a digest of everything a build is made from. scripts/build-in-docker.sh stores it
# beside the build and scripts/verify.sh refuses a build whose sources have changed since.
source_hash() {
  python3 - "$ROOT" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
files = [root / "Makefile", root / "pg_gcm.control"]
for directory in ("src", "sql"):
    files += sorted(p for p in (root / directory).rglob("*") if p.suffix in {".c", ".h", ".sql"})
digest = hashlib.sha256()
for path in files:
    digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes() + b"\0")
print(digest.hexdigest())
PY
}

# vector_field <id> <member> — one member of one vector of spec/test-vectors.json, so that a
# script compares against the file and never against a value copied out of it.
vector_field() {
  python3 - "$ROOT/spec/test-vectors.json" "$1" "$2" <<'PY'
import json
import sys

path, vector_id, member = sys.argv[1:]
with open(path, encoding="utf-8") as f:
    found = [v for v in json.load(f)["vectors"] if v["id"] == vector_id]
if len(found) != 1 or member not in found[0]:
    sys.exit(f"error: spec/test-vectors.json has no vector {vector_id} with a member {member}")
print(found[0][member])
PY
}

# extension_version [control file] — the extension's version, read from a control file (the
# source one by default, the built copy when one is given). Nothing copies the version out.
extension_version() {
  awk -F"'" '/^default_version/ {print $2}' "${1:-$ROOT/pg_gcm.control}"
}

build_image_tag() {
  echo "pg-gcm-build:$1"
}

dev_container_name() {
  echo "pg-gcm-dev-$1"
}

# data_mount <major> — where the official image keeps its data (it moved in 18).
# A name such as 17-bookworm is the major 17.
data_mount() {
  if [ "${1%%-*}" -ge 18 ]; then
    echo "/var/lib/postgresql"
  else
    echo "/var/lib/postgresql/data"
  fi
}

# ensure_build_image <major> — build docker/build.Dockerfile for that major if needed.
ensure_build_image() {
  local major="$1" ref
  ref="$(image_ref "$major")"
  docker build --quiet --file "$ROOT/docker/build.Dockerfile" --build-arg "BASE=$ref" \
    --tag "$(build_image_tag "$major")" "$ROOT/docker" >/dev/null
}

# install_extension <container> <major> — copy the build into the server container. Works on a
# container that is created but not started, which is what a preloading server needs.
# `make install` in the build container would install into that container, where no server looks.
install_extension() {
  local container="$1" major="$2" ref pkglibdir sharedir build="$ROOT/build/$2"
  [ -f "$build/pg_gcm.so" ] || die "build/$major/pg_gcm.so is missing — run scripts/build-in-docker.sh $major"
  ref="$(image_ref "$major")"
  pkglibdir="$(docker run --rm --entrypoint pg_config "$ref" --pkglibdir)"
  sharedir="$(docker run --rm --entrypoint pg_config "$ref" --sharedir)"
  docker cp --quiet "$build/pg_gcm.so" "$container:$pkglibdir/pg_gcm.so"
  docker cp --quiet "$build/pg_gcm.control" "$container:$sharedir/extension/pg_gcm.control"
  local script
  for script in "$build"/sql/*.sql; do
    docker cp --quiet "$script" "$container:$sharedir/extension/$(basename "$script")"
  done
}

# wait_healthy <container> — wait on the container's pg_isready health check.
wait_healthy() {
  local container="$1" status
  while :; do
    status="$(docker inspect --format '{{.State.Status}}/{{.State.Health.Status}}' "$container")"
    case "$status" in
      running/healthy) return 0 ;;
      running/starting) sleep 0.5 ;;
      *)
        docker logs --tail 30 "$container" >&2
        die "$container did not become healthy ($status)"
        ;;
    esac
  done
}
