#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Package one build into a release tarball: pg_gcm-<version>-pg<major>-<arch>.tar.gz, laid out
# so that extracting it gives a directory that `cp` can install from. Writes the tarball and
# its .sha256 next to it and prints both.
# Usage: scripts/package.sh <major> <arch> [outdir]
#   arch is amd64 or arm64 (the build's, from scripts/build-in-docker.sh on that machine).
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -ge 2 ] && [ $# -le 3 ] || die "usage: scripts/package.sh <major> <arch> [outdir]"
major="$1"
arch="$2"
out="${3:-$ROOT/dist}"
case "$arch" in
  amd64 | arm64) ;;
  *) die "arch must be amd64 or arm64, not '$arch'" ;;
esac

build="$ROOT/build/$major"
[ -f "$build/pg_gcm.so" ] || die "build/$major/pg_gcm.so is missing — run scripts/build-in-docker.sh $major"
# A package on a binary older than the sources is not a package of these sources.
[ "$(cat "$build/SOURCE_HASH" 2>/dev/null)" = "$(source_hash)" ] ||
  die "build/$major was not built from the current sources — run scripts/build-in-docker.sh $major"

version="$(extension_version "$build/pg_gcm.control")"
name="pg_gcm-$version"
tarball="pg_gcm-$version-pg$major-$arch.tar.gz"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name/sql"
cp "$build/pg_gcm.so" "$build/pg_gcm.control" "$stage/$name/"
cp "$build"/sql/*.sql "$stage/$name/sql/"
cp "$ROOT/LICENSE" "$ROOT/README.md" "$stage/$name/"

mkdir -p "$out"
tar --create --gzip --file "$out/$tarball" --directory "$stage" "$name"
sha256="$(python3 - "$out/$tarball" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
printf '%s  %s\n' "$sha256" "$tarball" >"$out/$tarball.sha256"
echo "$out/$tarball"
echo "sha256 $sha256"
