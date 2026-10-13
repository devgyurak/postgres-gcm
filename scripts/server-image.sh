#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Build the distribution server image for one major: the official postgres:<major> with the
# built extension installed and CREATE EXTENSION pg_gcm in its init script.
# Usage: scripts/server-image.sh <major> [tag]
#   Needs scripts/build-in-docker.sh <major> to have run. The default tag is local
#   (pg-gcm-server:<major>); the release workflow passes a ghcr.io tag.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  die "usage: scripts/server-image.sh <major> [tag]"
fi
major="$1"
tag="${2:-pg-gcm-server:$major}"

[ -f "$ROOT/build/$major/pg_gcm.so" ] ||
  die "build/$major/pg_gcm.so is missing — run scripts/build-in-docker.sh $major"
# A pass on a binary older than the sources is not a pass.
[ "$(cat "$ROOT/build/$major/SOURCE_HASH" 2>/dev/null)" = "$(source_hash)" ] ||
  die "build/$major was not built from the current sources — run scripts/build-in-docker.sh $major"

# The build context holds only what the image copies, so the Dockerfile never sees the tree.
context="$ROOT/build/$major/server-image"
rm -rf "$context"
mkdir -p "$context/sql" "$context/initdb.d"
cp "$ROOT/build/$major/pg_gcm.so" "$ROOT/build/$major/pg_gcm.control" "$context/"
cp "$ROOT/build/$major"/sql/*.sql "$context/sql/"
cp "$ROOT/docker/initdb.d/"*.sql "$context/initdb.d/"

docker build --file "$ROOT/docker/server.Dockerfile" \
  --build-arg "BASE=$(image_ref "$major")" --tag "$tag" "$context" >/dev/null
echo "built: $tag (PostgreSQL $major, pg_gcm $(extension_version "$context/pg_gcm.control"))"
