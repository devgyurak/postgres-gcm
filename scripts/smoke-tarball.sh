#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Smoke a release tarball: extract it, layer it onto the official postgres:<major> image with the
# same docker/server.Dockerfile the distribution image uses, and run the Korean LIKE round trip
# there. This loads the shipped bytes — each architecture's own pg_gcm.so — which building the
# server image from the build tree does not (the release workflow runs it on amd64 and arm64).
# Usage: scripts/smoke-tarball.sh <major> <tarball>
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

if [ $# -ne 2 ]; then
  die "usage: scripts/smoke-tarball.sh <major> <tarball>"
fi
major="$1"
tarball="$2"
[ -f "$tarball" ] || die "no such tarball: $tarball"

tag="pg-gcm-tarball:$major"
context="$(mktemp -d)"
cleanup() {
  rm -rf "$context"
  docker image rm --force "$tag" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The tarball holds pg_gcm-<version>/{pg_gcm.so,pg_gcm.control,sql/,LICENSE,README.md}; strip the
# directory so the Dockerfile's COPY paths match the build context it expects.
tar -xzf "$tarball" --strip-components=1 -C "$context"
mkdir -p "$context/initdb.d"
cp "$ROOT/docker/initdb.d/"*.sql "$context/initdb.d/"

docker build --file "$ROOT/docker/server.Dockerfile" \
  --build-arg "BASE=$(image_ref "$major")" --tag "$tag" "$context" >/dev/null
echo "staged: $tarball ($(extension_version "$context/pg_gcm.control"))"
"$ROOT/scripts/smoke-image.sh" "$tag"
