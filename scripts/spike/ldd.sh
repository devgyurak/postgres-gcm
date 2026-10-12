#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Which OpenSSL does the server in each image link, on arm64 and on amd64?
# (docs/design.md §4 step 8; §8 O2 and O11.)
# Usage: scripts/spike/ldd.sh all | <major>...     (all = every major in docker/versions.json)
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/../lib.sh"

[ $# -ge 1 ] || die "usage: scripts/spike/ldd.sh all | <major>..."
if [ "$1" = "all" ]; then
  # shellcheck disable=SC2046
  set -- $(python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); print(*(name for group in v.values() for name in group))' "$ROOT/docker/versions.json")
fi

for major in "$@"; do
  ref="$(image_ref "$major")"
  for platform in linux/arm64 linux/amd64; do
    docker run --rm --platform "$platform" --entrypoint bash "$ref" -c '
      crypto="$(ldd "$(command -v postgres)" | awk "/libcrypto/ {print \$1, \$3}")"
      echo "$PG_VERSION | $(uname -m) | postgres links: ${crypto:-NOT FOUND} | $(openssl version | cut -d" " -f1-2)"
    '
  done
done
