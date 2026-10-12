#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Build the extension with PGXS inside the build image for one PostgreSQL major.
# Leaves build/<major>/{pg_gcm.so,pg_gcm.control,sql/}.
# Usage: scripts/build-in-docker.sh <major>
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -eq 1 ] || die "usage: scripts/build-in-docker.sh <major>"
major="$1"

ensure_build_image "$major"

out="$ROOT/build/$major"
rm -rf "$out"
mkdir -p "$out/sql"
# Taken before the build: an edit made while it runs must not look built.
hash="$(source_hash)"

# The sources are mounted read-only and copied: PGXS builds in the tree, and objects built for
# one major must not be picked up by the next.
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --volume "$ROOT:/src:ro" \
  --volume "$out:/out" \
  "$(build_image_tag "$major")" \
  bash -euo pipefail -c '
    work="$(mktemp -d)"
    cp -r /src/Makefile /src/pg_gcm.control /src/src /src/sql "$work/"
    find "$work" \( -name "*.o" -o -name "*.bc" -o -name "*.so" \) -delete
    make -C "$work" USE_PGXS=1 PG_GCM_WERROR=1 >/dev/null
    cp "$work/pg_gcm.so" "$work/pg_gcm.control" /out/
    cp "$work"/sql/*.sql /out/sql/

    # The extension must resolve the libcrypto the server itself links, and it must be 3.x
    # (docs/design.md section 0).
    server="$(ldd "$(pg_config --bindir)/postgres" | awk "/libcrypto/ {print \$3}")"
    ours="$(ldd /out/pg_gcm.so | awk "/libcrypto/ {print \$3}")"
    echo "server libcrypto: $server"
    echo "pg_gcm libcrypto: $ours"
    [ -n "$server" ] && [ "$server" = "$ours" ] || { echo "error: libcrypto differs" >&2; exit 1; }
    case "$server" in *libcrypto.so.3) ;; *) echo "error: not OpenSSL 3" >&2; exit 1 ;; esac
    pg_config --version
  '
echo "$hash" >"$out/SOURCE_HASH"
echo "built: build/$major/pg_gcm.so"
