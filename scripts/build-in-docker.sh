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

    # The dynamic symbols are exactly the SQL-callable functions, their fmgr records and the
    # two entry points the server loads by name: an exported core function could be interposed
    # by a library loaded earlier. The headers hide the rest; PGXS does so by itself only
    # from 16. The linker adds a few names of its own on some platforms; they are set aside.
    wanted="Pg_magic_func _PG_init gcm_decrypt gcm_encrypt gcm_encrypt_det pg_finfo_gcm_decrypt pg_finfo_gcm_encrypt pg_finfo_gcm_encrypt_det"
    exported="$(nm -D --defined-only /out/pg_gcm.so | awk "{print \$3}" |
      grep -vxE "_init|_fini|_edata|_end|__bss_start|__bss_start__|__bss_end__|__end__" | LC_ALL=C sort | xargs)"
    [ "$exported" = "$wanted" ] || {
      echo "error: pg_gcm.so exports [$exported], expected [$wanted]" >&2
      exit 1
    }
    pg_config --version
  '
echo "$hash" >"$out/SOURCE_HASH"
echo "built: build/$major/pg_gcm.so"
