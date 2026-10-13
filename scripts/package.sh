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

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  die "usage: scripts/package.sh <major> <arch> [outdir]"
fi
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

# arch is a label; check it against the ELF the build actually produced (e_machine: 0x3e x86-64,
# 0xb7 AArch64), so an amd64 build is never shipped as arm64.
machine="$(python3 - "$build/pg_gcm.so" <<'PY'
import struct
import sys

with open(sys.argv[1], "rb") as handle:
    header = handle.read(20)
if header[:4] != b"\x7fELF":
    sys.exit("error: the build is not an ELF object")
print({0x3E: "amd64", 0xB7: "arm64"}.get(struct.unpack_from("<H", header, 18)[0], "unknown"))
PY
)"
[ "$machine" = "$arch" ] || die "build/$major/pg_gcm.so is a $machine object, not $arch"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name/sql"
cp "$build/pg_gcm.so" "$build/pg_gcm.control" "$stage/$name/"
cp "$build"/sql/*.sql "$stage/$name/sql/"
cp "$ROOT/LICENSE" "$ROOT/README.md" "$stage/$name/"

mkdir -p "$out"
# COPYFILE_DISABLE keeps macOS from adding ._* AppleDouble members and --no-xattrs drops its
# com.apple.provenance pax header; the fixed owner and group keep the archive root-owned whatever
# uid built it. The timestamps are not pinned, so two runs of this are not byte-identical.
COPYFILE_DISABLE=1 tar --create --gzip --file "$out/$tarball" --directory "$stage" \
  --no-xattrs --owner=0 --group=0 --numeric-owner "$name"
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
