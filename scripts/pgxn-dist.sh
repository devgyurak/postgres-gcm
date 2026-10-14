#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Build the PGXN source distribution: pg_gcm-<version>.zip, whose single top-level directory is
# pg_gcm-<version>/ — the layout PGXN Manager expects. The archive is `git archive HEAD`, so it
# holds exactly the tracked files of that commit (the tag, in the release job) and no build
# output; the version comes from META.json, so the name and the metadata cannot drift. The
# archive is validated here, so a mislaid prefix or a missing control file is found by us and not
# by PGXN. The default outdir is outside dist/, so the archive never joins the checksummed
# release assets. Usage: scripts/pgxn-dist.sh [outdir]
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

if [ $# -gt 1 ]; then
  die "usage: scripts/pgxn-dist.sh [outdir]"
fi
out="${1:-$ROOT/build/pgxn}"

# The archive is HEAD, so a dirty tree would ship something other than what the maintainer sees.
if ! git -C "$ROOT" diff --quiet -- || ! git -C "$ROOT" diff --cached --quiet --; then
  die "the working tree or the index has changes — commit them before building the archive"
fi

# An archive is never built from a META.json PGXN would refuse.
version="$(python3 "$ROOT/scripts/check-pgxn.py" --print-version)" ||
  die "META.json is not publishable (see above)"
name="pg_gcm-$version"

# git archive resolves --output against $ROOT, so make the outdir absolute first: a relative path
# given from another directory would otherwise be written under $ROOT, not where the caller asked.
mkdir -p "$out"
out="$(cd "$out" && pwd)"
archive="$out/$name.zip"

git -C "$ROOT" archive --format=zip --prefix="$name/" --output="$archive" HEAD

# The members PGXN Manager needs, the one top-level directory it expects, and the metadata inside
# the archive carrying the version its name does.
python3 - "$archive" "$name" "$version" <<'PY'
import json
import sys
import zipfile

archive, name, version = sys.argv[1:]
with zipfile.ZipFile(archive) as bundle:
    names = bundle.namelist()
    for member in ("META.json", "Makefile", "pg_gcm.control"):
        if f"{name}/{member}" not in names:
            sys.exit(f"error: {archive} has no {name}/{member}")
    meta = json.loads(bundle.read(f"{name}/META.json"))

roots = {member.split("/", 1)[0] for member in names}
if roots != {name}:
    sys.exit(f"error: {archive} has top-level entries {sorted(roots)}, not just {name}")
if meta.get("version") != version:
    sys.exit(f"error: {archive} holds META.json version {meta.get('version')}, not {version}")
PY

echo "$archive"
