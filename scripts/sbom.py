#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Write a CycloneDX 1.5 SBOM for a release: the extension, the server and libcrypto it needs,
and every release file with its SHA-256.

    python3 scripts/sbom.py --output dist/pg_gcm-0.1.0.sbom.cdx.json --version 0.1.0 \\
        --postgresql 15-18 --openssl 3.0+ dist/*.tar.gz
    python3 scripts/sbom.py --self-test        # check the document's shape; touches no file

The server and libcrypto entries are the supported range, not a resolution: what ships is
built against the image's own server and links that image's libcrypto (docs/design.md §0).
The lint workflow runs --self-test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.5"


def sha256(path: Path) -> str:
    """The SHA-256 of a file, read in blocks so a large artifact is not held in memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build(version: str, postgresql: str, openssl: str, artifacts: list[Path]) -> dict[str, Any]:
    """The CycloneDX document for these artifacts. Reads each artifact; builds nothing else."""
    extension = {
        "type": "library",
        "bom-ref": f"pkg:generic/pg_gcm@{version}",
        "name": "pg_gcm",
        "version": version,
        "purl": f"pkg:generic/pg_gcm@{version}",
        "licenses": [{"license": {"id": "PostgreSQL"}}],
    }
    server = {
        "type": "framework",
        "bom-ref": "pkg:generic/postgresql",
        "name": "postgresql",
        "version": postgresql,
        "description": "the host server the extension is built against (the supported range)",
    }
    crypto = {
        "type": "library",
        "bom-ref": "pkg:generic/openssl",
        "name": "openssl",
        "version": openssl,
        "description": "libcrypto, the server's own (the supported range)",
    }
    files = [
        {
            "type": "file",
            "name": artifact.name,
            "hashes": [{"alg": "SHA-256", "content": sha256(artifact)}],
        }
        for artifact in artifacts
    ]
    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": extension,
            "tools": [{"vendor": "pg_gcm", "name": "scripts/sbom.py", "version": version}],
        },
        "components": [extension, server, crypto, *files],
        "dependencies": [
            {"ref": extension["bom-ref"], "dependsOn": [server["bom-ref"], crypto["bom-ref"]]}
        ],
    }


def self_test() -> int:
    """The document's shape, from fixed inputs: no artifact and no server."""
    document = build("0.1.0", "15-18", "3.0+", [])
    names = {component["name"] for component in document["components"]}
    checks = {
        "the format and spec version": (document["bomFormat"], document["specVersion"])
        == (BOM_FORMAT, SPEC_VERSION),
        "a metadata component named pg_gcm": document["metadata"]["component"]["name"] == "pg_gcm",
        "the server and libcrypto are components": names >= {"pg_gcm", "postgresql", "openssl"},
        "the extension depends on both": document["dependencies"][0]["dependsOn"]
        == ["pkg:generic/postgresql", "pkg:generic/openssl"],
        "the PostgreSQL license": document["components"][0]["licenses"]
        == [{"license": {"id": "PostgreSQL"}}],
    }
    wrong = [name for name, ok in checks.items() if not ok]
    print(
        f"sbom self-test: {len(checks) - len(wrong)} of {len(checks)} checks as expected;"
        f" wrong: {wrong}",
        file=sys.stderr,
    )
    return 0 if not wrong else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--output", help="where to write the SBOM (JSON)")
    parser.add_argument("--version", help="the extension version")
    parser.add_argument("--postgresql", default="15-18", help="the supported server range")
    parser.add_argument("--openssl", default="3.0+", help="the supported libcrypto range")
    parser.add_argument("--self-test", action="store_true", help="check the shape; touches no file")
    parser.add_argument("artifacts", nargs="*", help="the release files to hash")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.output or not args.version:
        parser.error("--output and --version are required")
    paths = [Path(argument) for argument in args.artifacts]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        print(f"sbom: no such file: {', '.join(missing)}", file=sys.stderr)
        return 1
    if not paths:
        # An SBOM of nothing is the same failure as one that could not be written.
        print("sbom: no artifact was named", file=sys.stderr)
        return 1
    document = build(args.version, args.postgresql, args.openssl, paths)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    print(f"sbom: wrote {output} for {len(paths)} artifact(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
