#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Print a GitHub Actions matrix axis from docker/versions.json, the one list of images.

    ci-matrix.py all    every image: the supported majors, a pre-release, the OpenSSL floor
    ci-matrix.py unit   one image per libcrypto the unit suite must meet: the newest supported
                        major, and each image of the openssl-floor group

The output is a JSON list of {"image": ..., "label": ...}. `image` is what the scripts take;
`label` goes in the job name, and says so when the image is a pre-release — that job is the
one not meant to be a required check (docs/design.md §8, O1). A workflow that named the
images itself would go on passing after an image was added here and never built.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GROUPS = ("supported", "prerelease", "openssl-floor")


def entries(which: str) -> list[dict[str, str]]:
    versions = json.loads((ROOT / "docker" / "versions.json").read_text(encoding="utf-8"))
    unknown = sorted(set(versions) - set(GROUPS))
    if unknown:
        sys.exit(
            f"ci-matrix: docker/versions.json has a group this script does not know: {unknown}"
        )
    supported = sorted(versions.get("supported", {}), key=int)
    if not supported:
        sys.exit("ci-matrix: docker/versions.json lists no supported major")
    if which == "unit":
        names = [supported[-1], *versions.get("openssl-floor", {})]
        return [{"image": name, "label": name} for name in names]
    out = [{"image": name, "label": name} for name in supported]
    out += [
        {"image": name, "label": f"{name}, pre-release"} for name in versions.get("prerelease", {})
    ]
    out += [{"image": name, "label": name} for name in versions.get("openssl-floor", {})]
    return out


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("all", "unit"):
        print("usage: ci-matrix.py all|unit", file=sys.stderr)
        return 2
    print(json.dumps(entries(sys.argv[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
