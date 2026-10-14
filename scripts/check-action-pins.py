#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Every `uses:` in .github/workflows pins its action by commit SHA, with the version in a comment.

    uses: actions/checkout@<40 hex digits> # v5.1.0

A tag or a branch can be moved after review; a commit cannot (.agents/rules/stack-ci-docker.md).
Local actions (`./...`) and digest-pinned images (`docker://...@sha256:...`) pass.
Exit 0 when clean, 1 with one `file:line: message` per violation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Block style (`uses: x`, `- uses: x`) and flow style (`- {uses: x, with: ...}`) alike.
USES = re.compile(r"(?:^|[\s{,])uses:\s*([^\s,}#]+)[^#]*(#.*)?$")
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
DOCKER_PINNED = re.compile(r"^docker://\S+@sha256:[0-9a-f]{64}$")


def main() -> int:
    problems: list[str] = []
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
    for path in workflows:
        rel = path.relative_to(ROOT)
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = USES.search(line)
            if match is None:
                continue
            target, comment = match.group(1).strip("'\""), match.group(2)
            if target.startswith("./") or DOCKER_PINNED.match(target):
                continue
            if not PINNED.match(target):
                problems.append(f"{rel}:{number}: {target} is not pinned by a 40-digit commit SHA")
            elif comment is None or not re.search(r"v\d", comment):
                problems.append(
                    f"{rel}:{number}: {target} needs its version in a comment (# v1.2.3)"
                )

    for problem in problems:
        print(problem)
    if problems:
        print(f"check-action-pins: {len(problems)} violation(s)", file=sys.stderr)
        return 1
    print(f"check-action-pins: ok ({len(workflows)} workflow file(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
