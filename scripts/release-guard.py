#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Guard a release: the tag is SemVer, it matches pg_gcm.control's default_version, it is on
main, and CHANGELOG.md carries a `## <version>` section.

    python3 scripts/release-guard.py --tag v0.1.0 --on-main true
    python3 scripts/release-guard.py --print-version  # the control file's version, nothing guarded
    python3 scripts/release-guard.py --self-test      # check these rules; no repository

A `workflow_dispatch` run has no tag: the guard job prints the control file's version with
--print-version, and the pipeline runs every step except signing and publishing
(`.agents/skills/ci-release/SKILL.md`). The lint workflow runs --self-test.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def version_from_control(text: str) -> str | None:
    """The default_version of a control file, or None when it is not there."""
    for line in text.splitlines():
        match = re.match(r"^default_version\s*=\s*'([^']+)'", line)
        if match:
            return match.group(1)
    return None


def changelog_has_section(text: str, version: str) -> bool:
    """Whether the changelog carries a '## <version>' heading."""
    return any(re.match(rf"^##\s+{re.escape(version)}(\s|$)", line) for line in text.splitlines())


def check(tag: str, on_main: bool, control: str, changelog: str) -> tuple[bool, list[str]]:
    """Every release rule at once. Returns the verdict and one message per broken rule."""
    version = version_from_control(control)
    if version is None:
        return False, ["pg_gcm.control has no default_version"]
    if not SEMVER.match(tag):
        return False, [f"{tag} is not a SemVer tag vMAJOR.MINOR.PATCH"]
    problems: list[str] = []
    if tag[1:] != version:
        problems.append(f"the tag {tag} does not match default_version {version}")
    if not on_main:
        problems.append(f"{tag} is not an ancestor of main")
    if not changelog_has_section(changelog, version):
        problems.append(f"CHANGELOG.md has no '## {version}' section")
    return not problems, problems


def self_test() -> int:
    """The rules against tags whose verdict is known. Reads no repository file."""
    control = "default_version = '0.1.0'\n"
    changelog = "# Changelog\n\n## 0.1.0\n\n## Unreleased\n"
    cases: list[tuple[str, tuple[str, bool, str, str], bool]] = [
        (
            "a tag that matches, on main, with its section",
            ("v0.1.0", True, control, changelog),
            True,
        ),
        ("a tag without the v", ("0.1.0", True, control, changelog), False),
        ("a tag that is not SemVer", ("v1.2", True, control, changelog), False),
        ("a tag that does not match the control file", ("v0.2.0", True, control, changelog), False),
        ("a tag that is not on main", ("v0.1.0", False, control, changelog), False),
        (
            "a CHANGELOG without the section",
            ("v0.1.0", True, control, "# Changelog\n\n## Unreleased\n"),
            False,
        ),
        ("a control file without a version", ("v0.1.0", True, "comment = 'x'\n", changelog), False),
    ]
    verdicts = [(name, check(*args)[0], want) for name, args, want in cases]
    wrong = [name for name, got, want in verdicts if got != want]
    print(
        f"release-guard self-test: {len(verdicts) - len(wrong)} of {len(verdicts)} verdicts"
        f" as expected; wrong: {wrong}",
        file=sys.stderr,
    )
    return 0 if not wrong else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--tag", help="the pushed tag, vMAJOR.MINOR.PATCH")
    parser.add_argument(
        "--on-main",
        type=lambda value: value.lower() in ("1", "true", "yes"),
        default=False,
        help="whether the tag is an ancestor of main, computed by the workflow",
    )
    parser.add_argument(
        "--print-version", action="store_true", help="print the control file's version and exit"
    )
    parser.add_argument("--self-test", action="store_true", help="check the rules; no repository")
    parser.add_argument("--control", default=str(ROOT / "pg_gcm.control"))
    parser.add_argument("--changelog", default=str(ROOT / "CHANGELOG.md"))
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    control = Path(args.control).read_text(encoding="utf-8")
    version = version_from_control(control)
    if version is None:
        print("release-guard: pg_gcm.control has no default_version", file=sys.stderr)
        return 1
    if args.print_version:
        print(version)
        return 0
    if not args.tag:
        parser.error("--tag is required unless --print-version")

    changelog = Path(args.changelog).read_text(encoding="utf-8")
    passed, problems = check(args.tag, args.on_main, control, changelog)
    for problem in problems:
        print(f"release-guard: {problem}", file=sys.stderr)
    if not passed:
        return 1
    print(f"release-guard: {args.tag} may be released (version {version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
