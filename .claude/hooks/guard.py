#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""PreToolUse(Bash) guard body. Invoked by guard.sh; reads the hook JSON from stdin.

Exit 2 blocks the tool call (message on stderr), exit 0 allows.
Blocks: force-push, staging/committing key material, turning on statement logging
(log_statement=all/mod, log_min_duration_statement=0, auto_explain.log_analyze) that would write
keys and plaintext to the server log.

Git commands are tokenized per shell segment; ``cd`` and git global options
(``-C``, ``-c``, ``--git-dir``, ``--work-tree``) are carried into the internal
``git`` queries so the same repository is inspected. File lists are read with
``-z`` (NUL separated, unquoted) so ``core.quotePath`` cannot hide a name.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys

SECRET = re.compile(r"(\.(pem|key|p12|pfx|jks|keystore)$)|keyring|(^|/)\.env(\.|$)", re.IGNORECASE)
GLOBAL_OPTS_WITH_ARG = ("-C", "-c", "--git-dir", "--work-tree")
PREFIXES = ("sudo", "time", "env", "nice")


def deny(msg: str) -> None:
    print(f"guard: {msg}", file=sys.stderr)
    sys.exit(2)


def git_z(cwd: str, global_opts: list[str], *args: str) -> list[str]:
    """Run a git query with -z output and return the NUL-separated paths."""
    try:
        out = subprocess.run(
            ["git", *global_opts, *args],
            cwd=cwd,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    return [p.decode("utf-8", "surrogateescape") for p in out.stdout.split(b"\0") if p]


def staged_files(cwd: str, g: list[str]) -> list[str]:
    return git_z(cwd, g, "diff", "--cached", "--name-only", "-z")


def add_targets(cwd: str, g: list[str], args: list[str]) -> list[str]:
    """Files ``git add <args>`` would stage: untracked + modified under the pathspecs."""
    flags = [a for a in args if a.startswith("-") and a != "--"]
    if "--" in args:
        pathspecs = args[args.index("--") + 1 :]
    else:
        pathspecs = [a for a in args if not a.startswith("-")]
    update_only = any(f in ("-u", "--update") for f in flags)
    if not pathspecs:
        if update_only or any(f in ("-A", "--all", "--no-ignore-removal") for f in flags):
            # Without a pathspec, -A/-u act on the whole repository regardless of cwd;
            # ":/" is Git's top-level pathspec magic, so subdirectory runs see the root too.
            pathspecs = [":/"]
        else:
            return []
    query = ["ls-files", "-z", "--modified"]
    if not update_only:
        query.append("--others")  # -u stages tracked changes only
    if not any(f in ("-f", "--force") for f in flags):
        query.append("--exclude-standard")
    return git_z(cwd, g, *query, "--", *pathspecs)


def dirty_files(cwd: str, g: list[str]) -> list[str]:
    return git_z(cwd, g, "ls-files", "-z", "--others", "--modified", "--exclude-standard")


def resolve_cd(cwd: str, target: str) -> str:
    target = os.path.expanduser(target) if target else os.path.expanduser("~")
    return os.path.normpath(os.path.join(cwd, target))


def main() -> None:
    try:
        cmd = json.load(sys.stdin).get("tool_input", {}).get("command", "")
    except (json.JSONDecodeError, AttributeError):
        sys.exit(0)
    if not cmd:
        sys.exit(0)

    if re.search(
        r"\blog_statement\b['\"]?\s*(=|to)\s*['\"]?(all|mod)\b"
        r"|\blog_min_duration_statement\b['\"]?\s*(=|to)\s*['\"]?0\b"
        r"|\bauto_explain\.log_(analyze|parameter_max_length)\b['\"]?\s*(=|to)\s*['\"]?(on|true|1|-1)\b",
        cmd,
        re.IGNORECASE,
    ):
        deny(
            "turning on statement logging writes keys and plaintext to the server log "
            "(docs/design.md §6). Denied."
        )

    cwd = os.getcwd()
    for seg in re.split(r"\s*(?:&&|\|\||;|\||\n)\s*", cmd):
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        while toks and (re.match(r"^\w+=", toks[0]) or toks[0] in PREFIXES):
            toks = toks[1:]
        if not toks:
            continue
        if toks[0] == "cd":
            cwd = resolve_cd(cwd, toks[1] if len(toks) > 1 else "")
            continue
        if os.path.basename(toks[0]) != "git":
            continue

        i = 1
        while i < len(toks) and toks[i].startswith("-"):
            i += 2 if toks[i] in GLOBAL_OPTS_WITH_ARG else 1
        if i >= len(toks):
            continue
        g, sub, args = toks[1:i], toks[i], toks[i + 1 :]

        if sub == "push":
            forced = any(
                a in ("-f", "--force")
                or a.startswith("--force=")
                or (a.startswith("-") and not a.startswith("--") and "f" in a[1:])
                for a in args
            )
            if forced:
                deny(
                    "force-push is blocked in this repo (stack-ci-docker.md). "
                    "Use --force-with-lease only with explicit user approval."
                )
        elif sub == "add":
            hits = [p for p in add_targets(cwd, g, args) if SECRET.search(p)]
            if hits:
                deny(f"refusing to stage key material: {', '.join(hits[:3])} (crypto-safety.md).")
        elif sub == "commit":
            hits = [p for p in staged_files(cwd, g) if SECRET.search(p)]
            if hits:
                deny(
                    f"index contains key material ({', '.join(hits[:3])}); "
                    "unstage before committing."
                )
            if any(
                a in ("-a", "--all")
                or (a.startswith("-") and not a.startswith("--") and "a" in a[1:])
                for a in args
            ):
                hits = [p for p in dirty_files(cwd, g) if SECRET.search(p)]
                if hits:
                    deny(f"commit -a would include key material ({', '.join(hits[:3])}).")
    sys.exit(0)


if __name__ == "__main__":
    main()
