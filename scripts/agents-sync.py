#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Generate tool adapters from canonical sources, or verify they are up to date (--check).

Canonical:  .agents/rules/*.md      -> .claude/rules/*.md, .cursor/rules/*.mdc
            .claude/agents/*.md     -> .opencode/agents/*.md, .codex/agents/*.toml
Symlinks:   .agents/skills          <- .claude/skills, .cursor/skills
            .claude/agents          <- .cursor/agents
"""

import json
import os
import pathlib
import re
import sys
from typing import TypedDict

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECK = "--check" in sys.argv
problems: list[str] = []
generated: set[pathlib.Path] = set()

# ---- per-agent permissions (OpenCode) and sandbox (Codex). Read-only by default. -----------------


class AgentPolicy(TypedDict):
    bash: dict[str, str]
    webfetch: str
    codex_sandbox: str


RO_BASH: dict[str, str] = {
    "*": "ask",
    "git diff*": "allow",
    "git log*": "allow",
    "git status*": "allow",
    "git show*": "allow",
    "git ls-files*": "allow",
    "rg *": "allow",
    "grep *": "allow",
    "cat *": "allow",
    "head *": "allow",
    "sed -n*": "allow",
    "wc *": "allow",
    "find *": "allow",
    "ctest *": "allow",
    "scripts/verify.sh*": "allow",
    "git push*": "deny",
    "git commit*": "deny",
    "git add*": "deny",
    "git reset*": "deny",
    "rm *": "deny",
}
RUNNER_BASH: dict[str, str] = {
    "*": "ask",
    "cmake *": "allow",
    "ctest *": "allow",
    "ninja *": "allow",
    "make *": "allow",
    "docker *": "allow",
    "scripts/*": "allow",
    "python *": "allow",
    "python3 *": "allow",
    "pytest *": "allow",
    "git diff*": "allow",
    "git log*": "allow",
    "git status*": "allow",
    "git push*": "deny",
    "git commit*": "deny",
    "git add*": "deny",
    "rm -rf *": "deny",
}
AGENT_POLICY: dict[str, AgentPolicy] = {
    "code-reviewer": {
        "bash": RO_BASH,
        "webfetch": "deny",
        "codex_sandbox": "read-only",
    },
    "crypto-reviewer": {
        "bash": RO_BASH,
        "webfetch": "deny",
        "codex_sandbox": "read-only",
    },
    "pg-api-researcher": {
        "bash": RO_BASH,
        "webfetch": "allow",
        "codex_sandbox": "read-only",
    },
    "verify-runner": {
        "bash": RUNNER_BASH,
        "webfetch": "deny",
        "codex_sandbox": "workspace-write",
    },
}


def frontmatter(text: str) -> tuple[str, str]:
    m = re.match(r"---\n(.*?)\n---\n(.*)", text, re.DOTALL)
    return (m.group(1), m.group(2)) if m else ("", text)


def emit(path: pathlib.Path, content: str) -> None:
    rel = path.relative_to(ROOT)
    generated.add(path)
    if CHECK:
        if not path.exists() or path.read_text() != content:
            problems.append(f"stale: {rel}")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print(f"write {rel}")


def is_generated(f: pathlib.Path) -> bool:
    """True if the file carries this script's marker in its designated slot:
    first line for TOML, first body line after the frontmatter for .mdc / .md."""
    text = f.read_text()
    if f.suffix == ".toml":
        return text.startswith("# Generated from ")
    _, body = frontmatter(text)
    first = body.lstrip().split("\n", 1)[0]
    return (
        first.startswith(("Generated from ", "<!-- Generated from ")) and "agents-sync.py" in first
    )


def yaml_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# ---- Claude + Cursor rules ----------------------------------------------------------------------
for f in sorted((ROOT / ".agents/rules").glob("*.md")):
    fm, body = frontmatter(f.read_text())
    claude = (
        (f"---\n{fm}\n---\n" if fm else "")
        + f"<!-- Generated from .agents/rules/{f.name} by scripts/agents-sync.py"
        " — edit the source. -->\n" + body
    )
    emit(ROOT / ".claude/rules" / f.name, claude)
    paths = re.findall(r'^\s*-\s*"?([^"\n]+?)"?\s*$', fm, re.MULTILINE) if fm else []
    heading = re.search(r"^# (.+)$", body, re.MULTILINE)
    desc = heading.group(1).strip() if heading else f.stem
    if not paths:
        desc += " (always applied)"
    mdc = (
        "---\n"
        f"description: {yaml_quote(desc)}\n"
        f"globs: {yaml_quote(', '.join(paths))}\n"
        f"alwaysApply: {'false' if paths else 'true'}\n"
        "---\n"
        f"Generated from `.agents/rules/{f.name}` by scripts/agents-sync.py"
        " — edit the source, not this file.\n"
        "The full rule text is in the referenced file and applies together with this rule.\n\n"
        f"@.agents/rules/{f.name}\n"
    )
    emit(ROOT / ".cursor/rules" / (f.stem + ".mdc"), mdc)

# ---- OpenCode + Codex agents ---------------------------------------------------------------------
for f in sorted((ROOT / ".claude/agents").glob("*.md")):
    fm, body = frontmatter(f.read_text())
    name_m = re.search(r"^name: (.*)$", fm, re.MULTILINE)
    desc_m = re.search(r"^description: (.*)$", fm, re.MULTILINE)
    if name_m is None or desc_m is None:
        problems.append(f"{f.relative_to(ROOT)}: front matter needs name: and description:")
        continue
    name = name_m.group(1).strip()
    desc = desc_m.group(1).strip()
    pol = AGENT_POLICY.get(name)
    if pol is None:
        problems.append(f"no AGENT_POLICY for {name} (add it to scripts/agents-sync.py)")
        continue
    bash_lines = "\n".join(
        f"    {json.dumps(k)}: {v}" for k, v in pol["bash"].items()
    )  # "*" first: last match wins
    oc = (
        "---\n"
        f"description: {yaml_quote(desc)}\n"
        "mode: subagent\n"
        "permission:\n"
        "  edit: deny\n"
        f"  webfetch: {pol['webfetch']}\n"
        "  bash:\n"
        f"{bash_lines}\n"
        "---\n"
        f"<!-- Generated from .claude/agents/{f.name} by scripts/agents-sync.py"
        " — edit the source. -->\n" + body
    )
    emit(ROOT / ".opencode/agents" / f.name, oc)
    toml_name = name.replace("-", "_")
    instr = body.strip()
    if "'''" in instr:
        problems.append(
            f"{f.name}: body contains ''' which cannot be embedded in a TOML literal string"
        )
        continue
    tm = (
        f"# Generated from .claude/agents/{f.name} by scripts/agents-sync.py — edit the source.\n"
        f'name = "{toml_name}"\n'
        f"description = {json.dumps(desc, ensure_ascii=False)}\n"
        f'sandbox_mode = "{pol["codex_sandbox"]}"\n'
        # literal string: backslashes in regexes stay verbatim
        f"developer_instructions = '''\n{instr}\n'''\n"
    )
    emit(ROOT / ".codex/agents" / (toml_name + ".toml"), tm)

# ---- orphans: adapters whose source no longer exists ---------------------------------------------
for d, pattern in (
    (".claude/rules", "*.md"),
    (".cursor/rules", "*.mdc"),
    (".opencode/agents", "*.md"),
    (".codex/agents", "*.toml"),
):
    for f in sorted((ROOT / d).glob(pattern)) if (ROOT / d).exists() else []:
        if f in generated:
            continue
        if CHECK:
            problems.append(f"orphan adapter (source deleted?): {f.relative_to(ROOT)}")
        elif is_generated(f):
            f.unlink()
            print(f"remove {f.relative_to(ROOT)} (orphan)")
        else:
            problems.append(
                f"unexpected hand-written file: {f.relative_to(ROOT)} (remove or move to a source)"
            )

# ---- symlinks -----------------------------------------------------------------------------------
LINKS = {
    ".claude/skills": "../.agents/skills",
    ".cursor/skills": "../.agents/skills",
    ".cursor/agents": "../.claude/agents",
}
for link, target in LINKS.items():
    p = ROOT / link
    if CHECK:
        if not p.is_symlink() or os.readlink(p) != target:
            problems.append(f"symlink: {link} -> {target}")
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists() and not p.is_symlink():
            problems.append(f"{link} exists and is not a symlink")
            continue
        if p.is_symlink():
            p.unlink()
        p.symlink_to(target)
        print(f"link  {link} -> {target}")
for stale in [".opencode/skill", ".opencode/agent"]:
    if (ROOT / stale).exists() or (ROOT / stale).is_symlink():
        problems.append(f"stale path: {stale} (OpenCode reads .agents/skills and .opencode/agents)")

if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)
print("agents-sync: ok" if not CHECK else "agents-sync --check: up to date")
