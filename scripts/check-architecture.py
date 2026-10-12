#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Enforce the module boundaries of .agents/rules/architecture.md, line by line.

- The core (gcm, envelope, nonce) includes no PostgreSQL header and calls nothing of the
  server's: it allocates with malloc/OPENSSL_malloc and returns an error code.
- A core function that acquires an OpenSSL context leaves only through its `done:` label:
  no `return` between the acquisition and the label, a `*_CTX_free(` after the label before
  the function returns, no `goto` to any other label, and no `return` or `goto` in a macro.
  This is a line check, not a parser: it does not see a free that is conditional, a second
  context left unfreed beside a freed one, or a free of the wrong context. The unit suite's
  counting allocator catches those on the paths it executes.
- envelope depends on the C standard library only: no OpenSSL either.
- The direction is glue -> gcm -> envelope/nonce. The glue reaches OpenSSL through gcm.h alone.
- A test seam is never declared in the extension's SQL script and never called by the glue.
- The SQL script declares nothing IMMUTABLE and no DEFAULT NULL.

Exit 0 when clean, 1 with one `file:line: message` per violation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# Module -> the project headers its files may include.
CORE: dict[str, set[str]] = {
    "envelope": {"envelope.h"},
    "nonce": {"nonce.h", "envelope.h"},
    "gcm": {"gcm.h", "envelope.h", "nonce.h"},
}
GLUE_HEADERS = {"gcm.h", "envelope.h", "pg_gcm.h"}

# Entry points that exist for tests only (architecture.md §6). Every seam is listed here.
TEST_SEAMS = ("gcm_seal_with_nonce",)

C_STANDARD = {
    "assert.h", "errno.h", "limits.h", "stdbool.h", "stddef.h", "stdint.h", "stdlib.h", "string.h",
}  # fmt: skip
SERVER_CALLS = re.compile(
    r"\b(palloc0?|repalloc|pfree|ereport|elog|PG_TRY|PG_GETARG_\w+|CHECK_FOR_INTERRUPTS)\s*\("
)
ACQUIRE = re.compile(r"\b(EVP_\w+_CTX_(?:new|dup)\w*)\b")
EXIT_LABEL = re.compile(r"^done:")
RELEASE = re.compile(r"\bEVP_\w+_CTX_free\s*\(")
RETURN = re.compile(r"\breturn\b")
GOTO = re.compile(r"\bgoto\s+(\w+)")
DEFINE = re.compile(r"^\s*#\s*define\b")
INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]')
COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def code_lines(path: Path) -> list[tuple[int, str]]:
    """The file's lines with comments blanked out, numbered from 1."""
    text = path.read_text(encoding="utf-8")
    blanked = COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    return list(enumerate(blanked.splitlines(), start=1))


def check_core(path: Path, module: str, problems: list[str]) -> None:
    rel = path.relative_to(ROOT)
    # A context is "held" from its acquisition to the done: label, then "leaving" until a
    # *_CTX_free( call releases it. A return in either state, or the function's closing brace,
    # is a way out that skips the release.
    held: tuple[int, str] | None = None
    leaving: tuple[int, str] | None = None
    in_macro = False  # inside a #define, its backslash-continued lines included
    for number, line in code_lines(path):
        in_macro = in_macro or bool(DEFINE.match(line))
        if in_macro and (RETURN.search(line) or GOTO.search(line)):
            problems.append(f"{rel}:{number}: a macro in the core may not hide a return or a goto")
        if in_macro:
            in_macro = line.rstrip().endswith("\\")
            continue
        jump = GOTO.search(line)
        if jump and jump.group(1) != "done":
            problems.append(
                f"{rel}:{number}: goto {jump.group(1)} — the core's only exit label is done:"
            )
        if EXIT_LABEL.match(line):
            held, leaving = None, held
        elif held is not None and RETURN.search(line):
            problems.append(
                f"{rel}:{number}: return after {held[1]} (line {held[0]}) "
                "and before the done: label that frees it"
            )
        elif leaving is not None and RELEASE.search(line):
            leaving = None
        elif leaving is not None and RETURN.search(line):
            problems.append(
                f"{rel}:{number}: return after done: without freeing {leaving[1]} "
                f"(line {leaving[0]})"
            )
            leaving = None
        elif line.startswith("}") and (held is not None or leaving is not None):
            context = held if held is not None else leaving
            assert context is not None
            problems.append(
                f"{rel}:{number}: {context[1]} (line {context[0]}) is not freed after a done: label"
            )
            held = leaving = None
        acquire = ACQUIRE.search(line)
        if acquire:
            held = (number, acquire.group(1))
        include = INCLUDE.match(line)
        if include:
            bracket, header = include.groups()
            if bracket == '"':
                if header not in CORE[module]:
                    problems.append(f'{rel}:{number}: {module} may not include "{header}"')
            elif header.startswith("openssl/"):
                if module == "envelope":
                    problems.append(
                        f"{rel}:{number}: envelope may not include OpenSSL (<{header}>)"
                    )
            elif header not in C_STANDARD:
                problems.append(f"{rel}:{number}: the core may not include <{header}>")
        call = SERVER_CALLS.search(line)
        if call:
            problems.append(f"{rel}:{number}: the core may not call {call.group(1)}")


def check_glue(path: Path, problems: list[str]) -> None:
    rel = path.relative_to(ROOT)
    for number, line in code_lines(path):
        include = INCLUDE.match(line)
        if include:
            bracket, header = include.groups()
            if header.startswith("openssl/"):
                problems.append(
                    f"{rel}:{number}: the glue reaches OpenSSL through gcm.h, not <{header}>"
                )
            elif bracket == '"' and "/" not in header and header.endswith(".h"):
                project = (SRC / header).exists()
                if project and header not in GLUE_HEADERS:
                    problems.append(f'{rel}:{number}: the glue may not include "{header}"')
        for seam in TEST_SEAMS:
            if re.search(rf"\b{seam}\b", line):
                problems.append(f"{rel}:{number}: the glue may not call the test seam {seam}")


def check_sql(path: Path, problems: list[str]) -> None:
    rel = path.relative_to(ROOT)
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("--", 1)[0]
        if re.search(r"\bimmutable\b", line, re.IGNORECASE):
            problems.append(f"{rel}:{number}: no function is IMMUTABLE (design §5.3)")
        if re.search(r"\bdefault\s+null\b", line, re.IGNORECASE):
            problems.append(
                f"{rel}:{number}: AAD is two overloads, never DEFAULT NULL (design §2.1)"
            )
        for seam in TEST_SEAMS:
            if re.search(rf"\b{seam}\b", line):
                problems.append(f"{rel}:{number}: the test seam {seam} is never declared in SQL")


def main() -> int:
    problems: list[str] = []
    checked = 0
    for path in sorted(SRC.glob("*.[ch]")):
        checked += 1
        if path.stem in CORE:
            check_core(path, path.stem, problems)
        else:
            check_glue(path, problems)
    for path in sorted((ROOT / "sql").glob("*.sql")):
        checked += 1
        check_sql(path, problems)

    if checked == 0:
        # A gate that checked nothing is the same failure as one that failed.
        print("check-architecture: no file under src/ or sql/ was checked", file=sys.stderr)
        return 1
    for problem in problems:
        print(problem)
    if problems:
        print(f"check-architecture: {len(problems)} violation(s)", file=sys.stderr)
        return 1
    print(f"check-architecture: ok ({checked} files; test seams: {', '.join(TEST_SEAMS)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
