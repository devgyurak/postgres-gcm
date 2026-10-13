#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Check META.json against the PGXN Meta Spec 1.0.0 and against this repository.

    python3 scripts/check-pgxn.py                 # validate META.json and the cross-checks
    python3 scripts/check-pgxn.py --print-version # validate, then print the version
    python3 scripts/check-pgxn.py --self-test     # check the rules; reads no repository file

The specification's rules are the ones PGXN Manager enforces (PGXN::Meta::Validator); on top of
them this checks what the specification alone cannot: `version` agrees with `pg_gcm.control`, the
provided `file` and `docfile` exist, the extension version equals the distribution version, and
the `pg_gcm` extension is the one provided (docs/design.md §4, Phase 5). The lint workflow runs it
and its --self-test; `scripts/pgxn-dist.sh` reads the version through --print-version, so an
archive is never built from a META.json PGXN would refuse.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPEC_VERSION = "1.0.0"
REQUIRED = ("name", "abstract", "maintainer", "license", "provides", "version", "meta-spec")
OPTIONAL = (
    "description",
    "generated_by",
    "tags",
    "no_index",
    "prereqs",
    "release_status",
    "resources",
)
RELEASE_STATUS = {"stable", "testing", "unstable"}
PHASES = {"configure", "build", "test", "runtime", "develop"}
RELATIONS = {"requires", "recommends", "suggests", "conflicts"}
LICENSES = {
    "agpl_3", "apache_1_1", "apache_2_0", "artistic_1", "artistic_2", "bsd", "freebsd", "gfdl_1_2",
    "gfdl_1_3", "gpl_1", "gpl_2", "gpl_3", "lgpl_2_1", "lgpl_3_0", "mit", "mozilla_1_0",
    "mozilla_1_1", "openssl", "perl_5", "postgresql", "qpl_1_0", "ssleay", "sun", "zlib",
    "open_source", "restricted", "unrestricted", "unknown",
}  # fmt: skip
# A Term: two or more characters, no space, slash, backslash or control character.
TERM = re.compile(r"^[^\s/\\\x00-\x1f\x7f]{2,}$")
# A Tag: one to 255 characters, no slash, backslash or control character (spaces are allowed).
TAG = re.compile(r"^[^/\\\x00-\x1f\x7f]{1,255}$")
# A semantic version, semver.org's own regex with the leading "v" that PGXN's SemVer accepts.
SEMVER = re.compile(
    r"^v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
URL = re.compile(r"^[^:/?#\s]+://[^/?#\s]+")
OPERATOR = re.compile(r"^(?:[<>]=?|==|!=)\s*")
CONTROL_VERSION = re.compile(r"^default_version\s*=\s*'([^']+)'")


def control_default_version(text: str) -> str | None:
    """The default_version of a control file, or None when it is not there."""
    for line in text.splitlines():
        match = CONTROL_VERSION.match(line)
        if match:
            return match.group(1)
    return None


def is_version_range(value: str) -> bool:
    """Whether a prereq version range is a version, or a comma-separated list of bounded ones."""
    for part in value.split(","):
        part = part.strip()
        if not part:
            return False
        if part == "0":
            continue
        operator = OPERATOR.match(part)
        version = part[operator.end() :] if operator else part
        if not SEMVER.match(version):
            return False
    return True


def unknown_keys(mapping: dict[str, Any], allowed: set[str], where: str) -> list[str]:
    """The spec's rule that a map holds only its keys, or custom ones prefixed with x_/X_."""
    return [
        f"{where}.{key} is not a key of the meta spec (custom keys begin with x_)"
        for key in mapping
        if key not in allowed and not str(key).lower().startswith("x_")
    ]


def check_maintainer(value: Any) -> list[str]:
    if value is None:
        return ["maintainer is required"]
    entries = value if isinstance(value, list) else [value]
    if not entries:
        return ["maintainer is required"]
    problems = []
    for entry in entries:
        if not (isinstance(entry, str) and entry):
            problems.append("each maintainer must be a non-empty string")
        elif "<" not in entry or ">" not in entry:
            problems.append(f"maintainer {entry!r} should be 'name <email>'")
    return problems


def check_license(value: Any) -> list[str]:
    if value is None:
        return ["license is required"]
    if isinstance(value, str):
        return [] if value in LICENSES else [f"license {value!r} is not a known license string"]
    if isinstance(value, list):
        if not value:
            return ["license is required"]
        return [
            f"license {entry!r} is not a known license string"
            for entry in value
            if not (isinstance(entry, str) and entry in LICENSES)
        ]
    if isinstance(value, dict):
        return [
            f"license {name!r} must link to its text"
            for name, url in value.items()
            if not (isinstance(url, str) and URL.match(url))
        ]
    return ["license must be a string, a list of strings or a map of name to URL"]


def check_meta_spec(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["meta-spec is required"]
    problems = unknown_keys(value, {"version", "url"}, "meta-spec")
    spec = value.get("version")
    if spec is None:
        problems.append("meta-spec.version is required")
    elif spec != SPEC_VERSION:
        problems.append(f"meta-spec.version {spec!r} is not {SPEC_VERSION}")
    url = value.get("url")
    if url is not None and not (isinstance(url, str) and URL.match(url)):
        problems.append(f"meta-spec.url {url!r} is not a URL")
    return problems


def check_provides(value: Any, version: Any, exists: Callable[[str], bool]) -> list[str]:
    if not isinstance(value, dict) or not value:
        return ["provides is required, with at least one extension"]
    problems = []
    for extension, entry in value.items():
        if not (isinstance(extension, str) and TERM.match(extension)):
            problems.append(f"the extension name {extension!r} is not a term")
        if not isinstance(entry, dict):
            problems.append(f"provides.{extension} must be a map")
            continue
        problems += unknown_keys(
            entry, {"file", "version", "abstract", "docfile"}, f"provides.{extension}"
        )
        file = entry.get("file")
        if not isinstance(file, str) or not file:
            problems.append(f"provides.{extension}.file is required")
        elif not exists(file):
            problems.append(f"provides.{extension}.file {file!r} is not in the distribution")
        docfile = entry.get("docfile")
        if docfile is not None and not (isinstance(docfile, str) and exists(docfile)):
            problems.append(f"provides.{extension}.docfile {docfile!r} is not in the distribution")
        abstract = entry.get("abstract")
        if abstract is not None and not (isinstance(abstract, str) and abstract):
            problems.append(f"provides.{extension}.abstract must be a non-empty string")
        entry_version = entry.get("version")
        if not (isinstance(entry_version, str) and SEMVER.match(entry_version)):
            problems.append(f"provides.{extension}.version must be a semantic version")
        elif isinstance(version, str) and entry_version != version:
            problems.append(
                f"provides.{extension}.version {entry_version} does not match the"
                f" distribution version {version}"
            )
    if "pg_gcm" not in value:
        problems.append("provides must name the pg_gcm extension")
    return problems


def check_release_status(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, str) or value not in RELEASE_STATUS:
        return [f"release_status {value!r} must be one of {', '.join(sorted(RELEASE_STATUS))}"]
    return []


def check_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        return ["tags must be a list"]
    return [
        f"tag {tag!r} must be shorter than 256 characters, without a slash or backslash"
        for tag in value
        if not (isinstance(tag, str) and TAG.match(tag))
    ]


def check_no_index(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, dict):
        return ["no_index must be a map"]
    problems = unknown_keys(value, {"file", "directory"}, "no_index")
    for key in ("file", "directory"):
        entries = value.get(key, [])
        if not isinstance(entries, list) or any(
            not (isinstance(entry, str) and entry) for entry in entries
        ):
            problems.append(f"no_index.{key} must be a list of paths")
    return problems


def check_prereqs(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["prereqs.runtime.requires must name PostgreSQL"]
    problems = []
    for phase, relations in value.items():
        if phase not in PHASES and not str(phase).lower().startswith("x_"):
            problems.append(f"prereqs phase {phase!r} must be one of {', '.join(sorted(PHASES))}")
            continue
        if not isinstance(relations, dict):
            problems.append(f"prereqs.{phase} must be a map")
            continue
        for relation, requirements in relations.items():
            if relation not in RELATIONS and not str(relation).lower().startswith("x_"):
                problems.append(
                    f"prereqs.{phase}.{relation!r} must be one of {', '.join(sorted(RELATIONS))}"
                )
                continue
            if not isinstance(requirements, dict):
                problems.append(f"prereqs.{phase}.{relation} must be a map")
                continue
            for extension, version_range in requirements.items():
                if not (isinstance(extension, str) and TERM.match(extension)):
                    problems.append(f"prereq name {extension!r} is not a term")
                if not (isinstance(version_range, str) and is_version_range(version_range)):
                    problems.append(
                        f"prereq {extension} version range {version_range!r} is not valid"
                    )
    runtime = value.get("runtime")
    requires = runtime.get("requires") if isinstance(runtime, dict) else None
    postgresql = requires.get("PostgreSQL") if isinstance(requires, dict) else None
    if postgresql is None:
        problems.append("prereqs.runtime.requires.PostgreSQL is required")
    elif isinstance(postgresql, str):
        parts = [int(part) for part in re.findall(r"\d+", postgresql)][:3]
        parts += [0] * (3 - len(parts))
        if tuple(parts) < (15, 0, 0):
            problems.append(f"PostgreSQL {postgresql!r} is below the supported floor 15.0.0")
    return problems


def check_resources(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, dict):
        return ["resources must be a map"]
    problems = unknown_keys(value, {"homepage", "bugtracker", "repository", "license"}, "resources")
    homepage = value.get("homepage")
    if homepage is not None and not (isinstance(homepage, str) and URL.match(homepage)):
        problems.append(f"resources.homepage {homepage!r} is not a URL")
    license = value.get("license")
    if license is not None and (
        not isinstance(license, list)
        or any(not (isinstance(url, str) and URL.match(url)) for url in license)
    ):
        problems.append("resources.license must be a list of URLs")
    fields = {"bugtracker": {"web", "mailto"}, "repository": {"web", "url", "type"}}
    for key, allowed in fields.items():
        entry = value.get(key)
        if entry is None:
            continue
        if not isinstance(entry, dict):
            problems.append(f"resources.{key} must be a map")
            continue
        problems += unknown_keys(entry, allowed, f"resources.{key}")
        for field in ("web", "mailto", "url"):
            url = entry.get(field)
            if url is None:
                continue
            if field == "mailto":
                ok = isinstance(url, str) and "@" in url
            else:
                ok = isinstance(url, str) and bool(URL.match(url))
            if not ok:
                problems.append(f"resources.{key}.{field} {url!r} is not valid")
        if key == "repository" and "type" in entry:
            kind = entry["type"]
            if not (isinstance(kind, str) and kind and kind == kind.lower()):
                problems.append(f"resources.repository.type {kind!r} must be lowercase")
    return problems


def validate(
    meta: dict[str, Any],
    exists: Callable[[str], bool],
    control_version: str | None,
) -> list[str]:
    """Every rule at once: the PGXN Meta Spec 1.0.0 plus this repository's cross-checks."""
    problems: list[str] = []
    for key in REQUIRED:
        if key not in meta:
            problems.append(f"{key} is required")
    known = set(REQUIRED) | set(OPTIONAL)
    for key in meta:
        if key not in known and not key.lower().startswith("x_"):
            problems.append(f"{key} is not a key of the meta spec (custom keys begin with x_)")

    name = meta.get("name")
    if name is not None and not (isinstance(name, str) and TERM.match(name)):
        problems.append(f"name {name!r} is not a term (no space, slash or backslash, two or more)")

    version = meta.get("version")
    if not (isinstance(version, str) and SEMVER.match(version)):
        problems.append(f"version {version!r} is not a semantic version")
    elif control_version is not None and version != control_version:
        problems.append(
            f"version {version} does not match pg_gcm.control's default_version {control_version}"
        )

    if not (isinstance(meta.get("abstract"), str) and meta.get("abstract")):
        problems.append("abstract is required")
    if "description" in meta and not (isinstance(meta["description"], str) and meta["description"]):
        problems.append("description must be a non-empty string")
    if "generated_by" in meta and not (
        isinstance(meta["generated_by"], str) and meta["generated_by"]
    ):
        problems.append("generated_by must be a non-empty string")

    problems += check_maintainer(meta.get("maintainer"))
    problems += check_license(meta.get("license"))
    problems += check_meta_spec(meta.get("meta-spec"))
    problems += check_provides(meta.get("provides"), version, exists)
    problems += check_release_status(meta.get("release_status"))
    problems += check_tags(meta.get("tags"))
    problems += check_no_index(meta.get("no_index"))
    problems += check_prereqs(meta.get("prereqs"))
    problems += check_resources(meta.get("resources"))
    return problems


def valid_document() -> dict[str, Any]:
    """A document every rule accepts, the starting point the self-test breaks."""
    return {
        "name": "pg_gcm",
        "abstract": "AES-GCM authenticated encryption functions",
        "version": "0.1.0",
        "maintainer": ["devgyurak <dev@devgyurak.com>"],
        "license": "postgresql",
        "provides": {
            "pg_gcm": {
                "abstract": "AES-GCM functions",
                "file": "sql/pg_gcm--0.1.0.sql",
                "docfile": "README.md",
                "version": "0.1.0",
            }
        },
        "prereqs": {"runtime": {"requires": {"PostgreSQL": "15.0.0"}}},
        "release_status": "testing",
        "generated_by": "devgyurak",
        "meta-spec": {"version": "1.0.0", "url": "https://pgxn.org/meta/spec.txt"},
        "tags": ["encryption", "aes", "gcm"],
        "no_index": {"directory": ["scripts"], "file": ["AGENTS.md"]},
        "resources": {
            "homepage": "https://github.com/devgyurak/postgres-gcm",
            "bugtracker": {"web": "https://github.com/devgyurak/postgres-gcm/issues"},
            "repository": {
                "url": "https://github.com/devgyurak/postgres-gcm.git",
                "web": "https://github.com/devgyurak/postgres-gcm",
                "type": "git",
            },
        },
    }


def self_test() -> int:
    """Break the valid document one way at a time; a break not caught is a hole in this gate."""

    def broken(mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        document: dict[str, Any] = json.loads(json.dumps(valid_document()))
        mutate(document)
        return document

    cases: dict[str, Callable[[dict[str, Any]], None]] = {
        "a missing name": lambda d: d.pop("name"),
        "a name with a space": lambda d: d.update(name="pg gcm"),
        "a two-part version": lambda d: d.update(version="0.1"),
        "a version unlike the control file": lambda d: d.update(version="0.2.0"),
        "a missing abstract": lambda d: d.pop("abstract"),
        "an unknown license": lambda d: d.update(license="proprietary"),
        "a license list with one unknown": lambda d: d.update(
            license=["postgresql", "proprietary"]
        ),
        "a maintainer without a contact": lambda d: d.update(maintainer=["devgyurak"]),
        "a missing meta-spec": lambda d: d.pop("meta-spec"),
        "another meta-spec version": lambda d: d["meta-spec"].update(version="2.0.0"),
        "a missing provides": lambda d: d.pop("provides"),
        "a provided file that is not there": lambda d: d["provides"]["pg_gcm"].update(
            file="sql/gone--0.1.0.sql"
        ),
        "a docfile that is not there": lambda d: d["provides"]["pg_gcm"].update(
            docfile="docs/gone.md"
        ),
        "an extension version that disagrees": lambda d: d["provides"]["pg_gcm"].update(
            version="0.2.0"
        ),
        "a prerelease version with a leading zero": lambda d: d["provides"]["pg_gcm"].update(
            version="0.1.0-01"
        ),
        "a provided abstract that is not a string": lambda d: d["provides"]["pg_gcm"].update(
            abstract=42
        ),
        "a provided entry with an unknown key": lambda d: d["provides"]["pg_gcm"].update(files="x"),
        "a meta-spec with an unknown key": lambda d: d["meta-spec"].update(versoin="1.0.0"),
        "a no_index with an unknown key": lambda d: d.update(no_index={"files": ["a"]}),
        "a resources entry with an unknown key": lambda d: d["resources"].update(
            licence="https://x"
        ),
        "a resources license that is not a list of URLs": lambda d: d["resources"].update(
            license=["nope"]
        ),
        "a repository with an unknown key": lambda d: d["resources"]["repository"].update(
            branch="main"
        ),
        "a release_status outside the three": lambda d: d.update(release_status="beta"),
        "a tag with a slash": lambda d: d.update(tags=["a/b"]),
        "an unknown top-level key": lambda d: d.update(distribution="other"),
        "an unknown prereq phase": lambda d: d["prereqs"].update(deploy={"requires": {}}),
        "an unknown prereq relation": lambda d: d["prereqs"]["runtime"].update(
            wants={"PostgreSQL": "15.0.0"}
        ),
        "no PostgreSQL prereq": lambda d: d["prereqs"]["runtime"]["requires"].pop("PostgreSQL"),
        "a PostgreSQL floor below 15": lambda d: d["prereqs"]["runtime"]["requires"].update(
            PostgreSQL="14.0.0"
        ),
        "a version range that is not one": lambda d: d["prereqs"]["runtime"]["requires"].update(
            PostgreSQL="=~15"
        ),
        "an uppercase repository type": lambda d: d["resources"]["repository"].update(type="Git"),
        "a homepage that is not a URL": lambda d: d["resources"].update(
            homepage="github.com/devgyurak/postgres-gcm"
        ),
    }
    allowed: dict[str, Callable[[dict[str, Any]], None]] = {
        "a custom x_ prereq phase": lambda d: d["prereqs"].update(x_extra={"requires": {}}),
        "a custom x_ resource": lambda d: d["resources"].update(x_docs="https://example.test/"),
    }

    def exists(path: str) -> bool:
        """A file the self-test pretends is absent: its name holds "gone"."""
        return "gone" not in path

    holes = [
        name for name, mutate in cases.items() if not validate(broken(mutate), exists, "0.1.0")
    ]
    holes += [name for name, mutate in allowed.items() if validate(broken(mutate), exists, "0.1.0")]
    own = validate(valid_document(), exists, "0.1.0")
    if own:
        holes.append(f"the valid document itself ({own[0]})")
    total = len(cases) + len(allowed) + 1
    print(
        f"check-pgxn self-test: {total - len(holes)} of {total} checks as expected;"
        f" not caught: {holes}",
        file=sys.stderr,
    )
    return 0 if not holes else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument(
        "--print-version", action="store_true", help="validate, then print the version"
    )
    parser.add_argument("--self-test", action="store_true", help="check the rules; no repository")
    parser.add_argument("--meta", default=str(ROOT / "META.json"), help="the metadata file")
    parser.add_argument("--control", default=str(ROOT / "pg_gcm.control"), help="the control file")
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    meta_path = Path(args.meta)
    try:
        document = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"check-pgxn: {meta_path} is not readable JSON: {error}", file=sys.stderr)
        return 1
    if not isinstance(document, dict):
        print(f"check-pgxn: {meta_path} is not a JSON object", file=sys.stderr)
        return 1

    try:
        control_text = Path(args.control).read_text(encoding="utf-8")
    except OSError as error:
        print(f"check-pgxn: {args.control} is not readable: {error}", file=sys.stderr)
        return 1
    control_version = control_default_version(control_text)
    root = meta_path.parent
    problems = validate(document, lambda path: (root / path).is_file(), control_version)
    if control_version is None:
        problems.append("pg_gcm.control has no default_version")
    if problems:
        for problem in problems:
            print(f"check-pgxn: {problem}", file=sys.stderr)
        return 1
    if args.print_version:
        print(document["version"])
        return 0
    print(f"check-pgxn: {meta_path.name} is valid (version {document['version']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
