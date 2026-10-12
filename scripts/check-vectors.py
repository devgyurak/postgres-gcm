#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Re-derive every vector of spec/test-vectors.json with an implementation that is not the
extension's: `cryptography` for AES-GCM and the standard library for HMAC-SHA256.

This file is a second implementation of spec/envelope.md, kept as small as the spec allows.

- A `nist` vector is an AES-GCM known answer and is recomputed as such.
- An envelope vector is opened as the spec says and the outcome must be its `expect`. When
  that is `ok` the plaintext and the nonce must match and sealing the same inputs must give
  the same bytes; for the deterministic variant the nonce key and the nonce are re-derived.
- The file must hold every vector the specification and the rules name, each of them the
  case its name says, and cover every suite, outcome and plaintext class.

Exit 0 when everything holds, 1 with one `id: message` line per problem.
It only checks. Nothing here encrypts for anyone: there is no public API (stack-python.md).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
LABEL = b"pg_gcm/v1/det-nonce"
NONCE_LEN = 12
TAG_LEN = 16
OVERHEAD = 1 + NONCE_LEN + TAG_LEN
# Version byte -> (key length in bytes, deterministic). 0x01 is reserved and opens nowhere.
SUITES: dict[int, tuple[int, bool]] = {
    0x02: (32, False),
    0x03: (32, True),
    0x04: (16, False),
    0x05: (16, True),
    0x06: (24, False),
    0x07: (24, True),
}
KEY_LENGTHS = {16, 24, 32}
OUTCOMES = {"ok", "bad_tag", "bad_envelope", "bad_key_length"}
CLASSES = {"text", "not_utf8", "contains_nul"}
NIST_PER_KEY_LENGTH = 5
# Vectors that spec/envelope.md, the rules or the design name. The file may hold more.
REQUIRED = (
    "version-02-as-03",
    "version-03-as-02",
    "version-04-as-05",
    "version-06-as-07",
    "tag-last-bit-flipped",
    "ciphertext-first-bit-flipped",
    "nonce-first-bit-flipped",
    "key-different",
    "aad-missing",
    "aad-different",
    "aad-unexpected",
    "last-byte-dropped",
    "one-byte-appended",
    "envelope-empty",
    "envelope-one-byte",
    "envelope-12-bytes",
    "envelope-28-bytes",
    "version-01-reserved",
    "key-16-bytes-for-aes-256",
    "precedence-key-length-before-envelope",
    "precedence-envelope-before-suite",
    "precedence-short-envelope-before-suite",
    "random-256-korean",
    "det-256-korean",
    "det-256-aad",
    "det-256-nonce-not-derived",
    "random-256-not-utf8",
    "random-256-contains-nul",
)
HEX = re.compile(r"(?:[0-9a-f]{2})*")


Vector = dict[str, Any]


def derive_nonce(key: bytes, associated: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """The deterministic variant's nonce key and nonce (spec 1.8)."""
    nonce_key = hmac.new(key, LABEL, hashlib.sha256).digest()
    message = len(associated).to_bytes(8, "big") + associated + plaintext
    return nonce_key, hmac.new(nonce_key, message, hashlib.sha256).digest()[:NONCE_LEN]


def seal(version: int, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """version || nonce || ciphertext || tag, with A = version || aad (spec 1.5, 1.6)."""
    sealed = AESGCM(key).encrypt(nonce, plaintext, bytes([version]) + aad)
    return bytes([version]) + nonce + sealed


def open_envelope(key: bytes, aad: bytes, envelope: bytes) -> tuple[str, bytes]:
    """The outcome and the plaintext, in the order of checks spec 1.7 fixes."""
    if len(key) not in KEY_LENGTHS:
        return "bad_key_length", b""
    if len(envelope) < OVERHEAD or envelope[0] not in SUITES:
        return "bad_envelope", b""
    version = envelope[0]
    if len(key) != SUITES[version][0]:
        return "bad_key_length", b""
    nonce, sealed = envelope[1 : 1 + NONCE_LEN], envelope[1 + NONCE_LEN :]
    try:
        return "ok", AESGCM(key).decrypt(nonce, sealed, bytes([version]) + aad)
    except InvalidTag:
        return "bad_tag", b""


def classify(plaintext: bytes) -> str:
    """What a text-returning opener makes of an authenticated plaintext."""
    try:
        plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return "not_utf8"
    return "contains_nul" if b"\x00" in plaintext else "text"


def field(vector: Vector, name: str) -> bytes:
    value = vector.get(name)
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError(f"{name} is missing or is not lower-case hex")
    return bytes.fromhex(value)


def check_nist(vector: Vector) -> None:
    key, nonce, aad = field(vector, "key_hex"), field(vector, "nonce_hex"), field(vector, "aad_hex")
    expected = field(vector, "ciphertext_hex") + field(vector, "tag_hex")
    if vector.get("expect") != "ok" or not vector.get("source"):
        raise ValueError("a nist vector expects ok and names its source")
    if AESGCM(key).encrypt(nonce, field(vector, "plaintext_hex"), aad) != expected:
        raise ValueError("AES-GCM does not reproduce the ciphertext and tag")


def check_envelope(vector: Vector, by_id: dict[str, Vector]) -> None:
    key, aad = field(vector, "key_hex"), field(vector, "aad_hex")
    envelope = field(vector, "envelope_hex")
    outcome, plaintext = open_envelope(key, aad, envelope)
    if outcome != vector.get("expect"):
        raise ValueError(f"opens as {outcome}, the vector expects {vector.get('expect')}")
    if outcome != "ok":
        base = by_id.get(str(vector.get("derived_from")))
        if base is None or base.get("expect") != "ok" or base.get("kind") != vector.get("kind"):
            raise ValueError("derived_from must name an ok vector of the same kind")
        return

    version = envelope[0]
    deterministic = SUITES[version][1]
    nonce = envelope[1 : 1 + NONCE_LEN]
    derived_here = vector.get("nonce_derived", deterministic)
    if deterministic != (vector.get("kind") == "det"):
        raise ValueError(f"version byte 0x{version:02x} disagrees with kind {vector.get('kind')}")
    if derived_here and not deterministic:
        raise ValueError("only a det vector can have a derived nonce")
    if plaintext != field(vector, "plaintext_hex"):
        raise ValueError("the opened plaintext is not plaintext_hex")
    if nonce != field(vector, "nonce_hex"):
        raise ValueError("nonce_hex is not the nonce in the envelope")
    if classify(plaintext) != vector.get("plaintext_class"):
        raise ValueError(f"plaintext_class should be {classify(plaintext)}")
    if deterministic:
        nonce_key, derived = derive_nonce(key, bytes([version]) + aad, plaintext)
        if nonce_key != field(vector, "nonce_key_hex"):
            raise ValueError("nonce_key_hex is not HMAC-SHA256(key, label)")
        if (derived == nonce) != derived_here:
            raise ValueError("the nonce and nonce_derived disagree with spec 1.8")
    if seal(version, key, nonce, aad, plaintext) != envelope:
        raise ValueError("sealing the same inputs does not give envelope_hex")


def check_file(document: Any) -> list[str]:
    """Every vector on its own, then what the file as a whole must hold."""
    if not isinstance(document, dict) or type(document.get("version")) is not int:
        return ["file: not an object with an integer version"]
    vectors = document.get("vectors")
    if document["version"] != 1 or not isinstance(vectors, list) or not vectors:
        return ["file: version is not 1, or there are no vectors"]
    if document.get("det_nonce_label") != LABEL.decode("ascii"):
        return ["file: det_nonce_label is not the label of spec 1.8"]
    if not re.fullmatch(r"[0-9a-f]{64}", str(document.get("nist_source", {}).get("sha256"))):
        return ["file: nist_source.sha256 is not a SHA-256"]
    names = [v.get("id") if isinstance(v, dict) else None for v in vectors]
    if any(not isinstance(n, str) or not n for n in names) or len(set(names)) != len(names):
        return ["file: every vector needs an id of its own"]

    by_id: dict[str, Vector] = {v["id"]: v for v in vectors}
    problems: list[str] = []
    for vector in vectors:
        try:
            if vector.get("kind") == "nist":
                check_nist(vector)
            elif vector.get("kind") in ("random", "det"):
                check_envelope(vector, by_id)
            else:
                raise ValueError(f"unknown kind {vector.get('kind')!r}")
        except ValueError as error:
            problems.append(f"{vector['id']}: {error}")
    if problems:
        return problems

    # A file that leaves a named vector, a suite or a plaintext class out proves nothing about it.
    ok = [v for v in vectors if v["kind"] != "nist" and v["expect"] == "ok"]
    for name in REQUIRED:
        if name not in by_id:
            problems.append(f"coverage: the vector {name} is missing")
    for version in sorted(set(SUITES) - {bytes.fromhex(v["envelope_hex"])[0] for v in ok}):
        problems.append(f"coverage: no ok vector for version byte 0x{version:02x}")
    for plaintext_class in sorted(CLASSES - {v["plaintext_class"] for v in ok}):
        problems.append(f"coverage: no ok vector with plaintext_class {plaintext_class}")
    for size in sorted(KEY_LENGTHS):
        count = sum(1 for v in vectors if v["kind"] == "nist" and len(v["key_hex"]) == 2 * size)
        if count < NIST_PER_KEY_LENGTH:
            problems.append(f"coverage: {count} nist vectors for a {size}-byte key")
    for outcome in sorted(OUTCOMES - {v["expect"] for v in vectors if v["kind"] != "nist"}):
        problems.append(f"coverage: no vector expects {outcome}")
    return problems or check_shapes(by_id)


def check_shapes(by_id: dict[str, Vector]) -> list[str]:
    """A required vector must be the case its name says, not merely carry the name."""

    def raw(vector: Vector, member: str = "envelope_hex") -> bytes:
        return bytes.fromhex(vector[member])

    def base(vector: Vector) -> Vector:
        return by_id[vector["derived_from"]]

    def same(vector: Vector, *members: str) -> bool:
        return all(vector[m] == base(vector)[m] for m in members)

    def cut(vector: Vector, length: int) -> bool:
        return same(vector, "key_hex", "aad_hex") and raw(vector) == raw(base(vector))[:length]

    def relabelled(vector: Vector, version: int) -> bool:
        theirs = raw(base(vector))
        same_inputs = same(vector, "key_hex", "aad_hex")
        return same_inputs and theirs[0] != version and raw(vector) == bytes([version]) + theirs[1:]

    def flipped(vector: Vector, offset: int) -> bool:
        theirs = bytearray(raw(base(vector)))
        theirs[offset] ^= 0x01
        return same(vector, "key_hex", "aad_hex") and raw(vector) == bytes(theirs)

    def key_length(vector: Vector) -> int:
        return len(raw(vector, "key_hex"))

    def suite_key(envelope: bytes) -> int:
        return SUITES[envelope[0]][0]

    shapes: dict[str, Callable[[Vector], bool]] = {
        "version-02-as-03": lambda v: relabelled(v, 0x03),
        "version-03-as-02": lambda v: relabelled(v, 0x02),
        "version-04-as-05": lambda v: relabelled(v, 0x05),
        "version-06-as-07": lambda v: relabelled(v, 0x07),
        "version-01-reserved": lambda v: relabelled(v, 0x01),
        "tag-last-bit-flipped": lambda v: flipped(v, -1),
        "ciphertext-first-bit-flipped": lambda v: flipped(v, 1 + NONCE_LEN),
        "nonce-first-bit-flipped": lambda v: flipped(v, 1),
        "key-different": lambda v: (
            same(v, "aad_hex", "envelope_hex")
            and not same(v, "key_hex")
            and key_length(v) == key_length(base(v))
        ),
        "aad-missing": lambda v: same(v, "key_hex", "envelope_hex") and not v["aad_hex"],
        "aad-different": lambda v: (
            same(v, "key_hex", "envelope_hex") and bool(v["aad_hex"]) and not same(v, "aad_hex")
        ),
        "aad-unexpected": lambda v: (
            same(v, "key_hex", "envelope_hex") and bool(v["aad_hex"]) and not base(v)["aad_hex"]
        ),
        "last-byte-dropped": lambda v: cut(v, len(raw(base(v))) - 1),
        "one-byte-appended": lambda v: (
            same(v, "key_hex", "aad_hex") and raw(v)[:-1] == raw(base(v)) and len(raw(v)) > 0
        ),
        "envelope-empty": lambda v: cut(v, 0),
        "envelope-one-byte": lambda v: cut(v, 1),
        "envelope-12-bytes": lambda v: cut(v, 12),
        "envelope-28-bytes": lambda v: cut(v, 28),
        "key-16-bytes-for-aes-256": lambda v: (
            same(v, "aad_hex", "envelope_hex") and key_length(v) == 16 and suite_key(raw(v)) == 32
        ),
        # Two faults each, so that only the order of spec 1.7 gives the stated outcome.
        "precedence-key-length-before-envelope": lambda v: (
            key_length(v) not in KEY_LENGTHS and len(raw(v)) < OVERHEAD
        ),
        "precedence-envelope-before-suite": lambda v: (
            len(raw(v)) >= OVERHEAD
            and raw(v)[0] not in SUITES
            and key_length(v) in KEY_LENGTHS
            and key_length(v) != suite_key(raw(base(v)))
        ),
        "precedence-short-envelope-before-suite": lambda v: (
            0 < len(raw(v)) < OVERHEAD
            and raw(v)[0] in SUITES
            and key_length(v) in KEY_LENGTHS
            and key_length(v) != suite_key(raw(v))
        ),
        "det-256-nonce-not-derived": lambda v: v.get("nonce_derived") is False,
    }
    return [
        f"{name}: is not the case its name says"
        for name, holds in shapes.items()
        if name in by_id and not holds(by_id[name])
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--vectors", type=Path, default=ROOT / "spec" / "test-vectors.json")
    args = parser.parse_args()

    document = json.loads(args.vectors.read_text(encoding="utf-8"))
    problems = check_file(document)

    for problem in problems:
        print(problem)
    if problems:
        print(f"check-vectors: {len(problems)} problem(s)", file=sys.stderr)
        return 1
    kinds = ("nist", "random", "det")
    count = {k: sum(1 for v in document["vectors"] if v["kind"] == k) for k in kinds}
    print(
        f"check-vectors: ok ({len(document['vectors'])} vectors: "
        f"{count['nist']} nist, {count['random']} random, {count['det']} det)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
