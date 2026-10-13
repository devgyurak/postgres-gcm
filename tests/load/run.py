#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Load harness: decrypt + LIKE at scale, gated as a ratio against pgcrypto.

Rows of Korean names are sealed twice in one table, by `gcm_encrypt` (AES-256-GCM, random
nonce) and by pgcrypto's `encrypt_iv(..., 'aes-cbc')`. For each row count and each session
count the harness times, interleaved so that neither query owns the machine, the scan
`gcm_decrypt(name_enc, $1) LIKE '%김%'` against
`convert_from(decrypt_iv(name_cbc, $1, $2, 'aes-cbc'), 'UTF8') LIKE '%김%'`, and reports the
p95 of each and their ratio. The gate is the worst ratio (GCM over pgcrypto) over every cell,
never a number of milliseconds, so it is portable across machines; the ceiling lives in
tests/load/baseline.json, written from measurements (docs/perf.md).

The key is the public 00..1f pattern and travels only as a bind parameter (design section 6,
item 1). JIT is off, as in the Phase S measurement (docs/design.md section 8).

    python tests/load/run.py --rows 100000 --baseline pgcrypto
    python tests/load/run.py --self-test        # check the gate; no server

Connection details come from the PG* variables (PGHOST, PGPORT, PGUSER, PGPASSWORD,
PGDATABASE). The results go to stdout as JSON, one line per cell to stderr, and the exit
status is the gate: 0 only when every cell ran and the worst ratio was at or under the ceiling.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import psycopg

Row = tuple[Any, ...]
Connection = psycopg.Connection[Row]

ROOT = Path(__file__).resolve().parent.parent.parent
BASELINE = Path(__file__).resolve().parent / "baseline.json"

# The public 00..1f pattern key (.agents/rules/testing.md). Never a real key.
KEY = bytes(range(32))
IV = bytes(range(16))
# Three of the ten names contain 김; the pattern travels as a bind parameter.
PATTERN = "%김%"
NAMES = (
    "김철수",
    "이영희",
    "박민준",
    "최지우",
    "정길동",
    "홍길동",
    "김서연",
    "강감찬",
    "윤아름",
    "김민수",
)

GCM_SQL = "SELECT count(*) FROM {table} WHERE gcm_decrypt(name_enc, %(key)s) LIKE %(pattern)s"
CBC_SQL = (
    "SELECT count(*) FROM {table}"
    " WHERE convert_from(decrypt_iv(name_cbc, %(key)s, %(iv)s, 'aes-cbc'), 'UTF8')"
    " LIKE %(pattern)s"
)
NAMES_ARRAY = ", ".join(f"'{name}'" for name in NAMES)


def connect() -> Connection:
    """A session. User, password and database come from the PG* variables."""
    conn = psycopg.connect(autocommit=True)
    # Match the Phase S methodology and keep the two scans comparable (docs/design.md section 8).
    conn.execute("SET jit = off")
    return conn


def p95(samples: list[float]) -> float:
    """The 95th percentile, nearest-rank: the smallest value at or above 95% of the samples."""
    ordered = sorted(samples)
    rank = max(1, math.ceil(0.95 * len(ordered)))
    return ordered[rank - 1]


def load_rows(conn: Connection, table: str, rows: int) -> None:
    """Create the table and seal every name twice: GCM and pgcrypto AES-CBC, same key."""
    conn.execute("CREATE EXTENSION IF NOT EXISTS pg_gcm")
    conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    conn.execute(f"DROP TABLE IF EXISTS {table}")
    conn.execute(
        f"CREATE TABLE {table} (id integer PRIMARY KEY, name_enc bytea NOT NULL,"
        " name_cbc bytea NOT NULL)"
    )
    conn.execute(
        f"INSERT INTO {table} (id, name_enc, name_cbc)"
        " SELECT i, gcm_encrypt(n, %(key)s),"
        " encrypt_iv(convert_to(n, 'UTF8'), %(key)s, %(iv)s, 'aes-cbc')"
        f" FROM (SELECT i, (ARRAY[{NAMES_ARRAY}])[1 + mod(i - 1, 10)] AS n"
        " FROM generate_series(1, %(rows)s) AS i) AS s",
        {"key": KEY, "iv": IV, "rows": rows},
    )


def run_once(conn: Connection, table: str, which: str, pattern: str) -> float:
    """One scan; returns its latency in seconds. GCM or pgcrypto, by `which`."""
    sql = (GCM_SQL if which == "gcm" else CBC_SQL).format(table=table)
    started = time.perf_counter()
    conn.execute(sql, {"key": KEY, "pattern": pattern, "iv": IV})
    return time.perf_counter() - started


def measure_cell(rows: int, sessions: int, rounds: int, pattern: str) -> dict[str, Any]:
    """Time both scans at one row count and one session count, interleaved.

    Each round launches `sessions` scans at once; session i runs GCM when (i + round) is
    even and pgcrypto otherwise, so over the rounds every session runs both, neither query
    owns the machine, and neither is measured only when the caches are warm. JIT is off.
    """
    table = f"load_names_{rows}"
    admin = connect()
    try:
        load_rows(admin, table, rows)
    finally:
        admin.close()
    conns = [connect() for _ in range(sessions)]
    samples: dict[str, list[float]] = {"gcm": [], "pgcrypto": []}
    try:
        with ThreadPoolExecutor(max_workers=sessions) as pool:
            for round_index in range(rounds):
                futures = []
                for session in range(sessions):
                    which = "gcm" if (session + round_index) % 2 == 0 else "pgcrypto"
                    futures.append(
                        (which, pool.submit(run_once, conns[session], table, which, pattern))
                    )
                for which, future in futures:
                    samples[which].append(future.result())
    finally:
        for conn in conns:
            conn.close()
        cleanup = connect()
        try:
            cleanup.execute(f"DROP TABLE IF EXISTS {table}")
        finally:
            cleanup.close()

    gcm_p95 = p95(samples["gcm"])
    cbc_p95 = p95(samples["pgcrypto"])
    return {
        "rows": rows,
        "sessions": sessions,
        "rounds": rounds,
        "gcm_p95_ms": round(gcm_p95 * 1000, 4),
        "pgcrypto_p95_ms": round(cbc_p95 * 1000, 4),
        "ratio": gcm_p95 / cbc_p95 if cbc_p95 > 0 else math.inf,
    }


def verdict(cells: list[dict[str, Any]], ceiling: float) -> tuple[bool, float]:
    """The gate: every cell ran, and the worst GCM-over-pgcrypto ratio is at or under the ceiling."""
    if not cells:
        # A gate that measured nothing is the same failure as one that failed.
        return False, math.inf
    worst = max(cell["ratio"] for cell in cells)
    return worst <= ceiling, worst


def load_baseline(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        baseline: dict[str, Any] = json.load(handle)
    return baseline


def self_test() -> int:
    """The gate against cells whose verdict is known. Needs no server."""
    cases: list[tuple[str, list[dict[str, Any]], float, bool]] = [
        ("a ratio below the ceiling", [{"ratio": 0.5}], 1.0, True),
        ("a ratio at the ceiling", [{"ratio": 1.0}], 1.0, True),
        ("a ratio above the ceiling", [{"ratio": 1.5}], 1.0, False),
        ("the worst of several cells", [{"ratio": 0.5}, {"ratio": 1.5}], 1.0, False),
        ("no cell measured", [], 1.0, False),
    ]
    verdicts = [(name, verdict(cells, ceiling)[0], want) for name, cells, ceiling, want in cases]
    wrong = [name for name, got, want in verdicts if got != want]
    print(
        f"load self-test: {len(verdicts) - len(wrong)} of {len(verdicts)} verdicts as expected;"
        f" wrong: {wrong}",
        file=sys.stderr,
    )
    return 0 if not wrong else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument(
        "--baseline",
        default="pgcrypto",
        choices=["pgcrypto"],
        help="what the GCM scan is compared against (default: %(default)s)",
    )
    parser.add_argument("--rows", help="comma-separated row counts (default: baseline.json)")
    parser.add_argument(
        "--sessions", help="comma-separated session counts (default: baseline.json)"
    )
    parser.add_argument("--rounds", type=int, help="rounds per cell (default: baseline.json)")
    parser.add_argument("--gate", default=str(BASELINE), help="the ratio gate file")
    parser.add_argument("--self-test", action="store_true", help="check the gate; no server")
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    baseline = load_baseline(Path(args.gate))
    ceiling = float(baseline["max_ratio"])
    rows = [int(value) for value in (args.rows or ",".join(map(str, baseline["rows"]))).split(",")]
    sessions = [
        int(value)
        for value in (args.sessions or ",".join(map(str, baseline["sessions"]))).split(",")
    ]
    rounds = args.rounds if args.rounds is not None else int(baseline["rounds"])
    pattern = str(baseline.get("pattern", PATTERN))

    cells = []
    for count in rows:
        for session_count in sessions:
            cell = measure_cell(count, session_count, rounds, pattern)
            cells.append(cell)
            print(
                f"{count:>7} rows, {session_count:>2} sessions: {cell['ratio']:.3f}"
                f" (gcm {cell['gcm_p95_ms']} ms vs pgcrypto {cell['pgcrypto_p95_ms']} ms)",
                file=sys.stderr,
            )

    passed, worst = verdict(cells, ceiling)
    json.dump(
        {
            "baseline": args.baseline,
            "gate": passed,
            "ceiling": ceiling,
            "worst_ratio": None if math.isinf(worst) else round(worst, 4),
            "cells": cells,
        },
        sys.stdout,
        ensure_ascii=False,
        indent=2,
    )
    sys.stdout.write("\n")
    print(
        f"load: worst ratio {worst:.3f} against a ceiling of {ceiling}; gate: {passed}",
        file=sys.stderr,
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
