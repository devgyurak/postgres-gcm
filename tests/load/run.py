#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Load harness: decrypt + LIKE at scale, gated as a ratio against pgcrypto.

Rows of Korean names are sealed twice in one table, by `gcm_encrypt` (AES-256-GCM, random
nonce) and by pgcrypto's `encrypt_iv(..., 'aes-cbc')`. For each row count and each session
count the harness times, interleaved so that neither query owns the machine, the scan
`gcm_decrypt(name_enc, $1) LIKE '%김%'` against
`convert_from(decrypt_iv(name_cbc, $1, $2, 'aes-cbc'), 'UTF8') LIKE '%김%'`, and reports the
p95 of each and their ratio. The gate is the worst ratio (GCM over pgcrypto) over the gated
cells, never a number of milliseconds, so it is portable across machines; the ceiling lives in
tests/load/baseline.json, written from measurements (docs/perf.md).

`gated_sessions` in the baseline names the session counts the gate applies to. A cell at many
sessions on few rows is saturated: a whole scan is a few milliseconds, so under 32 concurrent
sessions the p95 is scheduling tail rather than crypto and the ratio converges to 1.0 whatever
the code does (local runs of the 10k × 32 cell ran 0.77–1.03). Those cells are still measured and
reported, but only the low-concurrency cells — where the crypto dominates — are gated.

The key is the public 00..1f pattern and travels only as a bind parameter
(docs/ops-constraints.md item 1). JIT is off and no parallel workers are used, as in the Phase S
measurement, so the two plans have the same shape (docs/design.md section 8). Each cell collects
about `samples` scans per query across the sessions, so the p95 is a percentile even at one
session.

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
    # Match the Phase S methodology (docs/design.md §8), so the two plans have the same shape and
    # the ratio is crypto against crypto. gcm_decrypt's declared COST (50) otherwise earns it a
    # parallel gather at 100k rows that decrypt_iv's COST (1) does not, which flatters GCM.
    conn.execute("SET jit = off")
    conn.execute("SET max_parallel_workers_per_gather = 0")
    return conn


def p95(samples: list[float]) -> float:
    """The 95th percentile, nearest-rank: the smallest value at or above 95% of the samples."""
    ordered = sorted(samples)
    rank = max(1, math.ceil(0.95 * len(ordered)))
    return ordered[rank - 1]


def ratio(gcm: float, pgcrypto: float) -> float:
    """GCM's p95 over pgcrypto's. GCM is the numerator, so a regression raises the ratio."""
    return gcm / pgcrypto if pgcrypto > 0 else math.inf


def rounds_for(sessions: int, samples: int) -> int:
    """Rounds so each query collects about `samples` samples.

    A round launches one scan per session, split across the two queries, so each query gets
    about `rounds * sessions / 2` samples; at one session that still needs `2 * samples`.
    """
    return max(1, math.ceil(2 * samples / sessions))


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
    # The Phase S measurement freezes and analyzes before timing (scripts/spike/measure.sql).
    conn.execute(f"VACUUM (ANALYZE, FREEZE) {table}")


def run_once(conn: Connection, table: str, which: str, pattern: str) -> tuple[float, int]:
    """One scan; returns its latency in seconds and the count it matched. GCM or pgcrypto."""
    sql = (GCM_SQL if which == "gcm" else CBC_SQL).format(table=table)
    started = time.perf_counter()
    row = conn.execute(sql, {"key": KEY, "pattern": pattern, "iv": IV}).fetchone()
    seconds = time.perf_counter() - started
    if row is None:
        raise RuntimeError("load: a scan returned no row")
    return seconds, int(row[0])


def measure_cell(rows: int, sessions: int, samples: int, pattern: str) -> dict[str, Any]:
    """Time both scans at one row count and one session count, interleaved.

    Each round launches `sessions` scans at once; session i runs GCM when (i + round) is
    even and pgcrypto otherwise, so over the rounds every session runs both, neither query
    owns the machine, and neither is measured only when the caches are warm. JIT is off and
    no parallel workers are used. One warm-up scan of each query is discarded first.
    """
    rounds = rounds_for(sessions, samples)
    table = f"load_names_{rows}"
    admin = connect()
    try:
        load_rows(admin, table, rows)
    finally:
        admin.close()
    conns = [connect() for _ in range(sessions)]
    timings: dict[str, list[float]] = {"gcm": [], "pgcrypto": []}
    counts: dict[str, list[int]] = {"gcm": [], "pgcrypto": []}
    try:
        # Discard one warm-up scan of each query: the first call reads the table cold.
        run_once(conns[0], table, "gcm", pattern)
        run_once(conns[0], table, "pgcrypto", pattern)
        with ThreadPoolExecutor(max_workers=sessions) as pool:
            for round_index in range(rounds):
                futures = []
                for session in range(sessions):
                    which = "gcm" if (session + round_index) % 2 == 0 else "pgcrypto"
                    futures.append(
                        (which, pool.submit(run_once, conns[session], table, which, pattern))
                    )
                for which, future in futures:
                    seconds, count = future.result()
                    timings[which].append(seconds)
                    counts[which].append(count)
    finally:
        for conn in conns:
            conn.close()
        cleanup = connect()
        try:
            cleanup.execute(f"DROP TABLE IF EXISTS {table}")
        finally:
            cleanup.close()

    # Both scans must match the same, non-zero rows every round. The gate is latency, not truth:
    # a gcm_decrypt that returned NULL for every row (e.g. pg_gcm.strict off) would make the GCM
    # scan cheaper and pass the ratio without decrypting anything.
    gcm_counts = set(counts["gcm"])
    cbc_counts = set(counts["pgcrypto"])
    if len(gcm_counts) != 1 or gcm_counts != cbc_counts or 0 in gcm_counts:
        raise RuntimeError("load: the two scans did not match the same non-zero rows each round")

    gcm_p95 = p95(timings["gcm"])
    cbc_p95 = p95(timings["pgcrypto"])
    return {
        "rows": rows,
        "sessions": sessions,
        "rounds": rounds,
        "gcm_p95_ms": round(gcm_p95 * 1000, 4),
        "pgcrypto_p95_ms": round(cbc_p95 * 1000, 4),
        "ratio": ratio(gcm_p95, cbc_p95),
    }


def verdict(
    cells: list[dict[str, Any]], ceiling: float, gated_sessions: set[int]
) -> tuple[bool, float]:
    """The gate: every gated cell ran, and the worst GCM-over-pgcrypto ratio is at or under the ceiling.

    A cell whose session count is not in `gated_sessions` is saturated (see the module docstring)
    and is recorded but not gated, so it cannot fail the gate on scheduling noise.
    """
    gated = [cell for cell in cells if cell["sessions"] in gated_sessions]
    if not gated:
        # A gate that measured nothing is the same failure as one that failed.
        return False, math.inf
    worst = max(cell["ratio"] for cell in gated)
    return worst <= ceiling, worst


def load_baseline(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        baseline: dict[str, Any] = json.load(handle)
    return baseline


def self_test() -> int:
    """The gate and the ratio direction against cases whose verdict is known. Needs no server."""
    cases: list[tuple[str, list[dict[str, Any]], float, set[int], bool]] = [
        ("a gated ratio below the ceiling", [{"sessions": 1, "ratio": 0.5}], 1.0, {1, 8}, True),
        ("a gated ratio at the ceiling", [{"sessions": 8, "ratio": 1.0}], 1.0, {1, 8}, True),
        ("a gated ratio above the ceiling", [{"sessions": 1, "ratio": 1.5}], 1.0, {1, 8}, False),
        (
            "the worst of several gated cells",
            [{"sessions": 1, "ratio": 0.5}, {"sessions": 8, "ratio": 1.5}],
            1.0,
            {1, 8},
            False,
        ),
        # A saturated cell is recorded, never gated, however high its ratio sits.
        (
            "a saturated cell does not gate",
            [{"sessions": 1, "ratio": 0.5}, {"sessions": 32, "ratio": 1.5}],
            1.0,
            {1, 8},
            True,
        ),
        (
            "only a saturated cell was measured",
            [{"sessions": 32, "ratio": 0.5}],
            1.0,
            {1, 8},
            False,
        ),
        ("no cell measured", [], 1.0, {1, 8}, False),
    ]
    verdicts = [
        (name, verdict(cells, ceiling, gated)[0], want)
        for name, cells, ceiling, gated, want in cases
    ]
    # The ratio's direction: GCM is the numerator, so twice pgcrypto is 2.0 and fails, not 0.5.
    directions = [
        ("the two sides equal is 1.0", ratio(1.0, 1.0), 1.0),
        ("GCM twice pgcrypto is 2.0", ratio(2.0, 1.0), 2.0),
        ("GCM half pgcrypto is 0.5", ratio(1.0, 2.0), 0.5),
    ]
    wrong = [name for name, got, want in verdicts if got != want]
    wrong += [name for name, got, want in directions if got != want]
    total = len(verdicts) + len(directions)
    print(
        f"load self-test: {total - len(wrong)} of {total} verdicts as expected; wrong: {wrong}",
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
    parser.add_argument(
        "--samples", type=int, help="scans per query per cell (default: baseline.json)"
    )
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
    samples = args.samples if args.samples is not None else int(baseline["samples"])
    pattern = str(baseline.get("pattern", PATTERN))
    # Absent `gated_sessions`, every session gates (a caller that overrides --sessions still gates).
    gated_sessions = {int(value) for value in baseline.get("gated_sessions", sessions)}

    cells = []
    for count in rows:
        for session_count in sessions:
            cell = measure_cell(count, session_count, samples, pattern)
            cell["gated"] = session_count in gated_sessions
            cells.append(cell)
            print(
                f"{count:>7} rows, {session_count:>2} sessions: {cell['ratio']:.3f}"
                f" ({'gated' if cell['gated'] else 'recorded'})"
                f" (gcm {cell['gcm_p95_ms']} ms vs pgcrypto {cell['pgcrypto_p95_ms']} ms)",
                file=sys.stderr,
            )

    passed, worst = verdict(cells, ceiling, gated_sessions)
    if not any(cell["gated"] for cell in cells):
        print(
            "load: no gated session was measured — --sessions must include one of "
            f"{sorted(gated_sessions)} for the gate to apply",
            file=sys.stderr,
        )
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
        f"load: worst gated ratio {worst:.3f} against a ceiling of {ceiling}; gate: {passed}",
        file=sys.stderr,
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
