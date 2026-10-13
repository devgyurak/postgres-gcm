#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Run the end-to-end scenarios (scenarios.py) against a primary and a streaming replica.

The servers are named by PG_GCM_E2E_PRIMARY and PG_GCM_E2E_REPLICA; user, password and
database come from the PG* variables libpq reads. tests/e2e/compose.yml sets all of them.

The results go to stdout as JSON, one line per scenario to stderr as it finishes, and the
exit status is the gate: 0 only when every scenario that unittest ran is one this runner
recorded as passed, and at least one ran. A scenario that was skipped has not passed.
"""

from __future__ import annotations

import argparse
import json
import sys
import unittest
from typing import Any

import scenarios


class Recorder(unittest.TestResult):
    """Collects one outcome per scenario and says so on stderr as it goes."""

    def __init__(self) -> None:
        super().__init__()
        self.outcomes: list[dict[str, str]] = []

    def record(self, test: unittest.TestCase, outcome: str, detail: str = "") -> None:
        name = test.id().removeprefix("scenarios.")
        self.outcomes.append({"scenario": name, "outcome": outcome, "detail": detail})
        print(f"{outcome:5} {name}", file=sys.stderr)
        if detail:
            print(detail, file=sys.stderr)

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self.record(test, "ok")

    def addFailure(self, test: unittest.TestCase, err: Any) -> None:
        super().addFailure(test, err)
        self.record(test, "FAIL", self.failures[-1][1])

    def addError(self, test: unittest.TestCase, err: Any) -> None:
        super().addError(test, err)
        self.record(test, "ERROR", self.errors[-1][1])

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self.record(test, "SKIP", reason)


def gate(suite: unittest.TestSuite) -> tuple[Recorder, bool]:
    """Run a suite; the verdict is True only when all of it ran, was recorded, and passed."""
    recorder = Recorder()
    suite.run(recorder)
    passed = sum(1 for outcome in recorder.outcomes if outcome["outcome"] == "ok")
    # testsRun and wasSuccessful also see what the four hooks above do not: a failing
    # subtest, an unexpected success. A gate that ran nothing is a failure too.
    verdict = (
        recorder.testsRun > 0
        and passed == len(recorder.outcomes) == recorder.testsRun
        and recorder.wasSuccessful()
    )
    return recorder, verdict


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument(
        "--replay-timeout",
        type=float,
        default=scenarios.replay_timeout,
        help="seconds the replica is given to replay the primary's writes (default: %(default)s)",
    )
    args = parser.parse_args()
    scenarios.replay_timeout = args.replay_timeout

    scenarios.set_up_cluster()
    recorder, verdict = gate(unittest.defaultTestLoader.loadTestsFromModule(scenarios))

    passed = sum(1 for outcome in recorder.outcomes if outcome["outcome"] == "ok")
    json.dump(
        {
            "passed": passed,
            "total": recorder.testsRun,
            "gate": verdict,
            "scenarios": recorder.outcomes,
        },
        sys.stdout,
        ensure_ascii=False,
        indent=2,
    )
    sys.stdout.write("\n")
    print(
        f"end-to-end: {passed} of {recorder.testsRun} scenarios passed; gate: {verdict}",
        file=sys.stderr,
    )
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
