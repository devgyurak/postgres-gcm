#!/usr/bin/env python3
# SPDX-License-Identifier: PostgreSQL
"""Run the end-to-end scenarios (scenarios.py) against a primary and a streaming replica.

The servers are named by PG_GCM_E2E_PRIMARY and PG_GCM_E2E_REPLICA; user, password and
database come from the PG* variables libpq reads. tests/e2e/compose.yml sets all of them.

The results go to stdout as JSON, one line per scenario to stderr as it finishes, and the
exit status is the gate: 0 only when every scenario that unittest ran is one this runner
recorded as passed, at least one ran, and the scenarios shared by the two nodes are the same
non-empty set on each. A scenario that was skipped has not passed. When the shared Given
cannot be built, the JSON says so and the gate is closed.

    run.py --self-test    check the gate itself, with no server: it must refuse a failure, an
                          error, a skip, a failing subtest, an expected failure, an unexpected
                          success and an empty run, refuse two classes whose scenarios differ
                          or are none, and accept a run that passed and two classes that agree
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


def same_scenarios(one: type[unittest.TestCase], other: type[unittest.TestCase]) -> bool:
    """Two classes give the loader the same scenarios, and not none.

    The scenarios shared by the two nodes reach the loader through a class per node; one
    that dropped out of either would otherwise be missed, not failed.
    """
    names = unittest.defaultTestLoader.getTestCaseNames
    return len(names(one)) > 0 and names(one) == names(other)


class _Passes(unittest.TestCase):
    def test_passes(self) -> None:
        self.assertTrue(True)


class _Fails(unittest.TestCase):
    def test_fails(self) -> None:
        self.assertTrue(False)


class _Errors(unittest.TestCase):
    def test_errors(self) -> None:
        raise RuntimeError("an error, not a failure")


class _Skips(unittest.TestCase):
    @unittest.skip("a skipped scenario has not passed")
    def test_skips(self) -> None:
        self.assertTrue(True)


class _FailsInASubtest(unittest.TestCase):
    def test_fails_in_a_subtest(self) -> None:
        with self.subTest("the part that fails"):
            self.assertTrue(False)


class _FailsAsExpected(unittest.TestCase):
    # unittest calls this a success; it reaches none of the recorder's hooks, so the count
    # of what was recorded falls short of what ran. A scenario marked so has not passed.
    @unittest.expectedFailure
    def test_fails_as_expected(self) -> None:
        self.assertTrue(False)


class _SucceedsUnexpectedly(unittest.TestCase):
    @unittest.expectedFailure
    def test_succeeds_unexpectedly(self) -> None:
        self.assertTrue(True)


def self_test() -> int:
    """The gate against runs whose verdict is known. Needs no server."""
    load = unittest.defaultTestLoader.loadTestsFromTestCase
    expected = [
        (_Passes, True),
        (_Fails, False),
        (_Errors, False),
        (_Skips, False),
        (_FailsInASubtest, False),
        (_FailsAsExpected, False),
        (_SucceedsUnexpectedly, False),
    ]
    verdicts = [(case.__name__, gate(load(case))[1], want) for case, want in expected]
    verdicts.append(("an empty run", gate(unittest.TestSuite())[1], False))
    # The other half of the gate: classes that agree, that differ, and that have nothing.
    verdicts.append(("the same scenarios", same_scenarios(_Passes, _Passes), True))
    verdicts.append(("different scenarios", same_scenarios(_Passes, _Fails), False))
    verdicts.append(("no scenarios", same_scenarios(unittest.TestCase, unittest.TestCase), False))
    verdicts.append(
        ("the two nodes", same_scenarios(scenarios.OnThePrimary, scenarios.OnTheReplica), True)
    )
    wrong = [name for name, got, want in verdicts if got != want]
    print(
        f"end-to-end self-test: {len(verdicts) - len(wrong)} of {len(verdicts)} verdicts"
        f" as expected; wrong: {wrong}",
        file=sys.stderr,
    )
    return 0 if not wrong else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument(
        "--replay-timeout",
        type=float,
        default=scenarios.replay_timeout,
        help="seconds the replica is given to replay the primary's writes (default: %(default)s)",
    )
    parser.add_argument("--self-test", action="store_true", help="check the gate; no server")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    scenarios.replay_timeout = args.replay_timeout

    try:
        scenarios.set_up_cluster()
    except Exception as error:  # noqa: BLE001  # whatever stopped the Given, the result is JSON
        json.dump(
            {"passed": 0, "total": 0, "gate": False, "setup_error": repr(error), "scenarios": []},
            sys.stdout,
            ensure_ascii=False,
            indent=2,
        )
        sys.stdout.write("\n")
        print(f"end-to-end: the shared Given could not be built: {error!r}", file=sys.stderr)
        return 1
    recorder, verdict = gate(unittest.defaultTestLoader.loadTestsFromModule(scenarios))
    verdict = verdict and same_scenarios(scenarios.OnThePrimary, scenarios.OnTheReplica)

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
