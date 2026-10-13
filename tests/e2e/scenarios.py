# SPDX-License-Identifier: PostgreSQL
"""The end-to-end scenarios: a primary and a streaming replica, reached over SQL alone.

Every scenario is Given-When-Then, in its name and in its body, and no test body branches or
loops. The shared Given is built once on the primary (set_up_cluster) and has reached the
replica before any test runs; a scenario that holds on both nodes is written once, in a
mixin, and run by a class for each node.

Nothing here encrypts or decrypts: the runner only issues SQL, and keys travel as bind
parameters, never in the statement text (docs/design.md section 6, item 1).
"""

from __future__ import annotations

import os
import time
import unittest
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

import psycopg

Row = tuple[Any, ...]
Connection = psycopg.Connection[Row]

# How long the replica is given to replay what the primary committed; run.py may change it.
replay_timeout = 30.0


def connect(node: str) -> Connection:
    """A session on one node. User, password and database come from the PG* variables."""
    return psycopg.connect(host=os.environ[f"PG_GCM_E2E_{node.upper()}"], autocommit=True)


def wait_for_replay(primary: Connection, replica: Connection) -> None:
    """Return once the replica has replayed everything the primary has written so far."""
    target = primary.execute("SELECT pg_current_wal_insert_lsn()").fetchone()
    assert target is not None
    deadline = time.monotonic() + replay_timeout
    while time.monotonic() < deadline:
        replayed = replica.execute(
            "SELECT pg_last_wal_replay_lsn() >= %s::pg_lsn", (str(target[0]),)
        ).fetchone()
        if replayed == (True,):
            return
        time.sleep(0.1)
    raise TimeoutError(f"the replica did not replay up to {target[0]} in {replay_timeout} s")


def set_up_cluster() -> None:
    """The shared Given: the extension, created on the primary only."""
    with connect("primary") as primary, connect("replica") as replica:
        primary.execute("CREATE EXTENSION IF NOT EXISTS pg_gcm")
        wait_for_replay(primary, replica)


class Scenario(unittest.TestCase):
    """A session on the node a subclass names, opened for each test and closed after it."""

    node: ClassVar[str]
    db: Connection

    def setUp(self) -> None:
        self.db = connect(self.node)
        self.addCleanup(self.db.close)

    def rows(self, query: str, parameters: Sequence[Any] | Mapping[str, Any] = ()) -> list[Row]:
        return self.db.execute(query, parameters).fetchall()


class Replication(Scenario):
    """That the second node really is a streaming replica: the rest means nothing otherwise."""

    node = "replica"

    def test_given_the_replica_when_its_state_is_read_then_it_is_a_standby_streaming_from_the_primary(
        self,
    ) -> None:
        # Given: the replica, started from a base backup of the primary

        # When
        state = self.rows(
            "SELECT pg_is_in_recovery(), status, sender_host FROM pg_stat_wal_receiver"
        )

        # Then
        self.assertEqual(state, [(True, "streaming", "primary")])

    def test_given_the_extension_created_on_the_primary_when_the_replica_catalog_is_read_then_it_is_there(
        self,
    ) -> None:
        # Given: CREATE EXTENSION ran on the primary alone; the replica has the library on disk

        # When
        installed = self.rows("SELECT extversion FROM pg_extension WHERE extname = 'pg_gcm'")

        # Then: the catalog entry arrived through WAL (design section 6, item 7)
        self.assertEqual(installed, [("0.1.0",)])
