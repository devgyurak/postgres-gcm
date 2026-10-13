# SPDX-License-Identifier: PostgreSQL
"""The end-to-end scenarios: a primary and a streaming replica, reached over SQL alone.

Every scenario is Given-When-Then, in its name and in its body, and no test body branches or
loops. The shared Given is built once on the primary (set_up_cluster) and has reached the
replica before any test runs; a scenario that holds on both nodes is written once, in a
mixin, and run by a class for each node.

Nothing here encrypts or decrypts: the runner only issues SQL, and keys travel as bind
parameters, never in the statement text (docs/ops-constraints.md item 1).
"""

from __future__ import annotations

import os
import time
import unittest
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, ClassVar

import psycopg

Row = tuple[Any, ...]
Connection = psycopg.Connection[Row]

# The public 00..1f pattern key (.agents/rules/testing.md). Never a real key.
KEY = bytes(range(32))
NAME_AAD = b"people.name"
CODE_AAD = b"people.code"

# id, name, member code. Two of the names contain 길.
PEOPLE = [(1, "홍길동", "M-0001"), (2, "김영희", "M-0002"), (3, "길동이", "M-0003")]
# person's member code, note. Two visits for M-0001, one for M-0002, none for M-0003.
VISITS = [("M-0001", "first visit"), ("M-0001", "second visit"), ("M-0002", "first visit")]

# How long the replica is given to replay what the primary committed; run.py may change it.
replay_timeout = 30.0


def connect(node: str) -> Connection:
    """A session on one node. User, password and database come from the PG* variables."""
    return psycopg.connect(host=os.environ[f"PG_GCM_E2E_{node.upper()}"], autocommit=True)


def wait_for_replay(primary: Connection, replica: Connection) -> None:
    """Return once the replica has replayed everything the primary has written so far.

    And once its WAL receiver reports streaming: a receiver that has just connected passes
    through other states first, and the scenario that asserts the state should not meet them.
    A bounded wait on the cluster's state, before any scenario runs — not a retry of one.
    """
    target = primary.execute("SELECT pg_current_wal_insert_lsn()").fetchone()
    assert target is not None
    deadline = time.monotonic() + replay_timeout
    while time.monotonic() < deadline:
        ready = replica.execute(
            "SELECT pg_last_wal_replay_lsn() >= %s::pg_lsn"
            " AND EXISTS (SELECT FROM pg_stat_wal_receiver WHERE status = 'streaming')",
            (str(target[0]),),
        ).fetchone()
        if ready == (True,):
            return
        time.sleep(0.1)
    raise TimeoutError(
        f"the replica was not streaming and replayed up to {target[0]} in {replay_timeout} s"
    )


def set_up_cluster() -> None:
    """The shared Given: the extension and three tables, all written on the primary only."""
    with connect("primary") as primary, connect("replica") as replica:
        primary.execute("CREATE EXTENSION IF NOT EXISTS pg_gcm")
        primary.execute("DROP TABLE IF EXISTS e2e_visits, e2e_people, e2e_forged")
        primary.execute(
            "CREATE TABLE e2e_people (id int PRIMARY KEY, name_enc bytea NOT NULL,"
            " code_det bytea NOT NULL UNIQUE CHECK (get_byte(code_det, 0) = 3))"
        )
        primary.execute(
            "CREATE TABLE e2e_visits (person_code_det bytea NOT NULL, note_enc bytea NOT NULL)"
        )
        primary.execute("CREATE TABLE e2e_forged (id int PRIMARY KEY, name_enc bytea NOT NULL)")
        with primary.cursor() as cursor:
            cursor.executemany(
                "INSERT INTO e2e_people VALUES"
                " (%s, gcm_encrypt(%s::text, %s, %s), gcm_encrypt_det(%s::text, %s, %s))",
                [(i, name, KEY, NAME_AAD, code, KEY, CODE_AAD) for i, name, code in PEOPLE],
            )
            cursor.executemany(
                "INSERT INTO e2e_visits VALUES"
                " (gcm_encrypt_det(%s::text, %s, %s), gcm_encrypt(%s::text, %s))",
                [(code, KEY, CODE_AAD, note, KEY) for code, note in VISITS],
            )
        # The first person's envelope with the last bit of its tag flipped.
        primary.execute(
            "INSERT INTO e2e_forged SELECT id,"
            " set_byte(name_enc, octet_length(name_enc) - 1,"
            "          get_byte(name_enc, octet_length(name_enc) - 1) # 1)"
            " FROM e2e_people WHERE id = 1"
        )
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

    def test_given_the_replica_when_a_row_is_written_there_then_it_is_refused(self) -> None:
        # Given: the replica; every envelope it holds was therefore sealed on the primary
        forged = (4, b"\x02" + bytes(28))

        # When
        with self.assertRaises(psycopg.errors.ReadOnlySqlTransaction):
            self.db.execute("INSERT INTO e2e_forged VALUES (%s, %s)", forged)

        # Then: the transaction was refused as read-only (asserted by the block above)

    def test_given_the_extension_created_on_the_primary_when_the_replica_catalog_is_read_then_it_is_there(
        self,
    ) -> None:
        # Given: CREATE EXTENSION ran on the primary alone; the replica has the library on disk

        # When
        installed = self.rows("SELECT extversion FROM pg_extension WHERE extname = 'pg_gcm'")

        # Then: the catalog entry arrived through WAL (docs/ops-constraints.md item 7)
        self.assertEqual(installed, [("0.1.0",)])


# For the type checker the shared scenarios are a Scenario; for unittest's loader they are
# not a test case of their own, so they run only through the two classes that name a node.
if TYPE_CHECKING:
    _Shared = Scenario
else:
    _Shared = object


class OnEitherNode(_Shared):
    """Scenarios that must hold on the node that sealed the rows and on the one that did not."""

    def test_given_names_sealed_on_the_primary_when_decrypted_then_every_name_comes_back(
        self,
    ) -> None:
        # Given: three names sealed with a random nonce and an AAD, on the primary

        # When
        names = self.rows(
            "SELECT id, gcm_decrypt(name_enc, %s, %s) FROM e2e_people ORDER BY id",
            (KEY, NAME_AAD),
        )

        # Then
        self.assertEqual(names, [(1, "홍길동"), (2, "김영희"), (3, "길동이")])

    def test_given_names_sealed_on_the_primary_when_filtered_with_like_then_the_names_with_gil_match(
        self,
    ) -> None:
        # Given: three names sealed on the primary, two of which contain 길

        # When: the decrypted value is filtered with PostgreSQL's own LIKE
        matched = self.rows(
            "SELECT id FROM e2e_people WHERE gcm_decrypt(name_enc, %s, %s) LIKE %s ORDER BY id",
            (KEY, NAME_AAD, "%길%"),
        )

        # Then
        self.assertEqual(matched, [(1,), (3,)])

    def test_given_notes_sealed_without_an_aad_when_decrypted_by_the_two_argument_form_then_they_come_back(
        self,
    ) -> None:
        # Given: three visit notes sealed on the primary by the two-argument form

        # When
        notes = self.rows(
            "SELECT gcm_decrypt(note_enc, %s) AS note FROM e2e_visits ORDER BY note", (KEY,)
        )

        # Then
        self.assertEqual(notes, [("first visit",), ("first visit",), ("second visit",)])

    def test_given_a_code_sealed_deterministically_on_the_primary_when_sealed_again_here_then_the_envelopes_are_equal(
        self,
    ) -> None:
        # Given: M-0002 sealed with gcm_encrypt_det on the primary, under this key and AAD

        # When: the same plaintext, key and AAD are sealed on this node
        found = self.rows(
            "SELECT id FROM e2e_people WHERE code_det = gcm_encrypt_det(%s::text, %s, %s)",
            ("M-0002", KEY, CODE_AAD),
        )

        # Then: an exact-match lookup on the stored envelope finds the row
        self.assertEqual(found, [(2,)])

    def test_given_a_code_sealed_with_one_aad_when_looked_up_with_another_then_nothing_matches(
        self,
    ) -> None:
        # Given: M-0002 sealed deterministically with the AAD people.code

        # When: the same plaintext and key are sealed with another AAD
        found = self.rows(
            "SELECT id FROM e2e_people WHERE code_det = gcm_encrypt_det(%s::text, %s, %s)",
            ("M-0002", KEY, b"visits.code"),
        )

        # Then: the AAD is an input of the nonce, so the envelopes differ (design O16)
        self.assertEqual(found, [])

    def test_given_two_tables_sealed_deterministically_when_joined_on_the_envelopes_then_rows_pair_up(
        self,
    ) -> None:
        # Given: people and their visits, the member code sealed the same way in both tables

        # When: the tables are joined on the envelopes, with no key in the query at all
        visits = self.rows(
            "SELECT p.id, count(*) FROM e2e_people p"
            " JOIN e2e_visits v ON v.person_code_det = p.code_det GROUP BY p.id ORDER BY p.id"
        )

        # Then
        self.assertEqual(visits, [(1, 2), (2, 1)])

    def test_given_a_forged_tag_and_strict_on_when_decrypted_then_it_is_the_data_corrupted_error(
        self,
    ) -> None:
        # Given: an envelope whose tag has one bit flipped, and pg_gcm.strict on
        self.db.execute("SET pg_gcm.strict = on")

        # When
        with self.assertRaises(psycopg.errors.DataCorrupted):
            self.db.execute("SELECT gcm_decrypt(name_enc, %s, %s) FROM e2e_forged", (KEY, NAME_AAD))

        # Then: SQLSTATE XX001 (asserted by the block above)

    def test_given_a_forged_tag_and_strict_off_when_decrypted_then_it_is_null(self) -> None:
        # Given: the same envelope, and pg_gcm.strict off in this session
        self.db.execute("SET pg_gcm.strict = off")

        # When
        opened = self.rows("SELECT gcm_decrypt(name_enc, %s, %s) FROM e2e_forged", (KEY, NAME_AAD))

        # Then
        self.assertEqual(opened, [(None,)])

    def test_given_a_null_in_each_argument_position_when_called_then_every_result_is_null(
        self,
    ) -> None:
        # Given: the three functions in both forms, with NULL in one position at a time
        key, aad = KEY, NAME_AAD

        # When
        results = self.rows(
            "SELECT gcm_encrypt(NULL, %(k)s) IS NULL, gcm_encrypt('x', NULL) IS NULL,"
            " gcm_encrypt(NULL, %(k)s, %(a)s) IS NULL, gcm_encrypt('x', NULL, %(a)s) IS NULL,"
            " gcm_encrypt('x', %(k)s, NULL) IS NULL,"
            " gcm_encrypt_det(NULL, %(k)s) IS NULL, gcm_encrypt_det('x', NULL) IS NULL,"
            " gcm_encrypt_det(NULL, %(k)s, %(a)s) IS NULL,"
            " gcm_encrypt_det('x', NULL, %(a)s) IS NULL,"
            " gcm_encrypt_det('x', %(k)s, NULL) IS NULL,"
            " gcm_decrypt(NULL, %(k)s) IS NULL, gcm_decrypt(name_enc, NULL) IS NULL,"
            " gcm_decrypt(NULL, %(k)s, %(a)s) IS NULL, gcm_decrypt(name_enc, NULL, %(a)s) IS NULL,"
            " gcm_decrypt(name_enc, %(k)s, NULL) IS NULL"
            " FROM e2e_people WHERE id = 1",
            {"k": key, "a": aad},
        )

        # Then: fifteen positions, fifteen NULLs, and no error
        self.assertEqual(results, [(True,) * 15])


class OnThePrimary(OnEitherNode, Scenario):
    node = "primary"


class OnTheReplica(OnEitherNode, Scenario):
    """The same scenarios where nothing was ever encrypted: the replica only replayed WAL."""

    node = "replica"
