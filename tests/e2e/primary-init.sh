#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Run once by the official image while it initialises the primary (docker-entrypoint-initdb.d):
# a role the replica connects as, and the pg_hba.conf line that lets it. The password is
# generated per run by scripts/e2e.sh; psql reads it from the environment (\getenv, psql 15
# and later), so it is on no command line.
set -euo pipefail

psql --no-psqlrc --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<'SQL'
\getenv password PG_GCM_E2E_REPLICATION_PASSWORD
-- The statement below carries the password in its text. Were it to fail, the server would log
-- the statement (log_min_error_statement defaults to error), and scripts/e2e.sh prints the
-- servers' logs after a failed run.
SET log_min_error_statement = panic;
CREATE ROLE replicator REPLICATION LOGIN PASSWORD :'password';
SQL
echo "host replication replicator all scram-sha-256" >>"$PGDATA/pg_hba.conf"
