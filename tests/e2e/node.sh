#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# The entrypoint of both servers of the end-to-end suite (tests/e2e/compose.yml).
# Usage: node.sh primary|replica
#   Installs the build mounted at /pg_gcm-build into this official image, where its server
#   looks for it; for a replica, takes a base backup of the primary first; then hands over
#   to the image's own entrypoint.
set -euo pipefail

role="${1:-}"
case "$role" in
  primary | replica) ;;
  *)
    echo "usage: node.sh primary|replica" >&2
    exit 2
    ;;
esac

# docs/ops-constraints.md item 7: the catalog entries reach a replica through WAL; the library and
# the extension's files have to be on each node's disk.
install -m 755 /pg_gcm-build/pg_gcm.so "$(pg_config --pkglibdir)/pg_gcm.so"
install -m 644 /pg_gcm-build/pg_gcm.control /pg_gcm-build/sql/*.sql "$(pg_config --sharedir)/extension/"

if [ "$role" = replica ]; then
  # As the server's user, into a directory only it can read. --write-recovery-conf leaves
  # standby.signal and the connection to the primary, so the server starts as a hot standby;
  # that connection string holds the run's replication password, in this container's tmpfs.
  # --checkpoint fast: the backup does not wait on the primary's checkpoint schedule.
  install -d -m 700 -o postgres -g postgres "$PGDATA"
  PGPASSWORD="$PG_GCM_E2E_REPLICATION_PASSWORD" gosu postgres \
    pg_basebackup --host primary --username replicator --pgdata "$PGDATA" \
    --wal-method stream --write-recovery-conf --checkpoint fast
fi

# docs/ops-constraints.md item 1: bind values stay out of the statement log.
exec docker-entrypoint.sh postgres -c log_parameter_max_length=0
