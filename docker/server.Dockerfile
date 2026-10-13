# SPDX-License-Identifier: PostgreSQL
# The distribution server image: the official postgres image with pg_gcm installed and created
# in the default database. scripts/server-image.sh prepares the build context (the built
# pg_gcm.so, pg_gcm.control, sql/, initdb.d/) and passes BASE from docker/versions.json.
#
# One responsibility: a server that already has the extension. No test path depends on this
# image — tests install the build into the official image themselves (.agents/rules/stack-ci-docker.md).
# A default so a bare `docker build` has a base; scripts/server-image.sh always overrides it with
# the digest-pinned reference from docker/versions.json.
ARG BASE=postgres:17-bookworm
FROM ${BASE}

# The extension, into the directories this server's pg_config names, then the init script that
# creates it in the default database. pg_config is the image's own, so the paths are the
# server's, not a constant.
COPY pg_gcm.so pg_gcm.control /tmp/pg_gcm/
COPY sql/ /tmp/pg_gcm/sql/
RUN set -eux; \
    pkglibdir="$(pg_config --pkglibdir)"; \
    sharedir="$(pg_config --sharedir)"; \
    install -m 0644 /tmp/pg_gcm/pg_gcm.so "$pkglibdir/pg_gcm.so"; \
    install -m 0644 /tmp/pg_gcm/pg_gcm.control "$sharedir/extension/pg_gcm.control"; \
    install -m 0644 /tmp/pg_gcm/sql/*.sql "$sharedir/extension/"; \
    rm -rf /tmp/pg_gcm
COPY initdb.d/ /docker-entrypoint-initdb.d/

# The image's own entrypoint runs /docker-entrypoint-initdb.d on first init. The check is TCP:
# the image's init-time server answers on the socket before the real server is up. A normal
# production cadence, not a one-second poll — scripts/smoke-image.sh waits on this status.
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
  CMD pg_isready -h 127.0.0.1 -U "${POSTGRES_USER:-postgres}" || exit 1
