# SPDX-License-Identifier: PostgreSQL
# The build image: the official server image plus the headers of exactly that server.
# One responsibility — building and testing the extension. It never runs as the server under test
# (tests install into the official image), so it carries no HEALTHCHECK of its own.
#
# BASE is a digest-pinned reference from docker/versions.json (scripts/build-in-docker.sh passes it).
ARG BASE
FROM ${BASE}

# PG_MAJOR and PG_VERSION come from the official image's environment. Pinning the package to
# PG_VERSION keeps the headers on the server's own minor: an unpinned install takes a newer one.
# The server-dev package depends on the matching clang and llvm-dev (PGXS emits bitcode) and, through
# libpq-dev, on libssl-dev. cmake, googletest and nlohmann-json are for the unit suite
# (scripts/unit-in-docker.sh), which reads spec/test-vectors.json; Google Benchmark and
# nlohmann-json are for the core micro-benchmarks (scripts/bench.sh).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      "postgresql-server-dev-${PG_MAJOR}=${PG_VERSION}" \
      cmake \
      libgtest-dev \
      libgmock-dev \
      libbenchmark-dev \
      nlohmann-json3-dev \
 && rm -rf /var/lib/apt/lists/*
