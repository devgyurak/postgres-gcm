---
paths:
  - ".github/**"
  - "docker/**"
  - "scripts/**"
  - "tests/e2e/compose*.yml"
---
# CI · Docker · script conventions

- GitHub Actions, split by concern: `lint.yml`, `unit.yml`, `build.yml` (matrix), `regress.yml` (the
  required SQL checks), `e2e.yml`, `load.yml` (nightly/dispatch), `bench.yml`, `release.yml` (tags).
  Added phase by phase; never one giant file.
- Pin actions by SHA (`actions/checkout@<sha> # v4`), checked by `scripts/check-action-pins.py`.
- Matrix axes: PostgreSQL majors (the exact images live in one place, `docker/versions.json`) ×
  `amd64 / arm64`. OpenSSL is whatever each image's server links, and the build job fails unless
  `ldd` shows the server and `pg_gcm.so` resolving the same `libcrypto.so.3` (design §0: 3.0 or later).
- Build image: `docker/build.Dockerfile` is `postgres:<major>` (base pinned by digest) plus
  `postgresql-server-dev-<major>=$PG_VERSION` and `build-essential`. **Pin the package to the image's
  `PG_VERSION`**: a digest-pinned base with an unpinned `apt-get install` takes headers from a newer
  minor than the server, and PGDG keeps only the last few versions, so refresh digest and pin together.
  The server-dev package already depends on the matching `clang` and `llvm-dev` (PGXS emits bitcode
  because the packaged `Makefile.global` has `with_llvm = yes`) and, through `libpq-dev`, on
  `libssl-dev`. No source-tree build is needed — PGXS builds against the installed headers — so no
  image cache layer is needed.
- A pre-release major (19 before its release) comes from PGDG's per-major apt component, not `main`.
- Tests install the built `.so`, `.control` and SQL into the **official** `postgres:<major>` image. The
  one exception is the release server image (`docker/server.Dockerfile`), which no test path depends on.
  `make installcheck` running in the build container reaches that server over a shared network with
  `PGHOST`, `PGPORT`, `PGUSER` (a superuser) and `PGPASSWORD`; `make install` in the build container
  does not install anything the server can see.
- From 18 the official image keeps its data in `/var/lib/postgresql/<major>/docker` with the volume at
  `/var/lib/postgresql`; before that, at `/var/lib/postgresql/data`. A tmpfs or volume mount takes its
  path per major, never from a constant.
- Never put `paths` on a workflow that holds a required check.
- PR gate workflows get a `concurrency` group with `cancel-in-progress` only on `pull_request`.
- Secrets come from GitHub Secrets only.
- Release artifacts: `pg_gcm-<ver>-pg<major>-<arch>.tar.gz` plus `SHA256SUMS`, its signature and an
  SBOM. Tags are SemVer `vMAJOR.MINOR.PATCH` on `main`, with a `## <version>` section in `CHANGELOG.md`.
- Shell scripts: `#!/usr/bin/env bash`, `set -euo pipefail`, clean under `shellcheck`, usage on no args.
- Dockerfiles: base pinned by digest, one responsibility each, a `HEALTHCHECK` (`pg_isready`) rather
  than a sleep.
