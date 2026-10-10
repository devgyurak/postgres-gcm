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
  `amd64 / arm64`. OpenSSL is whatever each image's server links.
- Build image: `docker/build.Dockerfile` is `postgres:<major>` (base pinned by digest) plus
  `postgresql-server-dev-<major>` and the compilers. No source-tree build is needed — PGXS builds
  against the installed headers — so there is no image cache layer like mysql-gcm's.
- Tests install the built `.so`, `.control` and SQL into the **official** `postgres:<major>` image. The
  one exception is the release server image (`docker/server.Dockerfile`), which no test path depends on.
- Never put `paths` on a workflow that holds a required check.
- PR gate workflows get a `concurrency` group with `cancel-in-progress` only on `pull_request`.
- Secrets come from GitHub Secrets only.
- Release artifacts: `pg_gcm-<ver>-pg<major>-<arch>.tar.gz` plus `SHA256SUMS`, its signature and an
  SBOM. Tags are SemVer `vMAJOR.MINOR.PATCH` on `main`, with a `## <version>` section in `CHANGELOG.md`.
- Shell scripts: `#!/usr/bin/env bash`, `set -euo pipefail`, clean under `shellcheck`, usage on no args.
- Dockerfiles: base pinned by digest, one responsibility each, a `HEALTHCHECK` (`pg_isready`) rather
  than a sleep.
