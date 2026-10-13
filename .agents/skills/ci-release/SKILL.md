---
name: ci-release
description: Composing the GitHub Actions workflows (lint, unit, build matrix, regress, e2e, bench, nightly load, release), the Docker build and server images, and the release artifacts (checksums, signature, SBOM). Use it when working in .github/ or docker/, and when adding a workflow at the end of a phase.
---

# ci-release

Rules: `stack-ci-docker.md`. PGXS builds against installed headers, so no workflow builds a server
from source.

## Workflows by phase
| Phase | Workflow | Trigger | Does |
|---|---|---|---|
| S | `lint.yml` | PR, push | `agents-sync.sh --check`, `check-action-pins.py`, `check-architecture.py`, `check-vectors.py` and its `--self-test` (from Phase 1), shellcheck, ruff, mypy, actionlint |
| 2 | `unit.yml` | PR, push, nightly | `scripts/unit-in-docker.sh` for the newest supported major and the OpenSSL floor: sanitizers, a non-zero test count, the collision test at 100,000 on a PR and 1,000,000 otherwise |
| 2 | `build.yml` | PR, push | `scripts/build-in-docker.sh` for every image of `docker/versions.json` × amd64/arm64, `-Werror`, the server's own libcrypto |
| 2 | `regress.yml` | PR, push | build, `scripts/dev-up.sh`, `scripts/verify.sh` per image — **the required checks**, never path-filtered |
| 3 | `e2e.yml` | PR (path-filtered workflow of its own), push | build, then `scripts/e2e.sh` per image: a primary, a streaming replica and the SQL runner. Not a required check |
| 4 | `load.yml` | nightly, dispatch | load gate against pgcrypto |
| 4 | `bench.yml` | merges, nightly | core micro-benchmark ratio gate |
| 4 | `release.yml` | tag `v*`, dispatch (dry run) | guard (SemVer, tag on `main`, `## <version>` in CHANGELOG) → build → server image smoke → package, sign, SBOM → publish |

The workflows call the same scripts a developer runs, so a failure reproduces locally with one
command. Each takes its matrix from `scripts/ci-matrix.py` (`all`, or `unit`: one image per
libcrypto), which reads `docker/versions.json` — a list written into a workflow would go on passing
after an image was added and never built. No job is `continue-on-error` (a failure under it does not fail the run and is
easy to miss): the pre-release image carries "pre-release" in its job name and is the one not to make a
required check. A `schedule` runs from the default branch only: a nightly job does nothing until
its file is on `main`.

## Release
- A dispatch run publishes nothing and exercises the whole pipeline; run it before every tag.
- The server image layers the extension onto `postgres:<major>` and runs
  `CREATE EXTENSION pg_gcm` in an init script; `scripts/smoke-image.sh` starts it and checks the Korean
  `LIKE` round trip before anything is pushed.
- Secrets (registry credentials) are repository secrets; workflows never echo them.
