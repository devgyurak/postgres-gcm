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
| 2 | `unit.yml` | PR, push | core unit tests with sanitizers; asserts a non-zero test count |
| 2 | `build.yml` | PR, push | majors × amd64/arm64 PGXS build, `-Werror` |
| 2 | `regress.yml` | PR, push | `make installcheck` per major — **the required checks**, never path-filtered |
| 3 | `e2e.yml` | PR (path-filtered workflow of its own), push | compose E2E: round trip, Korean `LIKE`, streaming replication |
| 4 | `load.yml` | nightly, dispatch | load gate against pgcrypto |
| 4 | `bench.yml` | merges, nightly | core micro-benchmark ratio gate |
| 4 | `release.yml` | tag `v*`, dispatch (dry run) | guard (SemVer, tag on `main`, `## <version>` in CHANGELOG) → build → server image smoke → package, sign, SBOM → publish |

## Release
- A dispatch run publishes nothing and exercises the whole pipeline; run it before every tag.
- The server image layers the extension onto `postgres:<major>` and runs
  `CREATE EXTENSION pg_gcm` in an init script; `scripts/smoke-image.sh` starts it and checks the Korean
  `LIKE` round trip before anything is pushed.
- Secrets (registry credentials) are repository secrets; workflows never echo them.
