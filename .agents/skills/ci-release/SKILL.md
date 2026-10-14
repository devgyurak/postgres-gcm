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
| 4 | `release.yml` | tag `v*`, dispatch (dry run) | guard (SemVer, tag on `main`, `## <version>` in CHANGELOG) → package every supported major on amd64 and arm64 → smoke each tarball → build and smoke the server image, then push and sign it (tag only) → SBOM, checksums, sign, publish |
| 5 | `release.yml` (`publish`) | tag `v*`, dispatch (dry run) | validate `META.json` and build the PGXN source archive (`check-pgxn.py`, `pgxn-dist.sh`), create the GitHub release, then upload to PGXN Manager (tag only) last |

The workflows call the same scripts a developer runs, so a failure reproduces locally with one
command. Each takes its matrix from `scripts/ci-matrix.py` (`all`, or `unit`: one image per
libcrypto), which reads `docker/versions.json` — a list written into a workflow would go on passing
after an image was added and never built. No job is `continue-on-error` (a failure under it does not fail the run and is
easy to miss): the pre-release image carries "pre-release" in its job name and is the one not to make a
required check. A `schedule` runs from the default branch only: a nightly job does nothing until
its file is on `main`.

## Release
- A dispatch run exercises the whole pipeline except the pushes, the image signature and the
  release create; run it before every tag.
- `package` builds the tarball per major per architecture, and `scripts/smoke-tarball.sh` layers
  it onto the official image and runs the Korean `LIKE` round trip there, so the shipped bytes are
  loaded on amd64 and arm64 alike.
- The server image layers the extension onto `postgres:<major>` and runs
  `CREATE EXTENSION pg_gcm` in an init script; `scripts/smoke-image.sh` starts it and checks the
  Korean `LIKE` round trip. The `server` job depends on `package`, so the image reaches ghcr.io and
  is signed with cosign only after every tarball passed, and only on a tag — never an unsigned
  image ahead of a failed package.
- The SBOM is written before `SHA256SUMS`, which covers the SBOM's own file; the checksums are
  signed keyless, then the GitHub release is created, and the PGXN upload is last.
- PGXN: `scripts/pgxn-dist.sh` validates `META.json` (`scripts/check-pgxn.py`) and writes the
  source archive `pg_gcm-<version>.zip` with `git archive HEAD` into a directory outside `dist/`,
  so it never joins the checksummed assets. The `publish` job builds the archive before the release
  (so metadata the upload would refuse fails there), creates the GitHub release, and uploads to
  PGXN Manager (`curl`, HTTP Basic auth, the multipart field `archive`) last, on a tag only; the
  release and the upload are idempotent, so a re-run finishes a partial release instead of failing
  on the version already published. A dispatch run builds and validates the archive and uploads
  nothing.
  `PGXN_USER` and `PGXN_PASSWORD` are secrets of the `release` environment, so its required
  reviewers gate them and not only the repository. Distribution packages (Debian, RPM) are not
  built.
- The `server` and `publish` jobs run in the `release` environment; give it required reviewers
  and protect `v*` tags, because a tag push runs this workflow from the tagged commit and the
  guard cannot refuse whoever can push a tag.
- Secrets (registry credentials) are repository secrets; workflows never echo them.
