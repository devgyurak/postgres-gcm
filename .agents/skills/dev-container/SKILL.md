---
name: dev-container
description: Starting a development PostgreSQL in Docker, building the extension in the matching build image, installing it, and running the Phase S checks (scripts/dev-up.sh, build-in-docker.sh, verify.sh, verify.sql). Use it for local verification and to create those scripts in Phase S.
---

# dev-container

Rules: `stack-ci-docker.md`. Majors and image digests come from `docker/versions.json` only.

## Scripts this skill creates (Phase S)
| Script | Does |
|---|---|
| `scripts/build-in-docker.sh <major>` | Builds `docker/build.Dockerfile` for that major, runs `make USE_PGXS=1` in it, leaves `build/<major>/{pg_gcm.so,pg_gcm.control,sql/}` |
| `scripts/dev-up.sh <major>` | Starts `postgres:<major>` as `pg-gcm-dev-<major>` with a random superuser password in a tmpfs, waits on `pg_isready` |
| `scripts/verify.sh <major>` | Copies the build into the container's `pg_config --pkglibdir` / `--sharedir`, runs `make installcheck` inside the build image against it, then `scripts/verify.sql` |
| `scripts/verify.sql` | The Phase S checks in design §4, printing one labelled row per check |

## Rules
- Never enable `log_statement = 'all'` or `auto_explain` with `log_analyze` on a container that runs
  key-bearing SQL (the guard hook blocks the obvious forms).
- Passwords are generated per run and never written to the repository.
- A failing step stops the script with the raw error; do not retry.
