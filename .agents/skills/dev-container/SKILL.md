---
name: dev-container
description: Starting a development PostgreSQL in Docker, building the extension in the matching build image, installing it, and running the Phase S checks (scripts/dev-up.sh, build-in-docker.sh, verify.sh, verify.sql). Use it for local verification and to create those scripts in Phase S.
---

# dev-container

Rules: `stack-ci-docker.md`. Majors and image digests come from `docker/versions.json` only.

## Scripts (created in Phase S)
| Script | Does |
|---|---|
| `scripts/build-in-docker.sh <major>` | Builds `docker/build.Dockerfile` for that major, runs `make USE_PGXS=1 PG_GCM_WERROR=1` in it on a copy of the sources, leaves `build/<major>/{pg_gcm.so,pg_gcm.control,sql/}`, and fails unless `ldd` shows the server and `pg_gcm.so` resolving the same `libcrypto.so.3` |
| `scripts/dev-up.sh <major> [--preload]` | Starts `postgres:<major>` as `pg-gcm-dev-<major>` on the network `pg-gcm-dev`, data directory on a tmpfs, a random superuser password per run, and waits on a `pg_isready` health check. `--preload` starts `pg-gcm-dev-<major>-preload` with `shared_preload_libraries = 'pg_gcm'` |
| `scripts/verify.sh <major>` | Copies the build into the server container's `pg_config --pkglibdir` / `--sharedir` (`docker cp`; `make install` in the build container reaches nothing the server sees), runs `make installcheck` inside the build image on the same network with `PGHOST`, `PGPORT`, `PGUSER` and `PGPASSWORD` set, then `scripts/verify.sql` with the library loaded lazily and preloaded, in two backends each |
| `scripts/verify.sql` | The Phase S checks in design §4, one labelled row per check, ending ` \| ok`, ` \| FAIL` or ` \| info` |
| `scripts/unit-in-docker.sh <major>` | The unit suite in that major's build image (GCC, the server's libcrypto) |
| `scripts/e2e.sh <major>` | The end-to-end suite of `tests/e2e/compose.yml` for that image, with the build installed into a primary and a streaming replica (the `e2e-load-tests` skill) |
| `scripts/lib.sh` | Sourced by the others: the image reference from `docker/versions.json`, installing into a container, waiting on health |

## Rules
- Never enable `log_statement = 'all'` or `auto_explain` with `log_analyze` on a container that runs
  key-bearing SQL (the guard hook blocks the obvious forms).
- Passwords are generated per run and never written to the repository.
- The data directory differs by major: `/var/lib/postgresql/data` through 17, and from 18
  `/var/lib/postgresql/<major>/docker` under a volume at `/var/lib/postgresql`. Mount per major.
- The build image installs `postgresql-server-dev-<major>` at the image's own `PG_VERSION`
  (`stack-ci-docker.md`); otherwise headers and server drift apart.
- A failing step stops the script with the raw error; do not retry.
- The health check is `pg_isready -h 127.0.0.1`: the image's init-time server listens on the socket
  only, so a socket check reports ready before the real server is up.
- A preloading server needs the library on disk before it starts: `docker create`, `docker cp`, then
  `docker start`. The data directory is a tmpfs, so `ALTER SYSTEM` plus a restart would lose it.
- The scripts run under macOS's bash 3.2 as well: no `mapfile`, no `${var,,}`, and an empty array is
  expanded as `${a[@]+"${a[@]}"}`.
