#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Start a development PostgreSQL for one major, from the official image.
#   scripts/dev-up.sh <major>            -> container pg-gcm-dev-<major>
#   scripts/dev-up.sh <major> --preload  -> container pg-gcm-dev-<major>-preload, started with
#                                           shared_preload_libraries = 'pg_gcm' (needs a build)
# The data directory is a tmpfs and the superuser password is generated per run; neither is
# written to the repository.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: scripts/dev-up.sh <major> [--preload]"
major="$1"
preload=0
if [ $# -eq 2 ]; then
  [ "$2" = "--preload" ] || die "usage: scripts/dev-up.sh <major> [--preload]"
  preload=1
fi

ref="$(image_ref "$major")"
name="$(dev_container_name "$major")"
server_args=()
if [ "$preload" -eq 1 ]; then
  name="$name-preload"
  server_args=(-c shared_preload_libraries=pg_gcm)
fi

docker network inspect "$DEV_NETWORK" >/dev/null 2>&1 || docker network create "$DEV_NETWORK" >/dev/null
docker rm --force "$name" >/dev/null 2>&1 || true

# The password reaches docker through the environment, not the command line.
# The health check uses TCP: the image's init-time server listens on the socket only, so a
# socket check would report ready before the real server is up.
POSTGRES_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(16))')" \
  docker create \
  --name "$name" \
  --network "$DEV_NETWORK" \
  --env POSTGRES_PASSWORD \
  --tmpfs "$(data_mount "$major")" \
  --health-cmd 'pg_isready -h 127.0.0.1 -U postgres' \
  --health-interval 1s --health-timeout 3s --health-retries 120 \
  "$ref" ${server_args[@]+"${server_args[@]}"} >/dev/null

# A preloading server needs the library on disk before it starts; a lazy one gets it here too
# when a build exists, and scripts/verify.sh installs it again either way.
if [ "$preload" -eq 1 ] || [ -f "$ROOT/build/$major/pg_gcm.so" ]; then
  install_extension "$name" "$major"
fi

docker start "$name" >/dev/null
wait_healthy "$name"
echo "$name is up: $(docker exec "$name" postgres --version) on network $DEV_NETWORK"
