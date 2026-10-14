#!/usr/bin/env bash
# SPDX-License-Identifier: PostgreSQL
# Start the distribution server image and check, before anything is pushed, that the extension
# is present in the default database (the image's init script created it) and that a Korean
# value sealed and opened there matches under the server's own LIKE.
# Usage: scripts/smoke-image.sh <image-ref>
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -eq 1 ] || die "usage: scripts/smoke-image.sh <image-ref>"
image="$1"
name="pg-gcm-smoke-$$"

# Generated per run, never written to the repository or a command line; it goes with the
# container at the end.
password="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
cleanup() {
  docker rm --force "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

POSTGRES_PASSWORD="$password" docker create --name "$name" \
  --env POSTGRES_PASSWORD "$image" >/dev/null
docker start "$name" >/dev/null
wait_healthy "$name"

# No CREATE EXTENSION here: the image's init script must have run it already, or the call to
# gcm_encrypt fails. ON_ERROR_STOP makes that, or a failed assertion, the exit status.
docker exec --interactive --env PGCLIENTENCODING=UTF8 "$name" \
  psql --no-psqlrc --quiet --username postgres --dbname postgres \
  --set ON_ERROR_STOP=1 <<'SQL'
DO $smoke$
DECLARE
  k bytea := '\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  hit boolean;
BEGIN
  hit := gcm_decrypt(gcm_encrypt('홍길동', k), k) LIKE '%길%';
  IF hit IS NOT TRUE THEN
    RAISE EXCEPTION 'pg_gcm smoke: the Korean LIKE round trip failed';
  END IF;
  RAISE NOTICE 'pg_gcm smoke: the Korean LIKE round trip holds';
END
$smoke$;
SQL
echo "== $image: the server image smoke test passed"
