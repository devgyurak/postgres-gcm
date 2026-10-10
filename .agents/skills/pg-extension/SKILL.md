---
name: pg-extension
description: Building and changing the pg_gcm PostgreSQL C extension — PGXS Makefile, control file, install and upgrade SQL scripts, version-1 fmgr functions, argument and encoding handling, and error translation. Use it before touching src/, sql/, pg_gcm.control or the Makefile, and to create the Phase S build.
---

# pg-extension

Rules: `.agents/rules/extension-src.md`, `architecture.md`, `crypto-safety.md`. Design: `docs/design.md`
§2, §5. When a signature is uncertain, ask the `pg-api-researcher` subagent; do not guess.

## Layout this skill creates
```
pg_gcm.control              comment, default_version, module_pathname = '$libdir/pg_gcm', relocatable = true
Makefile                    PGXS: MODULE_big = pg_gcm, OBJS = src/*.o, EXTENSION, DATA, REGRESS, SHLIB_LINK += -lcrypto
sql/pg_gcm--0.1.0.sql       \echo guard, then CREATE FUNCTION ... LANGUAGE C, explicit volatility, PARALLEL SAFE
src/pg_gcm.c                PG_MODULE_MAGIC, _PG_init (GUCs, fetch handles), on_proc_exit release
src/fn_encrypt.c            gcm_encrypt, gcm_encrypt_det
src/fn_decrypt.c            gcm_decrypt
src/gcm.c envelope.c nonce.c  the core (no PostgreSQL headers)
```

## Makefile skeleton
```make
MODULE_big = pg_gcm
OBJS = src/pg_gcm.o src/fn_encrypt.o src/fn_decrypt.o src/gcm.o src/envelope.o src/nonce.o
EXTENSION = pg_gcm
DATA = sql/pg_gcm--0.1.0.sql
REGRESS = $(patsubst test/sql/%.sql,%,$(wildcard test/sql/*.sql))
REGRESS_OPTS = --inputdir=test --load-extension=pg_gcm
SHLIB_LINK += -lcrypto
PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
```
Link only `-lcrypto`, the server's own. Confirm with `ldd` in the build image that the `.so` and
`postgres` resolve the same `libcrypto.so.3` (design §8 O2).

## A SQL-callable function, the shape to follow
1. `PG_ARGISNULL` checks: NULL plaintext/ciphertext → `PG_RETURN_NULL()`; NULL key → error.
2. Read `bytea` with `PG_GETARG_BYTEA_PP`; data `VARDATA_ANY`, length `VARSIZE_ANY_EXHDR`.
3. Key length in {32, 24, 16}; on encryption, also `>= pg_gcm_min_key_bytes`. Error otherwise.
4. Encryption: `pg_server_to_any(text, len, PG_UTF8)` **before** the core. Remember whether it returned a
   new buffer (it returns the input when no conversion is needed) so only a copy is cleansed and freed.
5. `palloc` the result `bytea` at its final size (`1 + 12 + len + 16`, overflow-checked against
   `MaxAllocSize`) **before** calling the core.
6. Call the core. It touches OpenSSL and returns an `enum gcm_error`. Nothing between its call and its
   return may `ereport`.
7. Cleanse and free every copy. Then translate the error: strict-dependent NULL or `ereport(ERROR)`.
8. Decryption: `pg_verify_mbstr(PG_UTF8, ...)` on the opened bytes (error on failure, after cleansing),
   then `pg_any_to_server(..., PG_UTF8)`, then `cstring_to_text_with_len`; cleanse the intermediate
   plaintext buffers.

## SQL script rules
- `gcm_encrypt` `VOLATILE`; `gcm_encrypt_det`, `gcm_decrypt` `STABLE`; all `PARALLEL SAFE`; none
  `IMMUTABLE` or `STRICT` (design §5.3, §2.1). `aad bytea DEFAULT NULL`.
- A released script is frozen. Changes ship as `pg_gcm--<from>--<to>.sql`, and the regression suite
  tests `ALTER EXTENSION pg_gcm UPDATE`.

## Phase S
Create the minimal version (AES-256, random, no AAD), then `scripts/build-in-docker.sh` and
`scripts/verify.sh` per the `dev-container` skill, and record every answer in design §8.
