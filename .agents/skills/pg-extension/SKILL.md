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
sql/pg_gcm--0.1.0.sql       \echo guard, then six CREATE FUNCTION ... LANGUAGE C: volatility, STRICT, PARALLEL SAFE, COST
src/pg_gcm.c                PG_MODULE_MAGIC, _PG_init (fetch handles, then GUCs); nothing is released
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
`postgres` resolve the same `libcrypto.so.3` (design §8 O2; a server on `libcrypto.so.1.1` is out of
scope). The skeleton is the shape pgvector uses. Two things to know: `results/`, `regression.diffs` and
`regression.out` land in the directory `make` runs from, not under `test/`; and PGXS also builds LLVM
bitcode, for which the server-dev package already brings the matching `clang`.

## A SQL-callable function, the shape to follow
1. No NULL handling: the functions are `STRICT`, so the server returns NULL without calling them. The
   two- and three-argument forms share one body (`PG_NARGS()`, or two thin entry points).
2. Read `bytea` with `PG_GETARG_BYTEA_PP`; data `VARDATA_ANY`, length `VARSIZE_ANY_EXHDR` (`varatt.h`
   from 16). Note for each argument whether the pointer differs from `PG_GETARG_POINTER(n)`: only such
   a detoasted copy is ever cleansed, and an argument is never modified.
3. Key length in {32, 24, 16}; on encryption, also `>= pg_gcm_min_key_bytes`. Error otherwise.
4. Everything that can raise and needs no secret comes first: the handle check (a failed fetch in
   `_PG_init` surfaces here), `FindDefaultConversionProc` when the database is neither UTF8 nor
   SQL_ASCII, the size arithmetic against `MaxAllocSize`, and the `palloc` of the result at its final
   size (`1 + 12 + len + 16` for an envelope).
5. Encryption, plaintext to UTF-8 (design §5.7): UTF8 database — use the bytes; SQL_ASCII —
   `pg_verify_mbstr(PG_UTF8, ..., true)`; otherwise `pg_do_encoding_conversion_buf(proc, ..., true)`
   into a `palloc`'d buffer of `len * MAX_CONVERSION_GROWTH + 1`. A false or short result is an error
   the glue raises itself, after cleansing, naming encodings and lengths only.
6. Call the core. It touches OpenSSL and returns an `enum gcm_error`. Nothing between its call and its
   return may `ereport`.
7. Decryption, opened bytes to `text`: `pg_verify_mbstr(PG_UTF8, ..., true)`; convert with
   `pg_do_encoding_conversion_buf(..., true)` when the database is not UTF8 or SQL_ASCII; build the
   result into the buffer allocated in step 4.
8. From the first secret copy to the last, the glue is inside `PG_TRY` / `PG_FINALLY`; `FINALLY`
   cleanses and frees every copy the function made. Only then translate the error: strict-dependent
   NULL or `ereport(ERROR)`. **Never** `pg_any_to_server`, `pg_server_to_any` or
   `pg_verify_mbstr(..., false)` — they write the offending bytes into the message.

## SQL script rules
- `gcm_encrypt` `VOLATILE`; `gcm_encrypt_det`, `gcm_decrypt` `STABLE`; all `STRICT` and `PARALLEL
  SAFE`, each with an explicit `COST`; none `IMMUTABLE` (design §2.1, §5.3).
- Six declarations: every function once as `(…, key bytea)` and once as `(…, key bytea, aad bytea)`.
  **No `DEFAULT NULL`**: with `STRICT` it makes the two-argument call return NULL without encrypting,
  and without `STRICT` an explicit NULL `aad` would become "no AAD" (design §2.1).
- A released script is frozen. Changes ship as `pg_gcm--<from>--<to>.sql`, and the regression suite
  tests `ALTER EXTENSION pg_gcm UPDATE`.

## Phase S
Create the minimal version (AES-256, random, no AAD), then `scripts/build-in-docker.sh` and
`scripts/verify.sh` per the `dev-container` skill, and record every answer in design §8.
