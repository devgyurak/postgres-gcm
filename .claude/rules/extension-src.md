---
paths:
  - "src/**"
  - "sql/**"
  - "*.control"
  - "Makefile"
---
<!-- Generated from .agents/rules/extension-src.md by scripts/agents-sync.py — edit the source. -->
# Extension source rules

- **Version-1 C functions and PGXS only.** `PG_MODULE_MAGIC` once, `PG_FUNCTION_INFO_V1` per function,
  built with `make USE_PGXS=1` against `pg_config`. No server patch, no executor or planner hook, no
  background worker, no shared memory.
- File responsibilities, dependency direction and lifetimes follow `architecture.md`.
- The SQL script `sql/pg_gcm--<version>.sql` declares every function with explicit volatility,
  `STRICT`, `PARALLEL SAFE` and an explicit `COST`, never `IMMUTABLE` (design §2.1, §5.3). Each
  function is **two declarations** — `(…, key bytea)` and `(…, key bytea, aad bytea)` — bound to two C
  entry points or one that reads `PG_NARGS()`; **never `DEFAULT NULL`**. It starts with
  `\echo Use "CREATE EXTENSION pg_gcm" to load this file. \quit`. A released script is never edited; a
  change ships as `pg_gcm--<from>--<to>.sql`.
- Arguments: read `bytea` with `PG_GETARG_BYTEA_PP` and `VARDATA_ANY`/`VARSIZE_ANY_EXHDR` (from 16
  these need `#include "varatt.h"` under `PG_VERSION_NUM >= 160000`). `STRICT` means no argument is
  NULL, so there is no `PG_ARGISNULL` branch to write. `key` is checked for length {32, 24, 16} **on
  every call**. An argument is never modified, and is cleansed only when it is a detoasted copy.
- Encoding (design §5.7): verify with `pg_verify_mbstr(PG_UTF8, ..., true)` and convert with
  `pg_do_encoding_conversion_buf(proc, ..., true)` into a buffer the glue allocated, `proc` coming from
  `FindDefaultConversionProc` before any secret copy exists. **Not** `pg_any_to_server`,
  `pg_server_to_any` or `pg_verify_mbstr(..., false)`: they put the offending bytes in the error
  message and allocate the copy where the caller cannot cleanse it. A UTF8 database converts nothing; a
  SQL_ASCII database verifies the plaintext as UTF-8 on encryption. All of it runs **outside** the core
  and outside any window where an OpenSSL resource is live.
- Errors: `ereport(ERROR, (errcode(...), errmsg(...)))` with the SQLSTATE fixed by `spec/envelope.md`
  — until Phase 1 writes it, the ones the spike uses (design §8, O7). Messages carry lengths and the
  version byte at most.
- `_PG_init`: fetch the OpenSSL handles first, recording a failure instead of raising; then
  `DefineCustomBoolVariable` / `DefineCustomIntVariable`; then `MarkGUCPrefixReserved("pg_gcm")` (the
  `guc-config` skill covers versions). No `on_proc_exit` (design §5.8).
- Compiled with the server's `CFLAGS` from PGXS plus `-Wall -Wextra -Werror` in CI
  (`make PG_GCM_WERROR=1`). C11, as `-std=gnu11`. No C++ in the shipped library.
- Each function's SQL behaviour (a NULL in each argument position, the empty string, maximum length,
  the two- and three-argument forms, an empty `aad`, a wrong key length, strict on and off, a
  non-UTF-8 database) is covered by `pg_regress`.
