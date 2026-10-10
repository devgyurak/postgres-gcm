---
paths:
  - "src/**"
  - "sql/**"
  - "*.control"
  - "Makefile"
---
# Extension source rules

- **Version-1 C functions and PGXS only.** `PG_MODULE_MAGIC` once, `PG_FUNCTION_INFO_V1` per function,
  built with `make USE_PGXS=1` against `pg_config`. No server patch, no executor or planner hook, no
  background worker, no shared memory.
- File responsibilities, dependency direction and lifetimes follow `architecture.md`.
- The SQL script `sql/pg_gcm--<version>.sql` declares every function with explicit volatility and
  `PARALLEL SAFE`, never `IMMUTABLE`, and not `STRICT` (NULL handling is in C, design §2.1). It starts
  with `\echo Use "CREATE EXTENSION pg_gcm" to load this file. \quit`. A released script is never
  edited; a change ships as `pg_gcm--<from>--<to>.sql`.
- Arguments: read `bytea` with `PG_GETARG_BYTEA_PP` and `VARDATA_ANY`/`VARSIZE_ANY_EXHDR`; check
  `PG_ARGISNULL` first. `key` is checked for length {32, 24, 16} **on every call**.
- Encoding: encryption converts the plaintext with `pg_server_to_any(..., PG_UTF8)`; decryption
  verifies with `pg_verify_mbstr(PG_UTF8, ...)` and converts with `pg_any_to_server(..., PG_UTF8)`.
  Both conversions run **outside** the core and outside any window where an OpenSSL resource is live.
- Errors: `ereport(ERROR, (errcode(...), errmsg(...)))` with the SQLSTATE fixed by `spec/envelope.md`.
  Messages carry lengths and the version byte at most.
- GUCs: `DefineCustomBoolVariable` / `DefineCustomIntVariable` in `_PG_init`, then
  `MarkGUCPrefixReserved("pg_gcm")` (the `guc-config` skill covers versions).
- Compiled with the server's `CFLAGS` from PGXS plus `-Wall -Wextra -Werror` in CI. C11. No C++ in the
  shipped library.
- Each function's SQL behaviour (NULL arguments, the empty string, maximum length, with and without
  AAD, a wrong key length, strict on and off, a non-UTF-8 database) is covered by `pg_regress`.
