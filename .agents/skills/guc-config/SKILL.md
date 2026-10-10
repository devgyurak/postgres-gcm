---
name: guc-config
description: Registering and reading the extension's GUCs (pg_gcm.strict, pg_gcm.min_key_bytes) — contexts, defaults, the reserved prefix, postgresql.conf, ALTER SYSTEM and GRANT SET, and how parallel workers see them. Use it before adding or changing a GUC or how the code reads one.
---

# guc-config

Design: `docs/design.md` §2.3, §5.6. A new GUC or a changed default is a design amendment first.

## The two GUCs
| Name | Type | Context | Default | Read by |
|---|---|---|---|---|
| `pg_gcm.strict` | bool | `PGC_USERSET` | on | `gcm_decrypt`: tag failure → error (on) or NULL (off) |
| `pg_gcm.min_key_bytes` | int, 16..32 | `PGC_SUSET` | 32 | the two encryption functions; decryption ignores it |

## Registration, in `_PG_init`
```c
DefineCustomBoolVariable("pg_gcm.strict", "...", NULL, &pg_gcm_strict, true,
                         PGC_USERSET, 0, NULL, NULL, NULL);
DefineCustomIntVariable("pg_gcm.min_key_bytes", "...", NULL, &pg_gcm_min_key_bytes, 32, 16, 32,
                        PGC_SUSET, 0, check_min_key_bytes, NULL, NULL);
MarkGUCPrefixReserved("pg_gcm");
```
- The OpenSSL fetch comes **before** these calls and never raises (design §5.8): an `ERROR` after a
  `DefineCustom*Variable` leaves the library unlisted, and every later call re-runs `_PG_init` into
  "attempt to redefine parameter".
- `check_min_key_bytes` accepts only 16, 24 and 32 and sets `GUC_check_errdetail` without echoing
  anything but the number.
- `MarkGUCPrefixReserved` exists from PostgreSQL 15; it replaced `EmitWarningsOnPlaceholders`.
  Confirm against each supported major's `utils/guc.h` (the `pg-api-researcher` subagent).

## Reading
- Read the C variable at call time. PostgreSQL updates it for the backend on `SET`, `RESET`,
  transaction-scoped `SET LOCAL` and config reload, so there is no snapshot to manage — unlike
  mysql-gcm, there is no per-`UDF_INIT` copy.
- A parallel worker sees the leader's value: it loads the leader's libraries, then restores every
  non-default GUC, `SET LOCAL` ones included (design §8 O9, confirmed on 15–18). Keep the regression
  test that forces a parallel scan (the `regress-tests` skill says how, without a version branch).

## Configuration
- `postgresql.conf`: `pg_gcm.strict = on`, `pg_gcm.min_key_bytes = 32`.
- Until the library loads in a backend the names are placeholders (design §2.3, §8):
  - `SET` takes any value and any spelling, and `SHOW` then returns that unvalidated value — `off`
    for `pg_gcm.strict` on a server with no extension at all. A successful `SHOW` is not evidence that
    the library is loaded; only a name never set errors. A check that needs the real variable calls
    one of the extension's functions first, which loads the library.
  - At load, a `pg_gcm.min_key_bytes` placeholder set by a role without the privilege is dropped with
    `WARNING: permission denied to set parameter` and the default stands. An invalid value is likewise
    a WARNING and the default, not an error.
  - The reserved prefix rejects a typo only in a `SET` **after** load. Before load, and in
    `postgresql.conf`, the typo is accepted and removed with a WARNING at load.
  - `ALTER SYSTEM SET pg_gcm.…` errors on 15 and 16 unless the library is loaded in that session; 17
    and 18 accept it unvalidated.
  - `shared_preload_libraries = 'pg_gcm'` makes all of this validated at server start.
- Delegation: `GRANT SET ON PARAMETER pg_gcm.min_key_bytes TO role` (PostgreSQL 15+). `ALTER ROLE` /
  `ALTER DATABASE ... SET` of it needs a superuser or that grant.
- Never a GUC that holds key material, a key id or a path to a key.
