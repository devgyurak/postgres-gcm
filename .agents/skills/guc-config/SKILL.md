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
- `check_min_key_bytes` accepts only 16, 24 and 32 and sets `GUC_check_errdetail` without echoing
  anything but the number.
- `MarkGUCPrefixReserved` exists from PostgreSQL 15; it replaced `EmitWarningsOnPlaceholders`.
  Confirm against each supported major's `utils/guc.h` (the `pg-api-researcher` subagent).

## Reading
- Read the C variable at call time. PostgreSQL updates it for the backend on `SET`, `RESET`,
  transaction-scoped `SET LOCAL` and config reload, so there is no snapshot to manage — unlike
  mysql-gcm, there is no per-`UDF_INIT` copy.
- A parallel worker must see the leader's value. Verify it in Phase S (design §8 O9) and keep a
  regression test that forces a parallel scan.

## Configuration
- `postgresql.conf`: `pg_gcm.strict = on`, `pg_gcm.min_key_bytes = 32`. Placeholders are accepted
  before the library loads; once it loads, values are validated.
- Delegation: `GRANT SET ON PARAMETER pg_gcm.min_key_bytes TO role` (PostgreSQL 15+).
- Never a GUC that holds key material, a key id or a path to a key.
