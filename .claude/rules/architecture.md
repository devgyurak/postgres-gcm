---
paths:
  - "src/**"
  - "tests/**"
  - "test/**"
  - "spec/**"
  - "docs/design.md"
  - "Makefile"
  - "**/CMakeLists.txt"
---
<!-- Generated from .agents/rules/architecture.md by scripts/agents-sync.py — edit the source. -->
# Architecture — responsibilities, dependency direction, resource lifetimes

The rationale is `docs/design.md` §3 and §5. For PostgreSQL API usage follow `extension-src.md`, for
crypto safety `crypto-safety.md`, and for tests `testing.md`.

## 1. Module responsibilities and dependency direction

| Module | Responsibility | Project dependencies allowed |
|---|---|---|
| `pg_gcm.c` | `PG_MODULE_MAGIC`, `_PG_init`, GUC registration, the fetched-handle cache | `gcm` init, PostgreSQL headers |
| `fn_encrypt.c`, `fn_decrypt.c` | SQL arguments, NULL, encoding conversion, GUC reads, error translation | `gcm`, the shared byte and error types, PostgreSQL headers |
| `gcm.{h,c}` | The encryption and decryption construction, the authentication result | `envelope`, `nonce`, OpenSSL |
| `nonce.{h,c}` | Domain separation and nonce derivation | The shared types, OpenSSL |
| `envelope.{h,c}` | Version, length, offset and field parsing; the shared types | The C standard library |

- The core (`gcm`, `envelope`, `nonce`) includes **no PostgreSQL header** — not `postgres.h`, not
  `fmgr.h`, not `utils/elog.h` — and allocates with `malloc`/`OPENSSL_malloc` only, so it builds and
  tests without a server.
- `envelope` does not depend on OpenSSL either. Do not duplicate envelope byte interpretation into the
  glue.
- `scripts/check-architecture.py` (Phase S) enforces the include boundary per line, as in mysql-gcm.

## 2. Errors cross the boundary as values

- The core returns an `enum gcm_error` and never longjmps. The glue decides error-or-NULL from
  `pg_gcm.strict` and raises with `ereport`.
- **Release before raising.** `ereport(ERROR)` does not return. Every `EVP_CIPHER_CTX`, `EVP_MAC_CTX`
  and secret copy is freed and cleansed **before** the glue calls `ereport`. Code between acquiring an
  OpenSSL resource and releasing it must not call anything that can `ereport(ERROR)` — no `palloc`
  (it errors on out-of-memory), no `CHECK_FOR_INTERRUPTS`, no encoding conversion. Allocate the
  PostgreSQL result buffer before entering the core, or after leaving it.
- A key-length or envelope error is never hidden by strict.

## 3. Ownership and lifetimes

| Lifetime | Resource and responsibility |
|---|---|
| backend (library load) | The fetched `EVP_CIPHER` and `EVP_MAC` handles, the GUC variables. Created in `_PG_init`; PostgreSQL never unloads a library, so release is at process exit (`on_proc_exit`) |
| call site (`flinfo->fn_extra`) | Only after the A11-equivalent amendment: a scheduled cipher context and the key copy it was scheduled for, allocated in `fn_mcxt`, cleansed by a memory-context reset callback |
| operation | The EVP operation, the nonce, MAC output and scratch copies. Released on every path before returning or raising |

- Input `bytea`/`text` comes from the caller's datum. Detoasting may make a copy (`PG_GETARG_BYTEA_PP`);
  a detoasted copy of the key or plaintext is cleansed before it is freed.
- No global mutable state beyond the backend-lifetime handles. Parallel workers are separate processes
  and load the library themselves.

## 4. Server version boundary

- `PG_VERSION_NUM` checks live only in the glue and `pg_gcm.c`. A version difference never changes the
  authentication policy or the envelope bytes.

## 5. Per-row cost

- Fetch in `_PG_init`, never per call. Read GUCs through their C variables.
- Size arithmetic checks overflow and the 1 GB `varlena` limit (`MaxAllocSize`) before allocating, and
  translates a failure into a SQL error.
- No optimisation omits authentication, the key-length check or the cleansing of secrets.

## 6. Test boundaries

- An internal entry point for vector tests (`gcm_encrypt_with_nonce`) is never declared in the
  extension's SQL script. `check-architecture.py` lists every such seam.
- No experimental code that skips encryption or returns plaintext under a GUC or a debug build.
