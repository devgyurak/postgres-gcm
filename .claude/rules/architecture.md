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
| `pg_gcm.{h,c}` | `PG_MODULE_MAGIC`, `_PG_init` (the core's fetch, then GUC registration), what the glue files share: the GUC variables, the conversion lookup in `pg_catalog`, argument release, error translation | `gcm` init, PostgreSQL headers |
| `fn_encrypt.c`, `fn_decrypt.c` | SQL arguments, encoding conversion, GUC reads, error translation (NULL never reaches them: the functions are `STRICT`) | `gcm`, `pg_gcm.h`, the shared byte and error types, PostgreSQL headers |
| `gcm.{h,c}` | The encryption and decryption construction, the authentication result, the fetched handles (`gcm_init`), `gcm_cleanse` | `envelope`, `nonce`, OpenSSL |
| `nonce.{h,c}` | Domain separation and nonce derivation | The shared types, OpenSSL |
| `envelope.{h,c}` | Version, length, offset and field parsing; the shared types | The C standard library |

- The core (`gcm`, `envelope`, `nonce`) includes **no PostgreSQL header** — not `postgres.h`, not
  `fmgr.h`, not `utils/elog.h` — and allocates with `malloc`/`OPENSSL_malloc` only, so it builds and
  tests without a server.
- `envelope` does not depend on OpenSSL either. Do not duplicate envelope byte interpretation into the
  glue.
- The glue includes no OpenSSL header: it reaches OpenSSL through `gcm.h` alone, `gcm_cleanse`
  included.
- `scripts/check-architecture.py` enforces the include boundary per line.

## 2. Errors cross the boundary as values

- The core returns an `enum gcm_error` and never longjmps. The glue decides error-or-NULL from
  `pg_gcm.strict` and raises with `ereport`.
- **Release before raising.** `ereport(ERROR)` does not return. Every `EVP_CIPHER_CTX`, `EVP_MAC_CTX`
  and secret copy is freed and cleansed **before** the glue calls `ereport`. Code between acquiring an
  OpenSSL resource and releasing it must not call anything that can `ereport(ERROR)` — no `palloc`
  (it errors on out-of-memory), no `CHECK_FOR_INTERRUPTS`, no encoding conversion. Allocate the
  PostgreSQL result buffer before entering the core, or after leaving it.
- **Secrets on the glue's own error paths.** Outside that window the glue may still hold a secret copy
  it made (a conversion buffer, the opened plaintext) while calling something that can raise. Such a
  stretch is a `PG_TRY` / `PG_FINALLY` block whose `FINALLY` cleanses the copy; a variable changed
  inside `TRY` and read afterwards is `volatile`. No OpenSSL context is live inside the block.
- **The server never composes a message from our data.** Encoding checks use the forms that return a
  result (`pg_verify_mbstr(..., true)`, `pg_do_encoding_conversion_buf(..., true)`), into buffers the
  glue owns; the glue raises afterwards (design §5.7). The conversion procedure is looked up
  in `pg_catalog` (`FindDefaultConversion`; the glue raises `42883` when there is none) before any
  secret copy exists.
- A key-length or envelope error is never hidden by strict.

## 3. Ownership and lifetimes

| Lifetime | Resource and responsibility |
|---|---|
| backend (library load) | The fetched `EVP_CIPHER` and `EVP_MAC` handles, the GUC variables. Created in `_PG_init`, handles first (design §5.8). PostgreSQL never unloads a library and the handles are never released: no `on_proc_exit` callback, which would not run in a backend forked from a preloading postmaster anyway |
| call site (`flinfo->fn_extra`) | Only after a design amendment (design §4): a scheduled cipher context and the key copy it was scheduled for, allocated in `fn_mcxt`, cleansed by a memory-context reset callback. An `FmgrInfo` is **not** bounded by one statement — PL/pgSQL keeps a simple expression's state to the end of the transaction — so that amendment sets its own bound |
| operation | The EVP operation, the nonce, MAC output and scratch copies. Released on every path before returning or raising |

- Input `bytea`/`text` comes from the caller's datum. Detoasting may make a copy (`PG_GETARG_BYTEA_PP`);
  a detoasted copy of the key or plaintext is cleansed before it is freed. **The original is never
  written to**: it may be a cached plan's constant, a bind value in the portal, or a tuple in a shared
  buffer page. A copy is one whose pointer differs from `PG_GETARG_POINTER(n)`.
- No global mutable state beyond the backend-lifetime handles. Parallel workers are separate processes;
  each loads the libraries its leader had loaded and then restores the leader's GUC values, custom and
  `SET LOCAL` ones included (design §8, O9 — confirmed on 15–18).

## 4. Server version boundary

- `PG_VERSION_NUM` checks live only in the glue and `pg_gcm.c`. A version difference never changes the
  authentication policy or the envelope bytes. The one check 15–18 need today: `#include "varatt.h"`
  from 16, where the varlena macros moved out of `postgres.h`.

## 5. Per-row cost

- Fetch in `_PG_init`, never per call. Read GUCs through their C variables.
- Size arithmetic checks overflow and the 1 GB `varlena` limit (`MaxAllocSize`) before allocating, and
  translates a failure into a SQL error.
- No optimisation omits authentication, the key-length check or the cleansing of secrets.

## 6. Test boundaries

- An internal entry point for vector tests (`gcm_encrypt_with_nonce`) is never declared in the
  extension's SQL script. `check-architecture.py` lists every such seam.
- No experimental code that skips encryption or returns plaintext under a GUC or a debug build.
