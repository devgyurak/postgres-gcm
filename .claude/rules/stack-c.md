---
paths:
  - "src/**"
  - "tests/unit/**"
  - "tests/bench/**"
  - "**/*.c"
  - "**/*.h"
  - "**/*.cc"
---
<!-- Generated from .agents/rules/stack-c.md by scripts/agents-sync.py — edit the source. -->
# C / PGXS / OpenSSL conventions

- The extension is **C11**, compiled with the server's flags from PGXS plus `-Wall -Wextra -Werror` in
  CI. Unit tests and benchmarks are C++17 (GoogleTest, Google Benchmark) that include the core's C
  headers under `extern "C"`.
- Follow PostgreSQL's own style in the glue (`pgindent` layout, `ereport` idioms, `palloc`). The core
  follows the same layout but uses only the C standard library and OpenSSL.
- Errors are `enum gcm_error { GCM_OK, GCM_BAD_ENVELOPE, GCM_BAD_TAG, GCM_BAD_KEY_LEN, GCM_OPENSSL_FAILURE, ... }`.
  No string errors — that is how data ends up in a message.
- Bytes are a `const uint8_t *` plus a `size_t`. Never a NUL-terminated string for binary data.
- Constants live in one place (`envelope.h`): `GCM_NONCE_LEN 12`, `GCM_TAG_LEN 16`, the version bytes.
- Every function that acquires an OpenSSL object has one exit label that frees it; no early `return`
  past an acquired resource.
- Static analysis: `clang-tidy` (`bugprone-*, cert-*, clang-analyzer-*`) on the core; `cppcheck` on the
  glue. Unit builds use `-fsanitize=address,undefined`; release builds never do.
- Includes: in the glue, `postgres.h` first, always; then `fmgr.h`, then the rest. In the core, own
  header → C standard → OpenSSL.
- Comments say **why** and cite the design (`/* design §5.2: release before ereport, it longjmps */`).
