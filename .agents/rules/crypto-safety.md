# Crypto safety rules (always apply)

This whole project is "make AEAD safe inside a PostgreSQL backend". Nothing below is negotiable. It
mirrors mysql-gcm's rule of the same name; where PostgreSQL changes the mechanics, the PostgreSQL form
is given.

## OpenSSL
- Fetch algorithms by name: `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)` (and `AES-192-GCM`,
  `AES-128-GCM`), `EVP_MAC_fetch(NULL, "HMAC", NULL)` with the `SHA256` digest. Never call a legacy
  symbol such as `EVP_aes_256_gcm()` or `HMAC()`.
- Fetch once per backend (`_PG_init`) and cache. Do not fetch per call. The fetch comes **before** the
  GUCs are registered, and a failed fetch is recorded, never raised: an `ERROR` in `_PG_init` stops the
  postmaster under `shared_preload_libraries`, and after `DefineCustom*Variable` it leaves a lazily
  loaded backend failing with "attempt to redefine parameter" (design §5.8). A call that finds no
  handle fails with the OpenSSL error class.
- Use the libcrypto the server links, and it must be **OpenSSL 3.0 or later**. No static linking, no
  bundling, no `dlopen` of another version, and no fallback to legacy symbols for a 1.1.1 server —
  that platform is out of scope (design §0).
- Nonce length is fixed at 12 and tag length at 16. No argument accepts another length.
- Random nonces come from `RAND_bytes`; any return other than 1 is an error. Never `random()`,
  `pg_prng`, or anything time-based. (`pg_strong_random` is not used either: one source, the same as
  mysql-gcm.)
- On decryption, call `EVP_CTRL_AEAD_SET_TAG` **before** `EVP_DecryptFinal_ex`; Final's return value
  *is* the tag check. When it returns 0, `OPENSSL_cleanse` the output buffer — never return
  unauthenticated plaintext.

## Key handling
- The key arrives only as the SQL argument `key` and is **exactly 32, 24 or 16 bytes** — the length
  selects the suite and nothing else does — and the two encryption functions also refuse anything
  below `pg_gcm.min_key_bytes`. Never fold, hash or pad a key to length.
- `pfree` does not zero memory. Every copy of the key or plaintext **that the extension made** — a
  detoasted argument, a conversion buffer, a scratch buffer, the opened plaintext before it becomes the
  result — is `OPENSSL_cleanse`d before it is freed, on success and on every error path. A stretch of
  glue that holds such a copy and can still raise (`palloc` can) is wrapped in `PG_TRY` /
  `PG_FINALLY`. Never hold a key in a `StringInfo`, which reallocates and leaves copies behind.
- **Never write to an argument in place.** One that needed no detoasting is the executor's storage: a
  constant in a cached plan, the portal's bind value, or a tuple in a shared buffer page. Cleanse only
  when the pointer differs from `PG_GETARG_POINTER(n)`, the test `PG_FREE_IF_COPY` uses.
- The rule's reach is the extension's own buffers. The result `text`, the caller's datums and the
  planner's copies are not ours to cleanse, and no document may claim that no key copy remains in
  backend memory (design §5.2).
- Derive the deterministic nonce key as `HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")`. The label is a
  single constant in `nonce.h` and keeps mysql-gcm's spelling so deterministic ciphertext matches across
  the two projects.
- No key bytes in a repository file, `postgresql.conf`, a GUC, an environment variable, a test fixture
  or any DDL. The only exception is the public vector keys in `spec/test-vectors.json`.
- That a key in a SQL statement can reach the server log is a **known operational constraint**
  (design §6). Do not write log-filtering code (`emit_log_hook`) — that is out of scope.

## Failure semantics
- Tag mismatch: with `pg_gcm.strict` on (the default) an error with the SQLSTATE `spec/envelope.md`
  fixes for it — its own, so a client can tell it from the other failure classes (design §8 O7); with
  it off, NULL. There is no third state.
- A malformed envelope, a wrong key length, invalid UTF-8 after a successful open and a character the
  database encoding cannot hold are **always** errors, regardless of strict.
- NULL in any argument gives NULL: the functions are `STRICT`, as mysql-gcm's are in effect (its spec
  §4, rule 3). That is argument propagation, not a failure mode, and it is not to be "fixed" into an
  error without amending the design.
- Verify and convert text only with the forms that report by return value —
  `pg_verify_mbstr(PG_UTF8, ..., true)` and `pg_do_encoding_conversion_buf(..., true)`.
  `pg_any_to_server`, `pg_server_to_any` and `pg_verify_mbstr(..., false)` format up to eight bytes of
  the offending character into the error message, and in `gcm_decrypt` those bytes are plaintext
  (design §5.7).
- Never put key, plaintext, nonce, tag or ciphertext bytes in a message, a `DETAIL`, a `HINT`, a
  `CONTEXT` callback or an assertion. Lengths and the version byte are as far as it goes.

## The deterministic variant
- `nonce = HMAC-SHA256(nonce_key, plaintext)[:12]` over the **UTF-8** plaintext bytes. AAD is not an
  input. Changing that means amending the design (and mysql-gcm's) first.
- For joins, UNIQUE constraints and exact-match lookups only. Keep the warning against free text in the
  documentation and the function comments.
- Every deterministic call under one key uses the same AAD bytes, or always none. Different AAD domains
  need different keys. The extension does not enforce this and must not be described as enforcing it.

## Operational responsibility
- mysql-gcm amendments A8 and A12 apply unchanged: a usage budget summing every use of a key, rotation
  criteria, independent full-length keys per suite and domain, and recovery that never resets usage
  accounting. The extension counts nothing and rotates nothing.

## Patterns blocked automatically (P1) in code review
Scope is C under `src/`.

`EVP_aes_`, `HMAC(`, `\brandom\(`, `pg_prng_`, `elog.*key`, `ereport.*(key|plain)`, `errdetail.*(key|plain|nonce)`,
`StringInfo.*key`, `pg_any_to_server`, `pg_server_to_any`, `pg_verify_mbstr` with a false last
argument, a hardcoded key literal, a key length outside {16, 24, 32}, a skipped
`pg_gcm.min_key_bytes` check on encryption, a tag failure turned into NULL without consulting strict,
an unchecked `EVP_DecryptFinal_ex`, an `ereport(ERROR)` reachable while an OpenSSL context is live, a
cleanse of an argument that is not a detoasted copy, and `IMMUTABLE` or `DEFAULT NULL` in the
extension SQL script.
