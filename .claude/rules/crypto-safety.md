<!-- Generated from .agents/rules/crypto-safety.md by scripts/agents-sync.py — edit the source. -->
# Crypto safety rules (always apply)

This whole project is "make AEAD safe inside a PostgreSQL backend". Nothing below is negotiable.

## OpenSSL
- Fetch algorithms by name: `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)` (and `AES-192-GCM`,
  `AES-128-GCM`), `EVP_MAC_fetch(NULL, "HMAC", NULL)` with the `SHA256` digest. Never call a legacy
  symbol such as `EVP_aes_256_gcm()` or `HMAC()`.
- Fetch once per backend (`_PG_init`) and cache. Do not fetch per call. (One name is still resolved
  per call: `EVP_MAC` takes its digest by name, so each deterministic call names SHA-256 to
  `EVP_MAC_init` — design §8, O15.) The fetch comes **before** the
  GUCs are registered, and a failed fetch is recorded, never raised: an `ERROR` in `_PG_init` stops the
  postmaster under `shared_preload_libraries`, and after `DefineCustom*Variable` it leaves a lazily
  loaded backend failing with "attempt to redefine parameter" (design §5.8). A call that finds no
  handle fails with the OpenSSL error class.
- Use the libcrypto the server links, and it must be **OpenSSL 3.0 or later**. No static linking, no
  bundling, no `dlopen` of another version, and no fallback to legacy symbols for a 1.1.1 server —
  that platform is out of scope (design §0).
- Nonce length is fixed at 12 and tag length at 16. No argument accepts another length.
- The associated data is `A = version || aad` (spec §1.5): the version byte is fed to GCM first, on
  seal and on open, and the caller's AAD after it. An envelope whose version byte alone was changed
  must fail the tag check; the vectors `version-02-as-03`, `version-03-as-02`, `version-04-as-05` and
  `version-06-as-07` say so.
- Random nonces come from `RAND_bytes`; any return other than 1 is an error. Never `random()`,
  `pg_prng`, or anything time-based. (`pg_strong_random` is not used either: one source.)
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
- Derive the deterministic nonce key as `HMAC-SHA256(key, "pg_gcm/v1/det-nonce")`. Never use the
  encryption key directly as the key of the HMAC over the plaintext (domain separation). The label is
  a single constant in `nonce.h`.
- No key bytes in a repository file, `postgresql.conf`, a GUC, an environment variable, a test fixture
  or any DDL. The only exception is the public vector keys in `spec/test-vectors.json`.
- That a key in a SQL statement can reach the server log is a **known operational constraint**
  (docs/ops-constraints.md). Do not write log-filtering code (`emit_log_hook`) — that is out of scope.

## Failure semantics
- Tag mismatch: with `pg_gcm.strict` on (the default) an error with the SQLSTATE `spec/envelope.md`
  fixes for it (§2.5: `XX001`) — its own, so a client can tell it from the other failure classes; with
  it off, NULL. There is no third state.
- A malformed envelope, a wrong key length, invalid UTF-8 after a successful open and a character the
  database encoding cannot hold are **always** errors, regardless of strict.
- NULL in any argument gives NULL: the functions are `STRICT`. That is argument propagation, not a failure mode, and it is not to be "fixed" into an
  error without amending the design.
- Verify and convert text only with the forms that report by return value —
  `pg_verify_mbstr(PG_UTF8, ..., true)` and `pg_do_encoding_conversion_buf(..., true)`.
  `pg_any_to_server`, `pg_server_to_any` and `pg_verify_mbstr(..., false)` format up to eight bytes of
  the offending character into the error message, and in `gcm_decrypt` those bytes are plaintext
  (design §5.7).
- Never put key, plaintext, nonce, tag or ciphertext bytes in a message, a `DETAIL`, a `HINT`, a
  `CONTEXT` callback or an assertion. Lengths, the version byte and the names of encodings are as far
  as it goes.

## The deterministic variant
- `nonce = HMAC-SHA256(nonce_key, be64(len(A)) || A || plaintext)[:12]`, with `A = version || aad` and
  the **UTF-8** plaintext bytes (spec §1.8). The associated data **is** an input: a nonce derived
  from the plaintext alone lets two AADs reuse one (key, nonce) pair, which breaks GCM's
  authentication for the whole key (design §8 O16). Changing the derivation means amending the
  design first.
- For joins, UNIQUE constraints and exact-match lookups only. Keep the warning against free text in the
  documentation and the function comments.
- `gcm_decrypt` opens either variant. A deterministic column whose uniqueness matters needs a check on
  the version byte, or a key or AAD no random-nonce column shares (docs/ops-constraints.md item 5). The extension
  does not enforce this and must not be described as enforcing it.

## Operational responsibility
- docs/ops-constraints.md item 9 is the rule: a usage budget summing every use of a key, rotation criteria,
  independent full-length keys per suite and security domain, and recovery that never resets usage
  accounting. The extension counts nothing, rotates nothing and detects no repeated nonce, and no
  document may state a universal safe limit or describe the extension as enforcing any of this.

## Patterns blocked automatically (P1) in code review
Scope is C under `src/`.

`EVP_aes_`, `HMAC(`, `\brandom\(`, `pg_prng_`, `elog.*key`, `ereport.*(key|plain)`, `errdetail.*(key|plain|nonce)`,
`StringInfo.*key`, `pg_any_to_server`, `pg_server_to_any`, `pg_verify_mbstr` with a false last
argument, a hardcoded key literal, a key length outside {16, 24, 32}, a skipped
`pg_gcm.min_key_bytes` check on encryption, a tag failure turned into NULL without consulting strict,
an unchecked `EVP_DecryptFinal_ex`, an `ereport(ERROR)` reachable while an OpenSSL context is live, a
cleanse of an argument that is not a detoasted copy, and `IMMUTABLE` or `DEFAULT NULL` in the
extension SQL script.
