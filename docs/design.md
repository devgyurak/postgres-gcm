# PostgreSQL GCM encryption functions (extension) — design and procedure

Status: **Phase 0, planning** (2026-10-10). Nothing here is implemented. Every claim about PostgreSQL
behaviour that the design leans on is either cited in §9 or listed in §8 "Open" for Phase S to settle.

## 0. Goal and scope

Give PostgreSQL the same thing [mysql-gcm](https://github.com/devgyurak/mysql-gcm) gives MySQL:
authenticated AES-GCM as SQL functions inside the server, with the decrypted value usable by the
server's own `LIKE`, and **the same envelope bytes**, so one application can move or share encrypted
columns between the two databases.

In scope: a C extension (`pg_gcm`) for self-managed PostgreSQL 15 and later (the exact majors are
settled in Phase S), its SQL API, its GUCs, tests, a release pipeline and documentation.

Out of scope: managed services that do not load third-party C extensions; key management, KMS or
keyring integration; an encryption SDK in any language; transparent or column-level encryption that
rewrites queries; index support for searching ciphertext.

## 1. Why this is needed

### 1.1 PostgreSQL has no GCM in SQL

`pgcrypto`, the contrib module most deployments already have, offers:

- `encrypt()` / `decrypt()` with `aes` in `cbc`, `cfb` or `ecb` mode — no authentication at all.
- `pgp_sym_encrypt()` — OpenPGP symmetric encryption with a SHA-1 modification-detection code. It is
  authenticated in the OpenPGP sense, but it is not GCM and it is not what a "use AES-GCM" requirement
  asks for.

Source: the PostgreSQL 18 `pgcrypto` documentation, "Raw Encryption Functions" (§9). MySQL and MariaDB
lack GCM too (mysql-gcm design §1.1, measured). SQL Server's Always Encrypted uses
AEAD_AES_256_CBC_HMAC_SHA_256 and decrypts in the client driver. Oracle added `CHAIN_GCM` to
`DBMS_CRYPTO` in 23ai; 19c has none.

Regulated sectors — healthcare in this project's case — increasingly ask for authenticated encryption
of personal data at rest, and AES-GCM is the usual answer. Without it in the database, applications
encrypt and decrypt themselves.

### 1.2 Application-side encryption loses server-side search

When the application holds the only decryption path, `WHERE name LIKE '%길%'` on an encrypted column
is impossible in SQL: every candidate row must travel to the application to be decrypted and filtered.
mysql-gcm exists to keep that search inside the server, and so does this project. A decrypted value
that comes back as `text` in the database encoding is matched by PostgreSQL's ordinary `LIKE`,
`ILIKE`, regular expressions and collations, with nothing new to learn.

### 1.3 Interoperability is the second reason

An organisation running both MySQL and PostgreSQL wants one encrypted-column format. Sharing
mysql-gcm's envelope means a column can be migrated between the two by copying bytes, a deterministic
value joins across them when key and AAD agree, and one set of test vectors guards both.

## 2. What is being built

### 2.1 Function surface

```sql
gcm_encrypt(plaintext text, key bytea, aad bytea DEFAULT NULL)      RETURNS bytea  VOLATILE PARALLEL SAFE
gcm_encrypt_det(plaintext text, key bytea, aad bytea DEFAULT NULL)  RETURNS bytea  STABLE   PARALLEL SAFE
gcm_decrypt(ciphertext bytea, key bytea, aad bytea DEFAULT NULL)    RETURNS text   STABLE   PARALLEL SAFE
```

- Names match mysql-gcm so SQL carries over. The extension is called `pg_gcm`, following the
  ecosystem's `pg_` convention, and its GUCs use the `pg_gcm.` prefix that the library reserves
  (§5.6).
- **Key length selects the suite**: 32 → AES-256-GCM, 24 → AES-192-GCM, 16 → AES-128-GCM. Anything
  else is an error, raised on every call because `key` need not be a constant.
- **NULL handling** follows mysql-gcm's failure table, adapted in Phase 1: a NULL plaintext or
  ciphertext gives NULL; a NULL key is an error. The functions are therefore not declared `STRICT`,
  which would also turn a NULL `aad` into a NULL result.
- Binary plaintext (`bytea` in, `bytea` out) is deliberately not in 0.1: overloading `text` and `bytea`
  on the first argument makes an untyped literal ambiguous. If wanted, it gets distinct names
  (`gcm_encrypt_bytes`, `gcm_decrypt_bytes`) through an amendment.

### 2.2 The envelope

Adopted from mysql-gcm `spec/envelope.md` unchanged — version byte, 12-byte nonce, ciphertext, 16-byte
tag, versions `0x02`–`0x07` (§0 of `AGENTS.md`). Phase 1 copies the spec and vectors and adds a CI check
that the copies match the pinned mysql-gcm commit. A change to the envelope happens in mysql-gcm first,
or in both projects in lockstep, never here alone.

The plaintext inside an envelope is **UTF-8**. `gcm_encrypt` converts the argument from the database
encoding to UTF-8 before sealing; `gcm_decrypt` verifies the opened bytes are valid UTF-8 and converts
them to the database encoding. A UTF-8 database (the common case) does no conversion. This is the
PostgreSQL counterpart of mysql-gcm tagging its result `utf8mb4`, and it is what makes the envelopes
portable.

`0x01`, mysql-gcm's legacy AES-256-CBC dual-read envelope, is the open question in §8: whether its
layout also describes `pgcrypto`'s `encrypt_iv(data, key, iv, 'aes-cbc')` output closely enough to give
existing pgcrypto columns the same migration path.

### 2.3 Configuration

```
# postgresql.conf — policy only, never key material (§5.4)
shared_preload_libraries = 'pg_gcm'   # optional; see §8 on fork and RAND state
pg_gcm.strict = on
pg_gcm.min_key_bytes = 32
```

`pg_gcm.strict` is `PGC_USERSET`: any session may relax it for itself, as mysql-gcm allows on 9.0+.
`pg_gcm.min_key_bytes` is `PGC_SUSET`: lowering it is an administrator decision, and PostgreSQL 15+
can delegate it with `GRANT SET ON PARAMETER`. Both are read per call through their C variables, which
PostgreSQL keeps current for the backend — no cross-thread synchronisation question arises, because a
backend is a single-threaded process.

## 3. Relationship to mysql-gcm

| Concern | mysql-gcm | postgres-gcm |
|---|---|---|
| Packaging | Component, `udf_registration` service | Extension, version-1 fmgr functions, PGXS |
| Plaintext charset | Argument converted to `utf8mb4`, result tagged `utf8mb4` | Converted to UTF-8 to seal, UTF-8 verified and converted back on open |
| Strict scope | GLOBAL on 8.x, SESSION on 9.0+ | `PGC_USERSET` on every supported major |
| Key-length floor | `gcm.min_key_bytes`, GLOBAL | `pg_gcm.min_key_bytes`, `PGC_SUSET` |
| Lifetimes | component / `UDF_INIT` / operation | library load (backend) / `FmgrInfo` (`fn_extra`) / operation |
| Errors | `mysql_runtime_error` | `ereport(ERROR, errcode(...))` with a SQLSTATE per failure class |
| Concurrency | Threads in one process | One process per backend; parallel workers are separate processes |
| Server tests | MTR + SQL scenarios | `pg_regress` (`make installcheck`) |
| Load baseline | `AES_DECRYPT` (CBC) | `pgcrypto` `decrypt()` (CBC) and `pgp_sym_decrypt()` |

What is shared without change: the envelope, the vectors, the deterministic-nonce construction and its
label, the strict semantics, and the operational responsibilities in mysql-gcm amendments A8 and A12
(usage budgets, rotation, fixed AAD per deterministic key, recovery).

## 4. Procedure

### Phase S — the spike (before the spec)

Build the smallest extension that answers the open questions in §8, on every candidate major:

1. `CREATE EXTENSION pg_gcm` from a PGXS build in `postgres:<major>` with `postgresql-server-dev-<major>`.
2. `gcm_encrypt`/`gcm_decrypt` for AES-256 only, random nonce, no AAD — enough to measure.
3. A key of the wrong length errors; `SET pg_gcm.strict = off` turns a forged tag into NULL.
4. `SELECT gcm_decrypt(gcm_encrypt('홍길동', k), k) LIKE '%길%'` is true in a UTF-8 database, and in an
   `EUC_KR` database too.
5. `EVP_CIPHER_fetch` succeeds inside a backend, with and without `shared_preload_libraries`.
6. An error raised mid-call leaks no `EVP_CIPHER_CTX`: count allocations or run under valgrind.
7. `EXPLAIN ANALYZE` of a decrypt-and-LIKE over 300k rows, and whether a sort or hash spills decrypted
   text to temporary files.

Record every answer in §8 with the command that produced it.

### Phase 1 — the spec

Copy `spec/envelope.md` and `spec/test-vectors.json` from mysql-gcm at a pinned commit. Add a
PostgreSQL section: SQLSTATE per failure class, NULL handling, the encoding rule, and the `0x01`
decision from Phase S.

### Phase 2 — implementation and tests

The core (`gcm.c`, `envelope.c`, `nonce.c`) ports mysql-gcm's C++ core to C11 with the same boundaries.
The glue (`fn_*.c`) handles arguments, encoding, GUCs and errors. Unit tests run the core against every
vector without a server; `pg_regress` covers the SQL behaviour. Per-call-site caching of the key
schedule (mysql-gcm amendment A11) comes after the baseline is measured, through an amendment here,
using `flinfo->fn_extra` and a memory-context reset callback that cleanses the key copy.

### Phase 3 — SQL E2E

A compose file with a primary, a streaming replica, a mysql-gcm server and a Python runner: round trip,
Korean `LIKE`, replication (the replica reads ciphertext it never encrypted), and an envelope sealed by
MySQL opened by PostgreSQL and the reverse.

### Phase 4 — distribution

Build matrix per major and architecture, tarballs with checksums and an SBOM, a `postgres:<major>`
image with the extension preinstalled, README and `docs/ops-constraints.md`, and the load baseline in
`docs/perf.md`.

### Phase 5 — ecosystem (optional)

PGXN, then distribution packaging if there is demand.

## 5. Design decisions and rationale

### 5.1 An extension with version-1 C functions

That is the only supported way to add SQL-callable native code without patching the server.
`CREATE EXTENSION` gives versioned install and upgrade scripts, and `DROP EXTENSION` removes the
functions cleanly.

### 5.2 The core never calls `ereport`

`ereport(ERROR)` unwinds with `longjmp`; it does not return. An `EVP_CIPHER_CTX` allocated by OpenSSL
is not tracked by a PostgreSQL memory context, so an error raised while one is live leaks it, and a key
copy in it is never cleansed. The core therefore returns an error code, and the glue releases every
OpenSSL resource and cleanses every secret before raising. This is the same boundary mysql-gcm draws
between core and adapter, made mandatory by the error model.

### 5.3 No function is `IMMUTABLE`

`gcm_encrypt_det` is deterministic in its inputs, so `IMMUTABLE` looks natural. It is refused because
an immutable function may be used in an index expression or a generated column, and the key would then
be a literal in the catalog (`pg_index`, `pg_attrdef`), readable through `pg_get_indexdef` and dumped by
`pg_dump`. An expression index on `gcm_decrypt(...)` would also store plaintext in the index. `STABLE`
is also simply correct: the result depends on `pg_gcm.min_key_bytes` and `pg_gcm.strict`.

### 5.4 The key is a SQL argument, never configuration

As in mysql-gcm amendment A1: no key in `postgresql.conf`, a GUC, a table or an environment variable.
The cost — the key is visible wherever the statement is — is an operational constraint (§6), and the
mitigation is bind parameters, not code in the extension.

### 5.5 A tag mismatch is not degraded to NULL by default

Identical to mysql-gcm: strict on means an error; off means NULL; a malformed envelope, a wrong key
length and invalid UTF-8 after a successful open are errors regardless of strict.

### 5.6 `pg_gcm.` as the GUC prefix

A custom GUC's prefix should be the library that defines it, so `MarkGUCPrefixReserved("pg_gcm")`
can reject a typo such as `pg_gcm.strcit` instead of silently creating a placeholder. mysql-gcm's
`gcm.` prefix is not reused for that reason.

## 6. Operational constraints (draft — Phase 4 moves them to `docs/ops-constraints.md` and the README)

1. **Keys and plaintext can appear in logs and statistics.** `log_statement`, `auto_explain`,
   `pg_stat_activity.query` and — because `log_min_error_statement` defaults to `error` — the log line
   of any statement that fails, including a forged-tag error. Send the key as a **bind parameter**:
   the statement text then holds `$1`, and parameters are not logged on error unless
   `log_parameter_max_length_on_error` is raised. `LIKE` patterns are plaintext fragments too.
2. **Never put a key literal in DDL.** Views, column defaults, rules, triggers, function bodies and
   policies are stored in the catalog and dumped by `pg_dump`.
3. **Decrypted values can reach disk.** A sort or hash over `gcm_decrypt(...)` that exceeds `work_mem`
   writes plaintext to temporary files (Phase S measures when). Encrypt the volume that holds
   `temp_tablespaces`.
4. **The functions are opaque to the planner.** `WHERE gcm_decrypt(col, $1) LIKE ...` scans the
   candidate set; selectivity must come from other predicates. There is no index on decrypted values,
   by design (§5.3).
5. **`gcm_encrypt_det` reveals equality and costs more than the random variant** — as mysql-gcm
   constraint 6, including one AAD convention per deterministic key (constraint 7).
6. **Self-managed PostgreSQL only.** Managed services do not load this extension.
7. **Install on every node that decrypts.** Streaming replicas get the extension's catalog entries
   through WAL but need the shared library installed on disk; a logical subscriber needs both.
8. **`pg_gcm.min_key_bytes` guards against a truncated key** — as mysql-gcm constraint 16.
9. **Usage budgets, rotation and recovery are the operator's responsibility** — as mysql-gcm
   constraints 11–13, unchanged.

## 7. License (open)

mysql-gcm is GPLv2 because it links the GPLv2 MySQL headers. PostgreSQL's headers are under the
PostgreSQL License, which places no such requirement, and the ecosystem's extensions are mostly
PostgreSQL-licensed or Apache-2.0. The crypto core will be ported from mysql-gcm, whose author is the
same, so relicensing it is the author's decision. **To decide before the first public commit of code.**

## 8. Established facts / open questions

### Confirmed (with source)

- `pgcrypto` raw encryption supports `bf` and `aes` with `cbc`, `cfb`, `ecb`; no GCM or AEAD mode.
  PGP functions append a SHA-1 MDC. (PostgreSQL 18 documentation, §9.)
- MySQL and MariaDB have no GCM in `block_encryption_mode`. (mysql-gcm design §1.1, measured.)

### Open (to be answered in Phase S)

| # | Question | How to settle it |
|---|---|---|
| O1 | Which majors to support: 15–18, and 19 if released? | Current support policy at postgresql.org; build and run the spike on each |
| O2 | Is the OpenSSL that each `postgres:<major>` image's server links 3.x on every architecture, so `EVP_CIPHER_fetch` is available? | `ldd` the server binary in each image; `openssl version` |
| O3 | With `shared_preload_libraries`, `_PG_init` runs in the postmaster and backends fork from it. Is the inherited RAND state reseeded in each child? | OpenSSL's fork detection and PostgreSQL's post-fork `pg_strong_random_init`; test two backends' first nonces |
| O4 | Do fetched `EVP_CIPHER` handles survive fork safely, or must each backend fetch its own? | OpenSSL 3 documentation on library contexts and fork; spike both |
| O5 | Does `pg_any_to_server` reject a UTF-8 character the database encoding cannot hold with an error (never a substitution)? | Spike in an `EUC_KR` and a `LATIN1` database |
| O6 | Does `0x01` (AES-256-CBC, PKCS#7, IV prefixed) match `pgcrypto`'s `encrypt_iv(..., 'aes-cbc')` with a 32-byte key? | Encrypt with pgcrypto, open with the spike |
| O7 | Which SQLSTATE fits each failure class (bad key length, bad envelope, bad tag, invalid UTF-8)? | `errcodes.txt`; prefer existing classes over a custom one |
| O8 | Is valgrind or a counting allocator the better leak gate for the `ereport` paths in CI? | Try both on the spike |
| O9 | Are custom GUC values serialised into parallel workers, so a worker sees the leader's `pg_gcm.strict`? | `SET pg_gcm.strict = off` then a forced parallel scan with a forged tag |
| O10 | Do the Debian `postgresql-server-dev-<major>` packages support `TAP_TESTS=1` for replication tests, or should replication live only in the compose E2E? | Try `make installcheck` with a TAP test |

## 9. References

- PostgreSQL 18 documentation, F.26 pgcrypto: https://www.postgresql.org/docs/current/pgcrypto.html
- PostgreSQL documentation, C-language functions and `fmgr`: https://www.postgresql.org/docs/current/xfunc-c.html
- PostgreSQL documentation, packaging related objects into an extension: https://www.postgresql.org/docs/current/extend-extensions.html
- PostgreSQL documentation, extension building infrastructure (PGXS): https://www.postgresql.org/docs/current/extend-pgxs.html
- mysql-gcm `docs/design.md` (amendments A1, A2, A5, A8, A10, A11, A12) and `spec/envelope.md`
- NIST SP 800-38D: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- Oracle `DBMS_CRYPTO` (19c and 23ai/26ai), SQL Server Always Encrypted cryptography — for §1.1 only
