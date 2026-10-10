# PostgreSQL GCM encryption functions (extension) — design and procedure

English | [한국어](design-KO.md)

Status: **Phase 0, planning** (2026-10-10). Nothing here is implemented. Every claim about PostgreSQL
behaviour that the design leans on is either cited in §9, recorded with its evidence in §8 "Confirmed",
or listed in §8 "Open" for Phase S to settle. The plan was checked against the PostgreSQL 15–18
sources, the official images and mysql-gcm on 2026-10-10; §8 records what that established.

## 0. Goal and scope

Give PostgreSQL the same thing [mysql-gcm](https://github.com/devgyurak/mysql-gcm) gives MySQL:
authenticated AES-GCM as SQL functions inside the server, with the decrypted value usable by the
server's own `LIKE`, and **the same envelope bytes**, so one application can move or share encrypted
columns between the two databases.

In scope: a C extension (`pg_gcm`) for self-managed PostgreSQL 15–18 (19 once it is released, §8 O1)
**whose server links OpenSSL 3.0 or later**, its SQL API, its GUCs, tests, a release pipeline and
documentation.

Out of scope: managed services that do not load third-party C extensions; servers linked against
OpenSSL 1.1.1, which have no `EVP_CIPHER_fetch` (the PGDG packages for RHEL/Rocky 8, §8); key
management, KMS or keyring integration; an encryption SDK in any language; transparent or column-level
encryption that rewrites queries; index support for searching ciphertext.

## 1. Why this is needed

### 1.1 PostgreSQL's core and contrib have no GCM in SQL

`pgcrypto`, the contrib module most deployments already have, offers:

- `encrypt()` / `decrypt()` with `aes` in `cbc` or `ecb` mode, and `cfb` from PostgreSQL 18 — no
  authentication at all.
- `pgp_sym_encrypt()` — OpenPGP symmetric encryption with a SHA-1 modification-detection code. It is
  authenticated in the OpenPGP sense, but it is not GCM and it is not what a "use AES-GCM" requirement
  asks for.

Source: the PostgreSQL 18 `pgcrypto` documentation, "Raw Encryption Functions" (§9), and the cipher
table in `contrib/pgcrypto/openssl.c` for 15–18 and 19beta4 (§8). MySQL and MariaDB lack GCM too
(mysql-gcm design §1.1, measured). SQL Server's Always Encrypted uses AEAD_AES_256_CBC_HMAC_SHA_256 and
decrypts in the client driver; its secure enclaves (SQL Server 2019 and later) add pattern matching
inside an enclave. Oracle added `CHAIN_GCM` to `DBMS_CRYPTO` in 23ai; 19c has none.

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

### 1.4 The existing extensions do not fill the gap

Checked on 2026-10-10 (repository metadata and PGXN; a search cannot prove nothing else exists).

| Project | What it offers | Why it is not the answer |
|---|---|---|
| [pgsodium](https://github.com/michelp/pgsodium) | libsodium AEAD in SQL: ChaCha20-Poly1305-IETF, deterministic XChaCha20-SIV, `crypto_secretbox`. PostgreSQL License, v3.1.11 (2026-06-10) | No AES-GCM, so it does not meet a "use AES-GCM" requirement, and its formats are not mysql-gcm's envelope. Supabase's documentation advises against it because it is to be deprecated |
| [pgcrypsi](https://github.com/telkomdev/pgcrypsi) | `pgcrypsi_aes_{128,192,256}_gcm_{encrypt,decrypt}` with the key as an argument. MIT | The PostgreSQL sibling of the UDF mysql-gcm design §1.3 turned down, for the same reasons: last pushed 2023-09-11, built for OpenSSL 1.1.1 and `postgresql-server-dev-10`, and not mysql-gcm's envelope |
| pg_tde (Percona), pg_vault_tde | Encryption at the storage layer (a table access method) | Transparent encryption of data at rest; no SQL function, no envelope a second database can open |

## 2. What is being built

### 2.1 Function surface

```sql
gcm_encrypt(plaintext text, key bytea)                 RETURNS bytea  VOLATILE STRICT PARALLEL SAFE
gcm_encrypt(plaintext text, key bytea, aad bytea)      RETURNS bytea  VOLATILE STRICT PARALLEL SAFE
gcm_encrypt_det(plaintext text, key bytea)             RETURNS bytea  STABLE   STRICT PARALLEL SAFE
gcm_encrypt_det(plaintext text, key bytea, aad bytea)  RETURNS bytea  STABLE   STRICT PARALLEL SAFE
gcm_decrypt(ciphertext bytea, key bytea)               RETURNS text   STABLE   STRICT PARALLEL SAFE
gcm_decrypt(ciphertext bytea, key bytea, aad bytea)    RETURNS text   STABLE   STRICT PARALLEL SAFE
```

- Names match mysql-gcm so SQL carries over. The extension is called `pg_gcm`, following the
  ecosystem's `pg_` convention, and its GUCs use the `pg_gcm.` prefix that the library reserves
  (§5.6).
- **Key length selects the suite**: 32 → AES-256-GCM, 24 → AES-192-GCM, 16 → AES-128-GCM. Anything
  else is an error, raised on every call because `key` need not be a constant.
- **NULL handling is mysql-gcm's** (`spec/envelope.md` §4, rule 3): SQL NULL in any argument yields
  SQL NULL, with no cryptographic work. Every function is therefore declared `STRICT`, and the server
  returns NULL without calling it.
- **AAD is optional through overloading, not through `DEFAULT NULL`**, so that a call that omits
  `aad` encrypts while an explicit NULL propagates. **A NULL default cannot give both.** Under
  `STRICT`, a defaulted NULL makes the two-argument call return NULL without encrypting anything
  (reproduced on 15–18, §8). Dropping `STRICT` so that NULL reads as "no AAD" would instead make an
  explicit NULL — a nullable column, an unset bind parameter — seal silently *without* AAD; under one
  deterministic key that mixes "with AAD" and "without AAD" writes of the same plaintext, the
  nonce-reuse condition `spec/envelope.md` §3 forbids, and it would no longer be mysql-gcm's NULL
  rule. With two overloads,
  the two-argument form means "no AAD", a NULL `aad` in the three-argument form gives NULL as it does
  in MySQL, and an empty `aad` (`''`) seals exactly as the two-argument form does.
  A non-NULL default would give both as well: `aad bytea DEFAULT ''` with `STRICT` runs with an empty
  AAD when the argument is omitted and still returns NULL for an explicit one (§8). Overloading is the
  choice made, not the only correct one; it keeps the surface as two arities, the way mysql-gcm's
  optional argument reads, with no default expression to explain.
- A consequence of `STRICT` to state wherever the functions are documented: **a missing key yields
  NULL, not an error.** Declare an encrypted column `NOT NULL` when its plaintext is never NULL, so an
  unset key parameter fails the statement instead of storing NULL (§6, item 11).
- Each function is declared with an explicit `COST`, settled in Phase S from the measured per-call
  cost. A C function defaults to cost 1, and the planner orders the quals of one scan by cost, so
  without it `gcm_decrypt(...) LIKE ...` is not placed after the cheap predicates that §6 item 4
  relies on.
- Binary plaintext (`bytea` in, `bytea` out) is deliberately not in 0.1: overloading `text` and `bytea`
  on the first argument makes an untyped literal ambiguous. If wanted, it gets distinct names
  (`gcm_encrypt_bytes`, `gcm_decrypt_bytes`) through an amendment.

### 2.2 The envelope

Adopted from mysql-gcm `spec/envelope.md` unchanged — version byte, 12-byte nonce, ciphertext, 16-byte
tag, versions `0x02`–`0x07` (`AGENTS.md` §2). Phase 1 copies the spec and vectors and adds a CI check
that the copies match the pinned mysql-gcm commit. A change to the envelope happens in mysql-gcm first,
or in both projects in lockstep, never here alone.

mysql-gcm's spec is not yet divided into a shared part and a server binding: its §1 and §4 speak of
`utf8mb4`, GLOBAL variables and `UDF_INIT`. The byte contract this project shares is its §2 (layout),
§3 (derivation), §5 (worked examples) and the vector schema in §6; the CI check compares those. The
PostgreSQL binding — SQLSTATEs, the encoding rule, the exceptions below — is a separate, clearly
marked part. Dividing the upstream file the same way is a follow-up for mysql-gcm, not a precondition.

The plaintext inside an envelope is **UTF-8**. `gcm_encrypt` converts the argument from the database
encoding to UTF-8 before sealing; `gcm_decrypt` verifies the opened bytes are valid UTF-8 and converts
them to the database encoding (§5.7 says how, and why not with the obvious server functions). A UTF-8
database (the common case) does no conversion. This is the PostgreSQL counterpart of mysql-gcm tagging
its result `utf8mb4`, and it is what makes the envelopes portable.

**Portable has three exceptions**, each of which authenticates and then fails as an error that
`pg_gcm.strict` does not hide:

1. A plaintext containing U+0000. MySQL's `utf8mb4` holds it; PostgreSQL `text` cannot, and UTF-8
   verification rejects the zero byte on every supported major (§8).
2. An envelope MySQL sealed from a `binary` argument that is not UTF-8 (mysql-gcm spec §2.3 notes that
   `gcm_encrypt(UNHEX('ff'), key)` seals `FF`). MySQL returns an ill-formed string; PostgreSQL raises.
3. A character the database encoding cannot hold, in a database that is not UTF-8.

`0x01`, mysql-gcm's legacy AES-256-CBC dual-read envelope (`0x01 || iv(16) || CBC ciphertext`,
mysql-gcm amendment A3), stays open as §8 O6. Two outcomes are possible, and Phase S chooses on two
grounds — compatibility and security policy: implement it as mysql-gcm does, if
`'\x01' || iv || encrypt_iv(data, key, iv, 'aes-cbc')` from `pgcrypto` with a 32-byte key opens
correctly, which gives existing pgcrypto columns a migration path without re-encryption; or leave it
unimplemented, which the spec's failure table already allows ("allocated-but-unimplemented version
byte" → `bad_envelope`). The second costs the two `legacy` vectors a different expectation here and
means a `0x01` row copied from MySQL does not open.

If it is implemented, two conditions come with it and are stated wherever `0x01` is exposed:

- **Prefixing is a migration only for legacy plaintext that is already UTF-8** (mysql-gcm spec §2.3).
  `encrypt_iv` takes `bytea` and converts nothing, so a column encrypted from LATIN1 bytes — `Müller`
  as `4D FC 6C 6C 65 72` — opens and then fails UTF-8 verification. PostgreSQL fails loudly where MySQL
  returns an ill-formed string, but it fails row by row: pure-ASCII values pass and the rest do not.
  Data in any other encoding is decrypted the old way, converted, and re-sealed with `gcm_encrypt`.
- **`0x01` is an exception to the authentication guarantee.** CBC has no tag: a changed IV or
  ciphertext block yields changed plaintext that still opens, `pg_gcm.strict = on` cannot detect it,
  and a wrong key can return garbage instead of an error. Adopting `0x01` therefore also means
  deciding how it is refused once a migration is over. mysql-gcm leaves that to the application (its
  constraint 8); a switch inside the extension would be a new GUC and an amendment in both projects.

### 2.3 Configuration

```
# postgresql.conf — policy only, never key material (§5.4)
shared_preload_libraries = 'pg_gcm'   # optional; it makes the two settings below validated at start
pg_gcm.strict = on
pg_gcm.min_key_bytes = 32
```

`pg_gcm.strict` is `PGC_USERSET`: any session may relax it for itself, as mysql-gcm allows on 9.0+.
`pg_gcm.min_key_bytes` is `PGC_SUSET`: lowering it is an administrator decision, and PostgreSQL 15+
can delegate it with `GRANT SET ON PARAMETER`. Both are read per call through their C variables, which
PostgreSQL keeps current for the backend — no cross-thread synchronisation question arises, because a
backend is a single-threaded process.

Without preloading, the library loads in a backend on the first call of one of its functions, and
until then `pg_gcm.*` names are placeholders (§8, confirmed on 15–18):

- `SET` accepts any value and any spelling, and `SHOW` then returns that unvalidated value:
  `SET pg_gcm.strict = off; SHOW pg_gcm.strict;` prints `off` on a server where the extension is not
  even installed. **A successful `SHOW` does not mean the library is loaded or the value was
  checked.** Only a name that was never set fails ("unrecognized configuration parameter").
- When the library loads, a placeholder for `pg_gcm.min_key_bytes` set by a role without the privilege
  is **discarded with a WARNING and the default of 32 stands** — the floor cannot be lowered by setting
  it early. A misspelt name is removed with a WARNING.
- Values from `postgresql.conf` are applied at load. A typo there is never rejected, only warned about
  in every session that loads the library.
- `ALTER SYSTEM SET pg_gcm.…` fails on 15 and 16 unless the library is loaded in that session, and is
  accepted without validation on 17 and 18.

A deployment that wants its configuration checked when the server starts preloads the library.

## 3. Relationship to mysql-gcm

| Concern | mysql-gcm | postgres-gcm |
|---|---|---|
| Packaging | Component, `udf_registration` service | Extension, version-1 fmgr functions, PGXS |
| Plaintext charset | Argument converted to `utf8mb4`, result tagged `utf8mb4` | Converted to UTF-8 to seal, UTF-8 verified and converted back on open |
| NULL arguments | NULL in any argument gives NULL | The same, through `STRICT` |
| Ill-formed plaintext | Returned as an ill-formed string | An error (§2.2) |
| Strict scope | GLOBAL on 8.x, SESSION on 9.0+ | `PGC_USERSET` on every supported major |
| Key-length floor | `gcm.min_key_bytes`, GLOBAL | `pg_gcm.min_key_bytes`, `PGC_SUSET` |
| Lifetimes | component / `UDF_INIT` / operation | library load (backend) / `FmgrInfo` (`fn_extra`) / operation |
| Errors | `mysql_runtime_error` | `ereport(ERROR, errcode(...))` with a SQLSTATE per failure class |
| Concurrency | Threads in one process | One process per backend; parallel workers are separate processes |
| Server tests | MTR + SQL scenarios | `pg_regress` (`make installcheck`) |
| Load baseline | `AES_DECRYPT` (CBC) | `pgcrypto` `decrypt()` (CBC) and `pgp_sym_decrypt()` |

What is shared without change: the envelope, the vectors, the deterministic-nonce construction and its
label, the strict semantics, the NULL rule, and the operational responsibilities in mysql-gcm's
amendment A8 "operational responsibility for keys and nonces" and amendment A12 (usage budgets,
rotation, fixed AAD per deterministic key, recovery).

## 4. Procedure

### Phase S — the spike (before the spec)

Build the smallest extension that answers the open questions in §8, on every supported major:

1. `CREATE EXTENSION pg_gcm` from a PGXS build in `postgres:<major>` with
   `postgresql-server-dev-<major>` pinned to the image's `PG_VERSION`.
2. `gcm_encrypt`/`gcm_decrypt` for AES-256 only, random nonce, no AAD — enough to measure.
3. A key of the wrong length errors; `SET pg_gcm.strict = off` turns a forged tag into NULL.
4. `SELECT gcm_decrypt(gcm_encrypt('홍길동', k), k) LIKE '%길%'` is true in a UTF-8 database, and in an
   `EUC_KR` database too.
5. With `shared_preload_libraries`, the handles fetched in the postmaster work in two forked backends:
   an AES-GCM round trip and the HMAC-SHA256 nonce-key vector both pass (O4), and the two backends'
   first random nonces differ. Without it, the same holds for handles fetched in the backend.
6. No call that can raise sits between acquiring and releasing an `EVP_CIPHER_CTX`. Nothing can count
   OpenSSL allocations inside a backend (§8), so this is shown by the structure of the glue and by the
   unit suite's counting allocator over every core error path; log what `CRYPTO_set_mem_functions`
   returns from `_PG_init` to keep that fact on record.
7. `EXPLAIN ANALYZE` of a decrypt-and-LIKE over 300k rows, whether a sort or hash spills decrypted
   text to temporary files, and the per-row cost of a `PG_TRY` block (O12).
8. `ldd` the server binary in each image on amd64 as well as arm64 (O11).

Record every answer in §8 with the command that produced it.

### Phase 1 — the spec

Copy `spec/envelope.md` and `spec/test-vectors.json` from mysql-gcm at a pinned commit. Add the
PostgreSQL binding as a separate part (§2.2): SQLSTATE per failure class, the encoding rule and its
three exceptions, the `0x01` decision from Phase S, and what the SQL layer expects for a vector whose
plaintext is not UTF-8. At mysql-gcm `2fe2da9` that is 1,345 of the 2,304 vectors (1,344 NIST cases and
one deterministic case): the core opens them and the unit suite compares the bytes; through SQL the
expected result is "authenticates, then the invalid-UTF-8 error", because `gcm_decrypt` returns `text`.

### Phase 2 — implementation and tests

The core (`gcm.c`, `envelope.c`, `nonce.c`) ports mysql-gcm's C++ core to C11 with the same boundaries.
The glue (`fn_*.c`) handles arguments, encoding, GUCs and errors. Unit tests run the core against every
vector without a server; `pg_regress` covers the SQL behaviour. Per-call-site caching of the key
schedule (mysql-gcm amendment A11) comes after the baseline is measured, through an amendment here,
using `flinfo->fn_extra` and a memory-context reset callback that cleanses the key copy. That amendment
cannot borrow A11's lifetime bound: a `UDF_INIT` is one execution of one statement, while an `FmgrInfo`
can live longer — PL/pgSQL keeps the state of a simple expression until the end of the transaction
(`pl_exec.c`, `shared_simple_eval_estate`).

### Phase 3 — SQL E2E

A compose file with a primary, a streaming replica, a mysql-gcm server and a Python runner: round trip,
Korean `LIKE`, replication (the replica reads ciphertext it never encrypted), an envelope sealed by
MySQL opened by PostgreSQL and the reverse, and NULL arguments giving NULL on both.

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

### 5.2 The core never calls `ereport`, and what the glue cleanses

`ereport(ERROR)` unwinds with `longjmp`; it does not return. An `EVP_CIPHER_CTX` allocated by OpenSSL
is not tracked by a PostgreSQL memory context, so an error raised while one is live leaks it, and a key
copy in it is never cleansed. The core therefore returns an error code, and the glue releases every
OpenSSL resource and cleanses every secret before raising. This is the same boundary mysql-gcm draws
between core and adapter, made mandatory by the error model. (`pgcrypto` solves the same problem with a
ResourceOwner callback, whose API differs between 15–16 and 17+; keeping raising calls out of the
window needs no version-specific code.)

**The cleansing rule covers the copies the extension makes, and only those**: a detoasted argument, a
conversion buffer, scratch space, the opened plaintext before it becomes the result.

- An argument that needed no detoasting is the executor's own storage — a constant in a cached plan,
  the portal's parameter value, or a tuple in a shared buffer page. **It is never written to.**
  Cleansing it in place would zero the key in a cached plan or corrupt a table page; the copy test is
  the one `PG_FREE_IF_COPY` uses (pointer inequality with `PG_GETARG_POINTER`).
- The result `text`, the caller's datums, and the copies the planner makes when it evaluates a `STABLE`
  call (§5.3) are outside the extension's reach. Cleansing is defence in depth for our own buffers, not
  a guarantee that no copy of a key remains in backend memory.
- A stretch of glue that holds one of our own secret copies and can still raise — `palloc` on
  out-of-memory, for one — is wrapped in `PG_TRY` / `PG_FINALLY`, so the copy is cleansed on the error
  path too. No OpenSSL context is live inside such a block.

### 5.3 No function is `IMMUTABLE`

`gcm_encrypt_det` is deterministic in its inputs, so `IMMUTABLE` looks natural. It is refused because
an immutable function may be used in an index expression, an index predicate, a generated column or a
partition key, and the key would then be a literal in the catalog (`pg_index`, `pg_attrdef`), readable
through `pg_get_indexdef` and dumped by `pg_dump`. An expression index on `gcm_decrypt(...)` would also
store plaintext in the index. `STABLE` is also simply correct: the result depends on
`pg_gcm.min_key_bytes` and `pg_gcm.strict`.

Three things follow from `STABLE`, each confirmed on 15–18 (§8):

- It keeps the deterministic variant useful: `WHERE det_col = gcm_encrypt_det($1, $2)` can use a btree
  index on the ciphertext column, which a `VOLATILE` function could not.
- The planner may run a `STABLE` function with constant or bound arguments while estimating
  selectivity. A `gcm_decrypt` error can therefore surface from a plain `EXPLAIN` or at Bind, and the
  planner holds its own copy of the arguments at that moment.
- It is not a barrier. PostgreSQL trusts the volatility label of a wrapper, so a user who writes an
  `IMMUTABLE` SQL function around `gcm_decrypt` can index it. That is an operational constraint (§6,
  item 2), not something the extension can prevent.

### 5.4 The key is a SQL argument, never configuration

As in mysql-gcm amendment A1: no key in `postgresql.conf`, a GUC, a table or an environment variable.
The cost — the key is visible wherever the statement is — is an operational constraint (§6), and the
mitigation is bind parameters, not code in the extension.

Encrypting inside the server draws a trust boundary that the extension cannot move, the one `pgcrypto`
documents for itself ("Security Limitations", §9): the key and the plaintext cross the client
connection, and they exist in the memory of a server its administrators control. The design protects
stored columns, backups and replicas that hold only ciphertext. It does not protect against an
unprotected connection, the database superuser or the server's operating-system administrator (§6,
item 12).

### 5.5 A tag mismatch is not degraded to NULL by default

Identical to mysql-gcm: strict on means an error; off means NULL; a malformed envelope, a wrong key
length and invalid UTF-8 after a successful open are errors regardless of strict.

### 5.6 `pg_gcm.` as the GUC prefix

A custom GUC's prefix should be the library that defines it, so that
`MarkGUCPrefixReserved("pg_gcm")` applies. What that buys is narrower than it sounds (§2.3, §8): once
the library is loaded in a backend, `SET pg_gcm.strcit` is an error; before that, and in
`postgresql.conf`, the typo is accepted as a placeholder and removed with a WARNING at load. mysql-gcm's
`gcm.` prefix is not reused, because the reserved prefix must be the library's own.

### 5.7 Encoding without letting the server write the message

The obvious functions are the wrong ones. `pg_any_to_server`, `pg_server_to_any` and
`pg_verify_mbstr(..., noError = false)` report a failure by formatting up to eight bytes of the
offending character into the error message (`invalid byte sequence for encoding "UTF8": 0x…`,
`character with byte sequence 0x… has no equivalent…`). In `gcm_decrypt` those bytes are decrypted
plaintext, in a message that goes to the client and the server log. They also allocate the converted
copy internally, so when they raise, the caller holds no pointer to cleanse.

The glue therefore uses the forms that report by return value, present on every supported major (§8):

- `pg_verify_mbstr(PG_UTF8, bytes, len, true)` — false means invalid UTF-8, including a zero byte.
- `pg_do_encoding_conversion_buf(proc, src, dest, in, inlen, out, outlen, true)` into a buffer the
  glue allocated (`inlen * MAX_CONVERSION_GROWTH + 1`, overflow-checked against `MaxAllocSize`). A
  count shorter than `inlen` after a successful verification means a character the target cannot hold.
- The conversion procedure comes from `FindDefaultConversionProc`, a catalog lookup that can raise
  (with no data in its message). It runs before any secret copy exists.

| Database encoding | `gcm_encrypt*` | `gcm_decrypt` |
|---|---|---|
| UTF8 | Bytes used as they are; the server validated them on input | Verify, then use as they are |
| SQL_ASCII | Verify as UTF-8; the bytes carry no encoding, so non-UTF-8 is an error | Verify, then use as they are |
| Any other | Convert to UTF-8 | Verify, then convert to the database encoding |

Every failure is raised by the glue, after cleansing, with a message that names the encodings and
lengths and nothing else.

### 5.8 `_PG_init` fetches first and never raises

`_PG_init` fetches the `EVP_CIPHER` and `EVP_MAC` handles **before** it registers the GUCs, and a
failed fetch is recorded, not raised; each function call then fails with the OpenSSL error class. Two
facts about library loading require this (§8). Under `shared_preload_libraries`, an `ERROR` in
`_PG_init` is fatal to the postmaster, so the server would not start. Under lazy loading, the library
is not marked loaded until `_PG_init` returns, so an `ERROR` after `DefineCustom*Variable` makes every
later call re-run `_PG_init` and fail with "attempt to redefine parameter", hiding the real cause.

The handles live for the life of the process and are not released. An `on_proc_exit` callback
registered while preloading would never run in a backend — the child discards the postmaster's
callbacks — and the process is exiting anyway.

## 6. Operational constraints (draft — Phase 4 moves them to `docs/ops-constraints.md` and the README)

1. **Keys and plaintext can appear in logs and statistics.** `log_statement`, `auto_explain`,
   `pg_stat_activity.query` and — because `log_min_error_statement` defaults to `error` — the log line
   of any statement that fails, including a forged-tag error. Send the key as a **bind parameter**, so
   the statement text holds `$1` — **and set `log_parameter_max_length = 0`**. Its default of -1 logs
   every bind value in full on the lines that `log_statement`, `log_min_duration_statement` and the
   sampling settings write, so a bind parameter alone does not keep a key out of the slow-statement
   log. Leave `log_parameter_max_length_on_error` at its default of 0. Do not run `auto_explain` on a
   database that takes key-bearing statements: from 16 it logs "Query Parameters", and on every major
   a custom plan's text contains the parameter values. `LIKE` patterns are plaintext fragments too.
2. **Never put a key literal in DDL.** Views, column defaults, check constraints, rules, triggers,
   function bodies and policies are stored in the catalog and dumped by `pg_dump`. Do not wrap these
   functions in a function declared `IMMUTABLE` to index them (§5.3).
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
10. **The server must link OpenSSL 3.0 or later.** The official `postgres` images do. The PGDG packages
    for RHEL/Rocky 8 link 1.1.1 and are not supported. OpenSSL 3.0 itself left upstream support on
    2026-09-07; prefer a platform on 3.5.
11. **A NULL argument gives NULL, silently.** A key parameter that was never bound stores NULL instead
    of failing. Put `NOT NULL` on an encrypted column whose plaintext is never NULL.
12. **Protect the connection, and trust the server's administrators.** Every key and plaintext travels
    from the client to the server. Connect over a protected local socket, or over TLS **with the
    server's certificate verified** (`sslmode=verify-full`); without that, bind parameters and the log
    settings in item 1 leave them readable on the network, or deliverable to an impostor server. The
    database superuser and the operating-system administrator of every node that decrypts can observe
    them and must be trusted — the same limitation `pgcrypto` documents.

## 7. License — the PostgreSQL License (settled 2026-10-10)

The full text is in `LICENSE`; every source file carries `SPDX-License-Identifier: PostgreSQL`.

- **Why not GPLv2, as mysql-gcm.** mysql-gcm is GPLv2 because a component links the GPLv2 MySQL
  headers. PostgreSQL's headers are under the PostgreSQL License, which imposes nothing comparable, so
  that reason does not carry over.
- **Why the PostgreSQL License.** It is the license of PostgreSQL itself and of most of its contrib
  modules, so the extension can be packaged by distributions, listed on PGXN and read by the community
  without a license question. It is a short permissive license, compatible with OpenSSL 3's
  Apache-2.0.
- **Why not Apache-2.0.** Its patent grant is the real advantage, but this project implements a
  published, unencumbered construction (AES-GCM, HMAC-SHA256) and holds no patents, and matching the
  host project mattered more.
- **Porting from mysql-gcm.** The core is ported from mysql-gcm, whose `src/` and `spec/` were written
  by one author, the same as this project's (checked with `git log` on 2026-10-10). That author can
  license the port here under the PostgreSQL License while mysql-gcm stays GPLv2. Code contributed to
  mysql-gcm by anyone else is **not** ported without that contributor's written permission.

## 8. Established facts / open questions

### Confirmed (with source)

Unless a line says otherwise, "source" is the PostgreSQL tree at the tip of each stable branch on
2026-10-10 (15.19, 16.15, 17.11, 18.6; line numbers are `REL_17_STABLE`), and "run" is `psql` against
the official `postgres:15`–`18` images on linux/arm64 the same day.

- License: the PostgreSQL License (§7; `LICENSE`).
- `pgcrypto` raw encryption supports `bf` and `aes` with `cbc` and `ecb`, and `cfb` from 18 (commit
  9ad1b3d01); no GCM or AEAD mode in 15–18, 19beta4 or master. PGP functions append a SHA-1 MDC.
  (Source: the cipher table in `contrib/pgcrypto/openssl.c`; `pgcrypto.sgml`; the 18 release notes.)
- MySQL and MariaDB have no GCM in `block_encryption_mode`. (mysql-gcm design §1.1, measured.)
- **mysql-gcm returns NULL for a NULL in any argument.** (`spec/envelope.md` §4 rule 3;
  `src/udf_glue.cc` `any_arg_is_null`, at `2fe2da9`.)
- **O2 — OpenSSL linked.** `postgres:15`–`18` (Debian trixie) link OpenSSL 3.5.7, the `-alpine`
  variants 3.5.8, `postgres:17-bookworm` 3.0.22. PGDG servers on Rocky 8 link `libcrypto.so.1.1` for 15
  and for 18. (Run: `ldd $(which postgres)` and `openssl version`, arm64 only — amd64 is O11.)
- **O3 — RAND after fork.** OpenSSL 3 reseeds a DRBG in a forked child: `drbg.c` compares a fork id
  (`getpid()`) on every generate, in 3.0 and 3.5. PostgreSQL 15–17 also call `RAND_poll()` in each
  child (`fork_process.c`); 18 does not, relying on OpenSSL ≥ 1.1.1. (Source only; OpenSSL's manual
  pages do not document the behaviour, so Phase S step 5 still checks it.)
- **O5 — untranslatable characters.** They are an error (`22P05`), never a substitution, and a zero
  byte fails UTF-8 verification (`22021`) on every major. But the stock functions put the offending
  bytes in the message (`mbutils.c:1851`, `:1898`), hence §5.7. (Source.)
- **The noError forms exist on 15–18.** `pg_verify_mbstr(int, const char *, int, bool noError)` and
  `pg_do_encoding_conversion_buf(Oid, int, int, unsigned char *, int, unsigned char *, int, bool
  noError)` (`mb/pg_wchar.h`; the latter since 14). `pg_unicode_to_server_noerror` is 16+ only and is
  not used. (Source.)
- **An argument that was not detoasted is the executor's storage.** `pg_detoast_datum_packed` copies
  only compressed or external values; a `Const` is the plan tree's datum, a bind parameter lives in
  the portal context, a column value points into the buffer page. `xfunc.sgml`: "Never modify the
  contents of a pass-by-reference input value". (Source: `fmgr.c`, `execExpr.c`, `execTuples.c`.)
- **O8 — the leak gate.** `CRYPTO_set_mem_functions` returns 0 once OpenSSL has allocated anything
  (`crypto/mem.c`, `allow_customize`), and the postmaster calls `RAND_bytes` before it loads preloaded
  libraries, so a counting allocator cannot be installed inside a backend. Valgrind on a server not
  built with `USE_VALGRIND` gives false positives (`pg_config_manual.h`), and the official images are
  not built with it. The gate is the unit suite's counting allocator. (Source; OpenSSL 3.0 and 3.5.)
- **O9 — parallel workers.** A worker loads the leader's libraries and then restores every non-default
  GUC, custom, `PGC_SUSET` and `SET LOCAL` values included (`parallel.c:1446-1457`;
  `guc.c` `can_skip_gucvar`). (Source, and run on 15–18 with a session value and a `SET LOCAL` value.)
- **O10 — TAP tests.** `postgresql-client-<major>` ships `pg_regress`, PGXS's `Makefile.global` with
  `enable_tap_tests = yes` and `PostgreSQL::Test::Cluster` for 15–18 and 19beta4. A TAP run also needs
  `libipc-run-perl` and a non-root user. (PGDG packages unpacked on 2026-10-09; not executed.)
- **`STRICT` and a NULL default.** A `STRICT` function declared with `aad DEFAULT NULL` returns NULL
  when `aad` is omitted — the default is filled in as an ordinary argument, so the strictness check
  sees a NULL — while two overloads
  call the two-argument body, and an explicit NULL gives NULL. (Run on 15–18: three throwaway
  `LANGUAGE sql STRICT` functions, `f(a, b DEFAULT NULL)`, `g(a)` and `g(a, b)`; `f('x')` is NULL,
  `g('x')` is not, `g('x', NULL)` is NULL. A fourth, `h(a, b bytea DEFAULT '')`, runs with a
  zero-length `b` when it is omitted and gives NULL for `h('x', NULL)`.)
- **Placeholders.** Before the library loads, `SHOW` returns whatever a placeholder was set to and
  errors only for a name never set (run on 15–18: `SET pg_gcm.strict = off; SHOW pg_gcm.strict;`
  prints `off` with no extension installed). A value set for `pg_gcm.min_key_bytes` before the library
  loads by a role without the privilege is discarded with `WARNING: permission denied to set
  parameter` and the default stands; a misspelt name set before load is removed with a WARNING, and
  set after load is an error;
  configuration files are exempt from the reserved-prefix test; `ALTER SYSTEM` for an unknown two-part
  name errors on 15–16 and is accepted on 17–18. (Source: `guc.c:5001-5021`, `:1115`, `:1144-1160`,
  `:5305-5322`. Run on 15–18 with `plpgsql.variable_conflict`, an in-core lazily-loaded `PGC_SUSET`
  variable: `SET`, then `DO $$ BEGIN END $$`, then `SHOW`.)
- **Volatility.** `IMMUTABLE` is required for index expressions and predicates, generated columns and
  partition keys; an `IMMUTABLE` wrapper around a `STABLE` function is accepted in an index; the
  planner evaluates a `STABLE` function with constant or bound arguments when estimating
  (`clauses.c:3816`), so `EXPLAIN` alone can raise its error; a `STABLE` call is usable as an index
  comparison value and a `VOLATILE` one is not (`indxpath.c`). (Source, and run on 15–18.)
- **Bind-parameter logging.** `log_parameter_max_length` defaults to -1 and
  `log_parameter_max_length_on_error` to 0 (`guc_tables.c:3054-3073`); the statement-logging paths
  append `Parameters:` whenever the former is not 0 (`postgres.c:2506-2512`).
  `auto_explain.log_parameter_max_length` exists from 16. (Source; the defaults also read from
  `pg_settings` on 16. The log line itself was not produced.)
- **`_PG_init`.** An `ERROR` with no exception stack is promoted to `FATAL` (`elog.c:378-384`), which
  is the postmaster under preload; `dfmgr.c:287-296` lists a library only after `_PG_init` returns;
  `InitPostmasterChild` calls `on_exit_reset()` (`miscinit.c:129`). (Source.)
- **Header change in 16.** `VARDATA_ANY`, `VARSIZE_ANY_EXHDR` and `SET_VARSIZE` moved to `varatt.h`,
  which `postgres.h` and `fmgr.h` do not include; the glue includes it under
  `PG_VERSION_NUM >= 160000`, as `pgcrypto.c` does. `MarkGUCPrefixReserved` exists from 15. (Source.)
- **Qual ordering.** A C function's default cost is 1 (`functioncmds.c`) and `order_qual_clauses`
  sorts by cost. (Source, 18.)
- **`\df+` differs by major.** 15 prints "Source code", 16–17 "Internal name", 18 adds "Leakproof?"
  (`describe.c`). The volatility test reads `pg_proc` instead. (Source.)
- **`pg_regress` and `\c`.** `pg_regress` unsets `PGCLIENTENCODING` unless `--encoding` is given, and
  after `\c` psql takes the new database's encoding as the client encoding; `--load-extension` applies
  only to the databases `pg_regress` creates. (Source: `pg_regress.c`, `psql/command.c`; not run.)

### Open (to be answered in Phase S)

Numbers are never reused; O2, O3, O5, O8, O9 and O10 moved to "Confirmed" above.

| # | Question | How to settle it |
|---|---|---|
| O1 | When does 19 join the supported majors? 15–18 are settled. 19 is at beta 4, with RC1 announced for 2026-10-15 and release for 2026-10-29 (pgsql-hackers, 2026-09-28) | Add it to `docker/versions.json` when the release image exists; until then build the spike against `19beta4` |
| O4 | Do `EVP_MAC` handles fetched in the postmaster work in forked backends? `EVP_CIPHER` has precedent — the postmaster's `SSL_CTX` fetches ciphers before forking — but nothing documents either | Phase S step 5: preload, then a known-answer HMAC in two backends |
| O6 | Is `0x01` (AES-256-CBC, PKCS#7, IV prefixed) implemented, and on what terms (§2.2)? Compatibility: does it match `pgcrypto`'s `encrypt_iv(..., 'aes-cbc')` with a 32-byte key? Security policy: it is unauthenticated and `pg_gcm.strict` cannot see tampering, so adopting it means stating that exception and deciding how `0x01` is refused after a migration | Encrypt with pgcrypto, open with the spike; then decide both parts together, not compatibility alone |
| O7 | Which SQLSTATE fits each failure class (bad key length, bad envelope, bad tag, invalid UTF-8, untranslatable character, OpenSSL failure)? Candidates in use elsewhere: `22023`, `XX001`, `22021`, `22P05`; `pgcrypto` raises everything as `39000` | `errcodes.txt`; prefer existing classes over a custom one, and one class per failure so a client can tell a forged tag from a wrong key length |
| O11 | Do the amd64 images link the same OpenSSL as the arm64 ones checked for O2? | `ldd` and `openssl version` on amd64 |
| O12 | What does a `PG_TRY` block per call cost over 300k rows, and does it change the load gate? | Phase S step 7, with and without the block |

## 9. References

- PostgreSQL 18 documentation, F.26 pgcrypto: https://www.postgresql.org/docs/18/pgcrypto.html
- PostgreSQL 18 documentation, pgcrypto security limitations: https://www.postgresql.org/docs/18/pgcrypto.html#PGCRYPTO-SECURITY-LIMITATIONS
- PostgreSQL 18 documentation, `CREATE FUNCTION` (`STRICT`, defaults): https://www.postgresql.org/docs/18/sql-createfunction.html
- PostgreSQL 18 documentation, C-language functions and `fmgr`: https://www.postgresql.org/docs/18/xfunc-c.html
- PostgreSQL 18 documentation, packaging related objects into an extension: https://www.postgresql.org/docs/18/extend-extensions.html
- PostgreSQL 18 documentation, extension building infrastructure (PGXS): https://www.postgresql.org/docs/18/extend-pgxs.html
- PostgreSQL 18 documentation, customized options: https://www.postgresql.org/docs/18/runtime-config-custom.html
- PostgreSQL versioning policy: https://www.postgresql.org/support/versioning/
- mysql-gcm `docs/design.md` (amendments A1, A2, A3, A5, A8 "operational responsibility for keys and
  nonces", A10, A11, A12) and `spec/envelope.md`
- OpenSSL manual, `OPENSSL_malloc(3)` (`CRYPTO_set_mem_functions`) and `EVP_EncryptInit(3)`
- NIST SP 800-38D: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- Oracle `DBMS_CRYPTO` (19c and 23ai/26ai), SQL Server Always Encrypted cryptography — for §1.1 only
