# PostgreSQL GCM encryption functions (extension) — design and procedure

English | [한국어](design-KO.md)

Status: **Phase 5 — ecosystem: the PGXN packaging is in place; Phase 4's completion criterion is
still open** (2026-10-13). The extension implements the specification — `spec/envelope.md`,
with `spec/test-vectors.json` — for the three key sizes, with and without AAD, with `pg_gcm.strict` and
`pg_gcm.min_key_bytes`. Its core runs every vector in the unit suite, its SQL functions every envelope
vector in the regression suite, and an end-to-end suite runs them on a primary and on a streaming
replica that only replayed what the primary sealed, on PostgreSQL 15–18 (§4, §8). A load gate watches
the decrypt-and-`LIKE` scan against `pgcrypto`, and core micro-benchmarks watch the seal and the open
against bare OpenSSL EVP ([`docs/perf.md`](perf.md)). The operational constraints are their own
document, [`docs/ops-constraints.md`](ops-constraints.md), and a release pipeline builds the tarballs,
their checksums and an SBOM, and a `postgres:<major>` image with the extension preinstalled. The
PGXN metadata and the source-distribution pipeline are also in place (§4, Phase 5); they, too, are
exercised but not observed end to end, and nothing has been uploaded. **Both performance gates are
still placeholders, exercised only by a throwaway probe branch and never yet by the merged
workflows on a GitHub runner** (§8 O17), so the completion criterion is not met. **Nothing is released and it is not for use yet**: no tag has been cut and the format may
change until 0.1.0.
Every claim about PostgreSQL behaviour that the design leans on is either cited in §9, recorded with
its evidence in §8, or listed in §8 "Open". The plan was checked against the PostgreSQL 15–18 sources
and the official images on 2026-10-10; the spike ran, the specification was written and the
implementation was brought to it on 2026-10-12; the end-to-end suite ran and distribution followed on
2026-10-13; §8 records what each established.

## 0. Goal and scope

Give PostgreSQL authenticated AES-GCM as SQL functions inside the server, with the decrypted value
usable by the server's own `LIKE`, in a documented, versioned envelope.

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
table in `contrib/pgcrypto/openssl.c` for 15–18 and 19beta4 (§8). SQL Server's Always Encrypted uses AEAD_AES_256_CBC_HMAC_SHA_256 and
decrypts in the client driver; its secure enclaves (SQL Server 2019 and later) add pattern matching
inside an enclave. Oracle added `CHAIN_GCM` to `DBMS_CRYPTO` in 23ai; 19c has none.

Regulated sectors — healthcare in this project's case — increasingly ask for authenticated encryption
of personal data at rest, and AES-GCM is the usual answer. Without it in the database, applications
encrypt and decrypt themselves.

### 1.2 Application-side encryption loses server-side search

When the application holds the only decryption path, `WHERE name LIKE '%길%'` on an encrypted column
is impossible in SQL: every candidate row must travel to the application to be decrypted and filtered.
This project exists to keep that search inside the server. A decrypted value
that comes back as `text` in the database encoding is matched by PostgreSQL's ordinary `LIKE`,
`ILIKE`, regular expressions and collations, with nothing new to learn.

### 1.3 The existing extensions do not fill the gap

Checked on 2026-10-10 (repository metadata and PGXN; a search cannot prove nothing else exists).

| Project | What it offers | Why it is not the answer |
|---|---|---|
| [pgsodium](https://github.com/michelp/pgsodium) | libsodium AEAD in SQL: ChaCha20-Poly1305-IETF, deterministic XChaCha20-SIV, `crypto_secretbox`. PostgreSQL License, v3.1.11 (2026-06-10) | No AES-GCM, so it does not meet a "use AES-GCM" requirement. Supabase's documentation advises against it because it is to be deprecated |
| [pgcrypsi](https://github.com/telkomdev/pgcrypsi) | `pgcrypsi_aes_{128,192,256}_gcm_{encrypt,decrypt}` with the key as an argument. MIT | Unmaintained: last pushed 2023-09-11, and built for OpenSSL 1.1.1 and `postgresql-server-dev-10` |
| pg_tde (Percona), pg_vault_tde | Encryption at the storage layer (a table access method) | Transparent encryption of data at rest; no SQL function |

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

- The extension is called `pg_gcm`, following the
  ecosystem's `pg_` convention, and its GUCs use the `pg_gcm.` prefix that the library reserves
  (§5.6).
- **Key length selects the suite**: 32 → AES-256-GCM, 24 → AES-192-GCM, 16 → AES-128-GCM. Anything
  else is an error, raised on every call because `key` need not be a constant.
- **NULL handling**: SQL NULL in any argument yields
  SQL NULL, with no cryptographic work. Every function is therefore declared `STRICT`, and the server
  returns NULL without calling it.
- **AAD is optional through overloading, not through `DEFAULT NULL`**, so that a call that omits
  `aad` encrypts while an explicit NULL propagates. **A NULL default cannot give both.** Under
  `STRICT`, a defaulted NULL makes the two-argument call return NULL without encrypting anything
  (reproduced on 15–18, §8). Dropping `STRICT` so that NULL reads as "no AAD" would instead make an
  explicit NULL — a nullable column, an unset bind parameter — seal silently *without* AAD: the
  value would then open without the binding it was meant to carry, and nothing would say so. With
  two overloads,
  the two-argument form means "no AAD", a NULL `aad` in the three-argument form gives NULL, and an
  empty `aad` (`''`) seals exactly as the two-argument form does.
  A non-NULL default would give both as well: `aad bytea DEFAULT ''` with `STRICT` runs with an empty
  AAD when the argument is omitted and still returns NULL for an explicit one (§8). Overloading is the
  choice made, not the only correct one; it keeps the surface as two arities with no default
  expression to explain.
- A consequence of `STRICT` to state wherever the functions are documented: **a missing key yields
  NULL, not an error.** Declare an encrypted column `NOT NULL` when its plaintext is never NULL, so an
  unset key parameter fails the statement instead of storing NULL (docs/ops-constraints.md item 11).
- Each function is declared with an explicit `COST`: 50 for `gcm_decrypt`, 100 for `gcm_encrypt` and
  200 for `gcm_encrypt_det`, round values from the Phase S measurement (§8). A C function defaults to
  cost 1, and the planner orders the quals of one scan by cost, so without it
  `gcm_decrypt(...) LIKE ...` is not placed after the cheap predicates that docs/ops-constraints.md item 4 relies on.
- Binary plaintext (`bytea` in, `bytea` out) is deliberately not in 0.1: overloading `text` and `bytea`
  on the first argument makes an untyped literal ambiguous. If wanted, it gets distinct names
  (`gcm_encrypt_bytes`, `gcm_decrypt_bytes`) through an amendment.

### 2.2 The envelope

The envelope is `version || nonce(12) || ciphertext || tag(16)`, where the version byte, `0x02`–`0x07`,
names the suite and the variant (`AGENTS.md` §2). `spec/envelope.md` is the
normative definition: a byte-offset table, the nonce derivation, worked hex examples and the vector
schema, kept free of PostgreSQL terms so that any implementation can read and write the format. The
PostgreSQL binding — SQLSTATEs, the encoding rule, the exceptions below — is a separate, clearly marked
part of the same file.

**Every byte of an envelope is authenticated.** The associated data given to GCM is the version byte
followed by the caller's AAD, `version || aad` (spec §1.5; decided in Phase 1, §8 O13). Without that
the version byte would be the one byte outside the tag, and `0x03` could be rewritten as `0x02` to
make a second, different envelope of one plaintext without the key. The deterministic nonce is derived
from that same associated data and the plaintext (spec §1.8; §8 O16), so one deterministic key can
serve any number of AAD values.

The plaintext inside an envelope is **UTF-8**. `gcm_encrypt` converts the argument from the database
encoding to UTF-8 before sealing; `gcm_decrypt` verifies the opened bytes are valid UTF-8 and converts
them to the database encoding (§5.7 says how, and why not with the obvious server functions). A UTF-8
database (the common case) does no conversion. Fixing the plaintext encoding makes an envelope
independent of the database that sealed it.

**Three kinds of plaintext authenticate and then fail**, as an error that `pg_gcm.strict` does not
hide. The first two can only come from an envelope this extension did not seal:

1. A plaintext containing U+0000. PostgreSQL `text` cannot hold it, and UTF-8 verification rejects the
   zero byte on every supported major (§8).
2. A plaintext that is not UTF-8.
3. A character the database encoding cannot hold, in a database that is not UTF-8.

`0x01` is reserved for a legacy, unauthenticated AES-256-CBC dual-read envelope
(`0x01 || iv(16) || CBC ciphertext`). **0.1 does not implement it** (§8 O6, settled in Phase S): the
byte stays allocated, and an envelope that carries it fails as a malformed envelope. Compatibility is
not the obstacle: `encrypt_iv(data, key, iv, 'aes-cbc')` from `pgcrypto` with a 32-byte key is plain
AES-256-CBC with PKCS#7 padding, so `'\x01' || iv || …` would give existing pgcrypto columns a
migration path without re-encryption. Security policy is: it would put an unauthenticated format
behind a function whose point is authentication. Implementing it later is an amendment to this
document and changes no envelope already written.

If it is implemented, two conditions come with it and are stated wherever `0x01` is exposed:

- **Prefixing is a migration only for legacy plaintext that is already UTF-8.**
  `encrypt_iv` takes `bytea` and converts nothing, so a column encrypted from LATIN1 bytes — `Müller`
  as `4D FC 6C 6C 65 72` — opens and then fails UTF-8 verification. It fails loudly, but row by row: pure-ASCII values pass and the rest do not.
  Data in any other encoding is decrypted the old way, converted, and re-sealed with `gcm_encrypt`.
- **`0x01` is an exception to the authentication guarantee.** CBC has no tag: a changed IV or
  ciphertext block yields changed plaintext that still opens, `pg_gcm.strict = on` cannot detect it,
  and a wrong key can return garbage instead of an error. Adopting `0x01` therefore also means
  deciding how it is refused once a migration is over. The default is to leave that to the
  application; a switch inside the extension would be a new GUC and an amendment.

### 2.3 Configuration

```
# postgresql.conf — policy only, never key material (§5.4)
shared_preload_libraries = 'pg_gcm'   # optional; it makes the two settings below validated at start
pg_gcm.strict = on
pg_gcm.min_key_bytes = 32
```

`pg_gcm.strict` is `PGC_USERSET`: any session may relax it for itself.
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

## 3. The extension at a glance

| Concern | How |
|---|---|
| Packaging | Extension, version-1 fmgr functions, PGXS |
| Plaintext encoding | Converted to UTF-8 to seal; UTF-8 verified and converted back on open |
| NULL arguments | NULL in any argument gives NULL, through `STRICT` |
| Ill-formed plaintext | An error (§2.2) |
| Strict scope | `PGC_USERSET` on every supported major |
| Key-length floor | `pg_gcm.min_key_bytes`, `PGC_SUSET` |
| Lifetimes | library load (backend) / `FmgrInfo` (`fn_extra`) / operation |
| Errors | `ereport(ERROR, errcode(...))` with a SQLSTATE per failure class |
| Concurrency | One process per backend; parallel workers are separate processes |
| Server tests | `pg_regress` (`make installcheck`) |
| Load baseline | `pgcrypto` `decrypt()` (CBC) and `pgp_sym_decrypt()` |

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

Done on 2026-10-12, on 15–18, on 19beta4 and on an image whose server links OpenSSL 3.0; the answers
are in §8 "Established in Phase S". Three things differ from the steps as written, and §8 says why.
The spike includes `gcm_encrypt_det`, because its nonce is the only place SQL can see an HMAC result
(step 5). The `CRYPTO_set_mem_functions` probe and the `PG_TRY` timing live in a measurement-only
module, not in the extension's `_PG_init` (steps 6 and 7). And step 6's counting allocator reaches
the paths an allocation failure or a tag mismatch takes, not every failure an EVP call can have;
the rest is shown by structure.

### Phase 1 — the spec

Write `spec/envelope.md` and build `spec/test-vectors.json`: the NIST CAVP GCM known-answer tests plus
this project's own vectors, reproducible with `scripts/check-vectors.py`. Add the PostgreSQL binding as
a separate part (§2.2): SQLSTATE per failure class, the encoding rule and the plaintexts it rejects, the
`0x01` decision from Phase S, and what the SQL layer expects for a vector whose plaintext is not UTF-8.

Done on 2026-10-12; §8 "Established in Phase 1" has the answers. Two things came out differently from
this section as first written. With the version byte authenticated (§2.2), a NIST vector is not an
envelope — its associated data is NIST's, not `version || aad` — so the NIST known answers test the
primitive, in the unit suite, and SQL never sees them; "authenticates, then the invalid-UTF-8 error"
is carried instead by the project's own vectors whose plaintexts are not UTF-8 or hold U+0000. And the
phase did not only write down the construction it was handed: review of the specification changed it
twice, in O13 and O16.

### Phase 2 — implementation and tests

Phase 2 brought the spike to the specification (issue #19): the version byte went into the
associated data, the deterministic nonce is derived from the associated data too, the core gained the
AAD argument and the 24- and 16-byte suites, the glue gained `pg_gcm.min_key_bytes`, and the inline
known answers of the spike's tests gave way to `spec/test-vectors.json`, read by the unit and the
regression suites. §8 "Established in Phase 2" records what was observed.

The core (`gcm.c`, `envelope.c`, `nonce.c`) is C11 and includes no PostgreSQL header.
The glue (`fn_*.c`) handles arguments, encoding, GUCs and errors. Unit tests run the core against every
vector without a server; `pg_regress` covers the SQL behaviour. Per-call-site caching of the key
schedule comes after the baseline is measured, through an amendment here,
using `flinfo->fn_extra` and a memory-context reset callback that cleanses the key copy. That amendment
has to bound the lifetime itself: an `FmgrInfo` can outlive a statement — PL/pgSQL keeps the state of a simple expression until the end of the transaction
(`pl_exec.c`, `shared_simple_eval_estate`).

### Phase 3 — SQL E2E

A compose file with a primary, a streaming replica and a Python runner: round trip, Korean `LIKE`,
replication (the replica reads ciphertext it never encrypted), and NULL arguments giving NULL. It is
`tests/e2e`, run by `scripts/e2e.sh <major>`; §8 "Established in Phase 3" records what it showed.

### Phase 4 — distribution

The build matrix per major and architecture is `build.yml` (§4, Phase 2); this phase adds
packaging, the distribution image and the two performance gates. `scripts/package.sh` writes
`pg_gcm-<version>-pg<major>-<arch>.tar.gz` and its checksum, `scripts/sbom.py` a CycloneDX SBOM,
and `release.yml` guards the tag (SemVer, on `main`, matching `pg_gcm.control`, with a
`## <version>` section in the changelog) and then publishes the tarballs, `SHA256SUMS`, its
keyless signature and the SBOM; a `workflow_dispatch` run is a dry run. `docker/server.Dockerfile`
layers the built extension onto `postgres:<major>` and runs `CREATE EXTENSION pg_gcm` in an init
script; `scripts/server-image.sh` builds it and `scripts/smoke-image.sh` checks the Korean `LIKE`
round trip against the image's own init before anything is pushed. The operational constraints
are `docs/ops-constraints.md`, and the load baseline and both performance gates are
`docs/perf.md`. §8 "Established in Phase 4" records what the gates and the image were observed to
do, and what is left to record.

### Phase 5 — ecosystem

PGXN, then distribution packaging if there is demand. `META.json` is the distribution's metadata
(PGXN Meta Spec 1.0.0). `scripts/check-pgxn.py` validates it against that specification — the
required fields, the rules on their values, and the rule that a map holds only its keys or custom
`x_` ones — and cross-checks what the specification cannot: the version agrees with
`pg_gcm.control`, the provided `file` and `docfile` exist, the extension version equals the
distribution version, and the PostgreSQL floor is the supported one. `scripts/pgxn-dist.sh` writes
the source archive
`pg_gcm-<version>.zip` with `git archive HEAD` — whose single top-level directory is
`pg_gcm-<version>/`, the layout PGXN Manager expects — into a directory outside `dist/`, so it
never joins the checksummed release assets. `release.yml`'s `publish` job validates the metadata,
builds the archive, and, on a tag only, uploads it to PGXN Manager with HTTP Basic authentication;
`workflow_dispatch` builds and validates the archive and uploads nothing. The distribution is
labelled `release_status` "testing" while 0.1.0 is pre-release: the envelope format may still
change and the project is not for use, so PGXN must not offer it as a stable install. Distribution
packages (Debian, RPM) await demand and are not built. §8 "Established in Phase 5" records what
the checker and the archive were observed to do, and what is left to record.

## 5. Design decisions and rationale

### 5.1 An extension with version-1 C functions

That is the only supported way to add SQL-callable native code without patching the server.
`CREATE EXTENSION` gives versioned install and upgrade scripts, and `DROP EXTENSION` removes the
functions cleanly.

### 5.2 The core never calls `ereport`, and what the glue cleanses

`ereport(ERROR)` unwinds with `longjmp`; it does not return. An `EVP_CIPHER_CTX` allocated by OpenSSL
is not tracked by a PostgreSQL memory context, so an error raised while one is live leaks it, and a key
copy in it is never cleansed. The core therefore returns an error code, and the glue releases every
OpenSSL resource and cleanses every secret before raising. The error model makes this boundary
mandatory. (`pgcrypto` solves the same problem with a
ResourceOwner callback, whose API differs between 15–16 and 17+; keeping raising calls out of the
window needs no version-specific code.)

**The cleansing rule covers the copies the extension makes, and only those**: a detoasted argument, a
conversion buffer, scratch space, the opened plaintext before it becomes the result.

- An argument that needed no detoasting is the executor's own storage — a constant in a cached plan,
  the portal's parameter value, or a tuple in a shared buffer page. **It is never written to.**
  Cleansing it in place would zero the key in a cached plan or corrupt a table page; the copy test is
  the one `PG_FREE_IF_COPY` uses (pointer inequality with `PG_GETARG_POINTER`).
- The result `text`, the caller's datums, and the copies the planner makes when it evaluates a `STABLE`
  call (§5.3) are outside the extension's reach. So are the server's intermediates when it detoasts
  a value for us — the fetched chunks and the compressed form, which it frees without zeroing even
  when the call succeeds. Cleansing is defence in depth for our own buffers, not a guarantee that no
  copy of a key remains in backend memory.
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
  `IMMUTABLE` SQL function around `gcm_decrypt` can index it. That is an operational constraint (docs/ops-constraints.md
  item 2), not something the extension can prevent.

### 5.4 The key is a SQL argument, never configuration

No key in `postgresql.conf`, a GUC, a table or an environment variable.
The cost — the key is visible wherever the statement is — is an operational constraint (docs/ops-constraints.md), and the
mitigation is bind parameters, not code in the extension.

Encrypting inside the server draws a trust boundary that the extension cannot move, the one `pgcrypto`
documents for itself ("Security Limitations", §9): the key and the plaintext cross the client
connection, and they exist in the memory of a server its administrators control. The design protects
stored columns, backups and replicas that hold only ciphertext. It does not protect against an
unprotected connection, the database superuser or the server's operating-system administrator (docs/ops-constraints.md
item 12).

### 5.5 A tag mismatch is not degraded to NULL by default

Strict on means an error; off means NULL; a malformed envelope, a wrong key
length and invalid UTF-8 after a successful open are errors regardless of strict.

### 5.6 `pg_gcm.` as the GUC prefix

A custom GUC's prefix should be the library that defines it, so that
`MarkGUCPrefixReserved("pg_gcm")` applies. What that buys is narrower than it sounds (§2.3, §8): once
the library is loaded in a backend, `SET pg_gcm.strcit` is an error; before that, and in
`postgresql.conf`, the typo is accepted as a placeholder and removed with a WARNING at load. A shorter
`gcm.` prefix is not used, because the reserved prefix must be the library's own.

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
  On sealing there is no verification to precede it — the extension does not verify the argument
  against the database encoding — so a short count is reported as an untranslatable character
  whatever stopped the conversion (spec §2.4).
  The length of the converted text is its `strlen`: the glue relies, as the server's own `convert`
  functions do, on the conversion procedure terminating its output. With the lookup confined to
  `pg_catalog`, only a procedure a superuser put there could break that.
- The conversion procedure comes from `FindDefaultConversion(PG_CATALOG_NAMESPACE, …)`, a catalog
  lookup; when there is none the glue raises `42883`, naming the two encodings. It runs before any
  secret copy exists. It looks in `pg_catalog` alone and does not follow `search_path` (§8 O14).

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

The handles are static in the core (`gcm.c`), fetched by `gcm_init()`, which `_PG_init` calls and
the unit suite calls from `main`. One thing is still resolved per call: `EVP_MAC` takes its digest by
name, so each deterministic call names SHA-256 to `EVP_MAC_init` (§8 O15).

The handles live for the life of the process and are not released. An `on_proc_exit` callback
registered while preloading would never run in a backend — the child discards the postmaster's
callbacks — and the process is exiting anyway.

## 6. Operational constraints

The constraints an operator must hold were settled here and are maintained in
[`docs/ops-constraints.md`](ops-constraints.md); every one of them is also on the first screen of
[`README.md`](../README.md). They belong to the deployment rather than to this code: what the
extension can and cannot protect is fixed by the trust boundary in §5.4, and nothing in
`postgresql.conf` moves it. Read that document before deploying, and keep it accurate — it is as much
a part of the deliverable as the SQL functions are.

## 7. License — the PostgreSQL License (settled 2026-10-10)

The full text is in `LICENSE`; every source file carries `SPDX-License-Identifier: PostgreSQL`.

- **Why the PostgreSQL License.** It is the license of PostgreSQL itself and of most of its contrib
  modules, so the extension can be packaged by distributions, listed on PGXN and read by the community
  without a license question. It is a short permissive license, compatible with OpenSSL 3's
  Apache-2.0.
- **Why not Apache-2.0.** Its patent grant is the real advantage, but this project implements a
  published, unencumbered construction (AES-GCM, HMAC-SHA256) and holds no patents, and matching the
  host project mattered more.

## 8. Established facts / open questions

### Confirmed (with source)

Unless a line says otherwise, "source" is the PostgreSQL tree at the tip of each stable branch on
2026-10-10 (15.19, 16.15, 17.11, 18.6; line numbers are `REL_17_STABLE`), and "run" is `psql` against
the official `postgres:15`–`18` images on linux/arm64 the same day.

- License: the PostgreSQL License (§7; `LICENSE`).
- `pgcrypto` raw encryption supports `bf` and `aes` with `cbc` and `ecb`, and `cfb` from 18 (commit
  9ad1b3d01); no GCM or AEAD mode in 15–18, 19beta4 or master. PGP functions append a SHA-1 MDC.
  (Source: the cipher table in `contrib/pgcrypto/openssl.c`; `pgcrypto.sgml`; the 18 release notes.)
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
  only to the databases `pg_regress` creates. (Source: `pg_regress.c`, `psql/command.c`; run on 17 in
  Phase S, below.)

### Established in Phase S (2026-10-12)

"Run" here is this repository's scripts on linux/arm64, against the digest-pinned images of
`docker/versions.json`: `postgres:15`–`18` (15.19, 16.15, 17.11, 18.6; OpenSSL 3.5.7),
`postgres:19beta4`, and `postgres:17-bookworm` (17.11; OpenSSL 3.0.22). Unless a line says otherwise
the result was the same on all six. Per image `M` the commands are `scripts/build-in-docker.sh M`,
`scripts/unit-in-docker.sh M`, `scripts/dev-up.sh M` and `scripts/verify.sh M` (steps 1–6),
`scripts/spike/measure.sh M` (step 7, O6, O8, O12), and `scripts/spike/ldd.sh all` (step 8).

- **Steps 1–4 pass.** The PGXS build is clean under `-Wall -Wextra -Werror`, and `ldd` shows the
  server and `pg_gcm.so` resolving the same `libcrypto.so.3`. `CREATE EXTENSION` installs 0.1.0; 14
  `pg_regress` files pass, and so do the 35 checks of `scripts/verify.sql` with the library loaded
  lazily and again preloaded. A key that is not 32 bytes is an error. A forged tag is an error with
  `pg_gcm.strict` on and NULL with it off, while a truncated envelope, an unimplemented version byte
  and an authenticated plaintext that is not text (the GCM specification's test case 14: sixteen
  zero bytes) stay errors with it off. `LIKE '%길%'` on a decrypted value is true in a UTF8 and in
  an `EUC_KR` database; the `EUC_KR` database seals nine bytes of UTF-8 for six bytes of text and
  derives the same deterministic nonce, each database opens what the other sealed, and a character
  `EUC_KR` cannot hold is an error whose message has no byte of it. A SQL_ASCII database refuses to
  seal bytes that are not UTF-8. A parallel scan with `pg_gcm.strict = off` returns NULL from every
  worker (O9, now with the real variable).
- **O4 — handles after fork.** They work. With `shared_preload_libraries = 'pg_gcm'`,
  `pg_gcm.strict` is a real variable before a backend's first call (the postmaster loaded the
  library), and in each of two backends an AES-256-GCM round trip succeeds and the deterministic
  nonce of `'홍길동'` under the `00..1f` key is `f55369153b2a94fcbc9b633f`, the value Python's
  `hmac` gives. What a backend inherits is the fetched `EVP_CIPHER` and `EVP_MAC`. The same holds
  when the backend loads the library itself.
- **O3, run.** The two backends' first random nonces differed in every run, preloaded and not.
- **O6 — `0x01`.** Compatibility: yes. `encrypt_iv(convert_to('홍길동','UTF8'), key32, iv,
  'aes-cbc')` from `pgcrypto` gives 16 bytes that `openssl enc -d -aes-256-cbc -K … -iv …` opens to
  `홍길동`: AES-256-CBC with PKCS#7 padding and nothing else. (It was opened with OpenSSL's own
  command, not with a CBC path in the extension.) Decision: not implemented in 0.1; the byte stays
  reserved (§2.2). Reversing that is an amendment and breaks no envelope.
- **O7 — SQLSTATEs, as far as the spike goes.** The spike raises `22023` for a key length, `22P03`
  for a malformed envelope, `XX001` for a tag mismatch, `22021` for text that is not UTF-8, `22P05`
  for an untranslatable character, `54000` for a value too long and `XX000` for an OpenSSL failure.
  Each exists in `errcodes.txt` on 15–18, and a regression test reads four of them back. One choice
  was left open here and is settled in Phase 1, below: `XX001` puts the commonest operational
  failure, a wrong key, in the internal-error class.
- **O8, run.** `CRYPTO_set_mem_functions` returned 0 in a preloading postmaster and in a backend
  loading on first call (the probe module's `_PG_init`; logged, and readable through SQL). In the
  unit suite, called first in `main`, it returned 1. One call makes 2 OpenSSL allocations to seal, 2
  to open and 13 to seal deterministically (19 on 3.0.22). The suite refuses each of the first 32 in
  turn: every call gives back all it took, never reports the failure as a tag mismatch, and leaves
  either the right output or a cleansed buffer. **What that does not execute:** an EVP call that
  fails for another reason while its context is live. Those exits rest on structure — one `done:`
  label per function, and no `return` between acquiring a context and that label — which
  `scripts/check-architecture.py` enforces. Step 6 is shown to that extent and no further.
- **O11 — amd64.** On amd64 `postgres` links `/lib/x86_64-linux-gnu/libcrypto.so.3` and `openssl
  version` is 3.5.7 for 15–18 and 19beta4, as on arm64; `17-bookworm` is 3.0.22 on both.
- **O12 — `PG_TRY`.** One `PG_TRY` / `PG_FINALLY` block costs a few nanoseconds per call: 2–7 ns on
  most of ten runs (3M calls of a function with the block against the same function without it),
  with one run reading below zero — the difference is at the noise floor. That is at most about 2%
  of one decrypt-and-`LIKE` row. It does not change a load gate.
- **Step 7 — cost.** Over 300k rows of 10–15-byte Korean names, in one backend with JIT off:
  `gcm_decrypt(...) LIKE '%길%'` costs 0.30–0.41 µs a row above the bare scan, `gcm_encrypt`
  0.64–1.00 µs, `gcm_encrypt_det` 0.99–1.18 µs, and `pgcrypto`'s `convert_from(decrypt_iv(...,
  'aes-cbc'), 'UTF8') LIKE` 0.58–0.68 µs: the GCM query takes 0.49–0.63 of the CBC one. In units of
  a cost-1 operator the answer is rough. An `int4ge` qual is a few nanoseconds, at the noise floor
  of these runs (it read 1–11 ns), so the ratio is good to a factor of two or three — 37–65 for
  decrypt, 64–111 for encrypt and 88–190 for the deterministic variant on the four runs where the
  yardstick held. The declared `COST` is therefore round: 50, 100 and 200. With it, a query written
  as `gcm_decrypt(...) LIKE '%길%' AND id % 2 = 0` is planned with `id % 2 = 0` first.
- **Step 7 — temporary files.** With `work_mem` at its default of 4MB, `ORDER BY` the decrypted name
  stays in memory at 30,000 rows on every major and is an external merge at 60,000 on 15, at 100,000
  on 16 and at 300,000 on 17–19; `GROUP BY` it spills at 100,000 on 15–17 and at 300,000 on 18–19.
  While a cursor over the sorted 300k rows is open, `base/pgsql_tmp` holds one file of about 7 MB in
  which the fragment `길동` occurs about 37,500 times; the table's own file holds none.
- **OpenSSL, from the sources of 3.0 and 3.5.** An `ivlen` parameter passed to `EVP_*Init_ex2` was
  applied after the IV had been copied until 3.0.12 / 3.1.4 (CVE-2023-5363); 12 is AES-GCM's
  default, so the core passes no parameter and checks `EVP_CIPHER_CTX_get_iv_length`. A tag mismatch
  in `EVP_DecryptFinal_ex` pushes nothing onto the error queue, and neither does a missing key, IV
  or tag on that path. `ERR_clear_error` keeps each entry's data buffer for reuse, and OpenSSL keeps
  the DRBGs and the thread's error state for the life of the process, so the unit suite runs every
  path once before it takes a baseline.
- **PostgreSQL, from the sources of 15–18.** `pg_do_encoding_conversion_buf` returns the number of
  source bytes it consumed, NUL-terminates its output, and with a destination of `srclen *
  MAX_CONVERSION_GROWTH + 1` is offered the whole input; 0 is ambiguous for empty input, which the
  glue therefore does not convert. `FindDefaultConversionProc` walks `search_path` (O14, settled in Phase 2).
  `-Wextra` fails on the server's own headers (unused parameters in static inlines), so the
  `-Werror` build takes them with `-isystem`.
- **`pg_regress` and `\c`, run on 17.** After `\c` to an `EUC_KR` database with `PGCLIENTENCODING`
  unset, `SHOW client_encoding` is `EUC_KR` and a UTF-8 literal fails with `invalid byte sequence
  for encoding "EUC_KR"`; `SET client_encoding = 'UTF8'` cures it. `pg_regress` stops at the first
  test that has no expected file.
- **The official image, run.** Its init-time server answers `pg_isready` on the socket before the
  real server is up; a check over TCP does not. A preloading server needs the library on disk before
  it starts (`docker create`, `docker cp`, `docker start`).
- **O1, so far.** The spike builds from `postgresql-server-dev-19` in `postgres:19beta4` and passes
  everything above. 19 stays out of the supported set until its release image exists.
- **Where things live** (decided while building; `AGENTS.md` §3 and `architecture.md` say the same).
  The fetched handles are static in the core, behind `gcm_init()`, because the unit suite needs them
  without a server. The glue includes no OpenSSL header and cleanses through `gcm_cleanse`. The
  spike includes the two-argument `gcm_encrypt_det`, because its nonce is the only place SQL can see
  an HMAC result (step 5). The `CRYPTO_set_mem_functions` probe and the `PG_TRY` timing are in a
  measurement-only module, `scripts/spike/pg_gcm_probe`, not in the extension.

### Established in Phase 1 (2026-10-12)

- **O13 — the version byte is authenticated.** Decided: the associated data given to GCM is `version
  || aad` (§2.2; spec §1.5). The alternative was to record the weakness as accepted. It was not
  taken because the weakness is concrete — without the key, one envelope could be turned into a
  second, different one that opens to the same plaintext — and closing it costs one byte of
  associated data and nothing on the wire. What it does not close is transplanting: `gcm_decrypt`
  opens either variant, so a random-nonce envelope of the same value under the same key and AAD is
  still a second envelope, and docs/ops-constraints.md item 5 says what a deterministic column does about that. One
  consequence for this phase: a NIST vector is no longer an envelope (its associated data is
  NIST's), so the NIST known answers are vectors of the primitive and SQL never sees them.
- **O16 — the deterministic nonce is derived from the associated data too.** Raised by the Phase 1
  crypto review and decided the same day: `nonce = HMAC-SHA256(nonce_key, be64(len(A)) || A ||
  P)[0:12]` with `A = version || aad` (spec §1.8). This reverses the earlier rule that AAD was not
  an input. Under that rule one plaintext sealed with two AADs used one (key, nonce) pair twice, and
  for GCM that is not a local failure: the difference of the two tags is a polynomial in the
  authentication subkey whose coefficients are the two associated data, so anyone who knows both
  AADs can solve for the subkey (Joux; SP 800-38D, Appendix A). With it, every envelope already
  sealed under that key, of either variant, can be altered — ciphertext, version byte and the AAD it
  answers to — and given a tag that verifies. The earlier answer was an operational rule — one AAD
  convention per deterministic key — that the function's own signature invited callers to break: a
  per-row AAD is the natural use of the argument and was exactly the forbidden case. Nothing is
  given up, because envelopes with different AADs never compared equal anyway; their tags differed.
  The length prefix makes the HMAC message unambiguous. The change costs nothing now and would have
  cost every stored deterministic envelope later.
- **O7 — the SQLSTATEs are settled** (spec §2.5). The spike's table stands, `XX001` for a tag
  mismatch included, and gains `42883` for a database encoding with no default conversion to or from
  UTF-8, which the spike already raises. An existing code was preferred to one of the extension's
  own. A class-level code of class 22 was the alternative, and what decided against it was run on
  15–18 (`scripts/spike/sqlstate-handlers.sql`): in PL/pgSQL, `WHEN SQLSTATE '22000'` and `WHEN
  data_exception` both catch a `22023`; `WHEN data_corrupted` catches `XX001` and neither `XX000`
  nor `XX002`; and `WHEN internal_error`, being the class, catches `XX001` as well. `XX001` is not
  the extension's alone — the server raises it for corrupted storage — and it sits in the
  internal-error class although the commonest cause is a wrong key, because the format cannot tell a
  wrong key from a modified envelope.
- **The vectors.** `spec/test-vectors.json` holds 77. Fifteen are NIST CAVP known answers for
  AES-GCM, five per key size, taken unchanged from `gcmEncryptExtIV128/192/256.rsp` in NIST's
  `gcmtestvectors.zip` (the URL is in the file; SHA-256
  `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`, retrieved 2026-10-12): `Count
  = 0` of the parameter sets with a 96-bit IV, a 128-bit tag and (plaintext, AAD) lengths of (0, 0),
  (128, 0), (0, 128), (104, 160) and (408, 720) bits. Sixty-two are this project's. 30 open: all six
  version bytes, with and without AAD (one of 300 bytes), around the block boundary, the empty text,
  a four-byte character, plaintexts that are not UTF-8 (a foreign byte pair, an overlong form, a
  surrogate, a cut-off character) or that hold U+0000, and one envelope labelled deterministic whose
  nonce is not the derived one. 32 do not (14 `bad_tag`, 10 `bad_envelope`, 8 `bad_key_length`),
  each derived from a valid one by a stated change; four of them are a valid envelope with only its
  version byte changed (`version-02-as-03`, `version-03-as-02`, `version-04-as-05`,
  `version-06-as-07`), all `bad_tag` — O13 in bytes. Keys are public: the `00..1f` pattern cut to
  the suite's length, 32 zero bytes, and NIST's.
- **How far they are checked.** `python3 scripts/check-vectors.py` (`cryptography` 50.0.2 and the
  standard library's HMAC) recomputes every NIST vector on the primitive, opens every envelope to
  its expected outcome, re-seals every valid one to the same bytes and re-derives every
  deterministic nonce. It requires the vectors the documents name, each of them the case its name
  says, and at least one for every suite, outcome and plaintext class; and it checks the worked
  examples of `spec/envelope.md` against the vector each names — a run of twelve or more hexadecimal
  digits must be a whole member of it, a row of a field table the whole field at its offset, and the
  suite and outcomes tables must have their rows. `--self-test` breaks the file and the spec in
  memory in 35 ways and fails unless each is caught, which shows the gate notices those breaks and
  not every possible one; the lint workflow runs both. Three limits. The project's vectors were
  *generated* with the checker's own functions, so its agreeing with them is not independent
  evidence. What is independent: a scratch copy of the spike's core, given the two changes of O13
  and O16 and calling EVP directly (OpenSSL 3.6.4), sealed the 16 AES-256 vectors that have no AAD
  to their exact bytes, opened them and refused the 9 `bad_tag` ones among them; and the crypto
  review recomputed 76 of the 77 — all but `det-256-300-byte-aad`, added afterwards, whose nonce was
  re-derived with the `openssl` command — with an AES-GCM and an HMAC written for the purpose. That
  copy of the core is not in the repository: **no committed C code runs a vector until Phase 2**
  (issue #19). And the check of the spec sees hexadecimal runs and table rows, not prose.
- **The order of checks when opening** (spec §1.7) is fixed and has vectors of its own: a key length
  that names no suite, then the envelope's length and version byte, then the key length against the
  suite, then the tag. It is the order the spike's glue already follows. An opener does not
  recompute a deterministic nonce (vector `det-256-nonce-not-derived`): doing so would cost two
  HMACs on every `gcm_decrypt`, the path the load gate measures, to defend against a holder of the
  key.
- **The vector schema changed** from the one first written in `docs.md`: a `nist` vector carries a
  ciphertext and a tag instead of an envelope; `expect` gains `bad_key_length`; a valid vector
  carries a `plaintext_class` (`text`, `not_utf8`, `contains_nul`), which is what the SQL layer
  reads to know whether to expect text or `22021`; a failing one names the vector it was
  `derived_from`; and `nonce_derived: false` marks the one deterministic vector a sealer cannot
  reproduce.

### Established in Phase 2 (2026-10-12)

- **The code implements the specification.** The core seals and opens all six version bytes with
  `A = version || aad` and derives the deterministic nonce from `be64(len(A)) || A || P`; the glue
  adds the three-argument forms and `pg_gcm.min_key_bytes`. The unit suite reads
  `spec/test-vectors.json`, and one of its tests fails if any of the 77 vectors is consumed by no
  suite: the 15 NIST vectors run on the primitive through a test seam, every envelope vector
  through open, every valid one through seal with its nonce (a deterministic one derives its own,
  and `gcm_nonce_derive` is also run alone against each derived nonce), and every failing one must
  leave the output buffer zeroed. The regression suite reads the same
  file: the 62 envelope vectors go through `gcm_decrypt` with `pg_gcm.strict` on and off, and the
  11 deterministic ones whose nonce is derived are sealed to their exact bytes. No known answer is
  written into a test any more. Observed on PostgreSQL 15.19, 16.15, 17.11 and 18.6 with OpenSSL
  3.5.7, on 17.11 with OpenSSL 3.0.22 and on 19beta4: 302 unit tests, 18 regression files, and
  `scripts/verify.sql` with the library loaded lazily and preloaded.
- **The nonce collision test.** A million distinct plaintexts sealed deterministically under one
  key and AAD give a million distinct nonces (100,000 on a pull request). That is a check of the
  derivation's wiring — a truncation to too few bytes or a constant input would fail it — and says
  nothing about the birthday bound of a 96-bit nonce, which no test can reach. docs/ops-constraints.md item 9 stays the
  rule.
- **O14 — the conversion is looked up in `pg_catalog` alone**, with
  `FindDefaultConversion(PG_CATALOG_NAMESPACE, …)`. Observed on 17.11: a role that is not a
  superuser but has `CREATE` on a schema can create a default conversion there, and along
  `search_path` it would be found before the built-in one. It can only bind an existing function,
  though: `CREATE CONVERSION` refused a built-in function for a pair of encodings it was not
  written for, and the role could create no C or internal function. So the exposure was to a
  conversion function a superuser had installed, chosen by the caller's `search_path`. Looking in
  `pg_catalog` makes the result independent of `search_path`; the price is that a site's own
  default conversion for the database encoding is not used by these functions. The regression
  test `conversion_lookup` shows the difference on 15–18 and 19beta4: in a throwaway EUC_KR
  database whose built-in conversions are unmarked as defaults, every function gives `42883`, and
  goes on giving it when a schema on `search_path` holds default conversions that the server's own
  `SET client_encoding` then finds. `scripts/check-architecture.py` also refuses
  `FindDefaultConversionProc` in `src/`. On a stock server `42883` is nearly unreachable:
  MULE_INTERNAL was the one server encoding without a conversion to UTF-8 on 17.11, and 19beta4
  does not have that encoding.
- **O15 — the per-call form stays, and the floor stays at 3.0.0.** On 17.11 with OpenSSL 3.5.7
  (one arm64 laptop, two runs, good to a factor of two at best) `gcm_encrypt_det` costs about
  1.1 µs a call, `gcm_encrypt` 0.6 µs and `gcm_decrypt` with `LIKE` 0.3 µs. The 0.5 µs between the
  first two holds two HMAC-SHA256 computations as well as the resolution of the digest by name, so
  it bounds from above what a prepared context could save; the saving itself was not isolated.
  Against it stands a context that fails on 3.0.0. The deterministic variant is for join keys and
  exact-match lookups, not bulk text, so the floor is not raised for it. The load gate of Phase 4
  is where this would be reopened.
- **`pg_gcm.min_key_bytes` and placeholders**, on 15–18 and 19beta4 (regression test
  `min_key_bytes`). A value a superuser sets before the library is loaded holds when it loads. A
  value that is not 16, 24 or 32 is dropped with a warning and the default applies. A value set by
  a role that may not set the parameter is dropped with "permission denied to set parameter" when
  the library loads, so a placeholder is not a way round `PGC_SUSET`. `GRANT SET ON PARAMETER`
  delegates it. A key below the setting is refused with `22023` and a message of its own; a length
  that names no suite keeps the key-length message whatever the setting.
- **The library exports its SQL functions and nothing else.** PGXS compiles with
  `-fvisibility=hidden` from PostgreSQL 16 only: `nm -D` of the build for 15 listed every core
  function, the two test seams among them, each callable through the dynamic linker and open to
  interposition by a library loaded earlier. None was reachable from SQL. The project's headers
  now declare everything but the SQL-callable functions with hidden visibility, and
  `scripts/build-in-docker.sh` fails unless the dynamic symbols are exactly those functions,
  their fmgr records, `_PG_init` and `Pg_magic_func`; it was seen to fail on a build without the
  pragmas.
- **CI.** `unit.yml` runs the unit suite under the sanitizers in one build image per libcrypto
  (the newest supported major, and the OpenSSL floor); `build.yml` builds with `-Werror` for
  every image of `docker/versions.json` on amd64 and arm64 and fails unless `pg_gcm.so` resolves
  the server's own `libcrypto.so.3`; `regress.yml` runs `make installcheck` and
  `scripts/verify.sql` for every image. Each takes its list of images from
  `scripts/ci-matrix.py`, which reads that file. No job is `continue-on-error`, under which a
  failure does not fail the run and is easy to miss: the pre-release image fails visibly, and its job is the one not
  meant to be a required check (O1). GitHub runs a schedule from the default branch only, so the
  nightly run starts when these files reach `main`; until then the million-plaintext run happens
  on every push to `develop`.
- **After the review of the whole phase (2026-10-13).** `gcm_decrypt` sizes its result to the
  plaintext, so the core is always handed a buffer of exactly the ciphertext's length — none for
  the empty text — and the unit suite opens every envelope vector that way, with guard bytes after
  the buffer. EVP promises to write no more than that only for a cipher whose block size is 1, as
  AES-GCM's is; `gcm_init` requires it of each cipher it fetches, and requires the key length the
  cipher reports to be the one its name stands for, since EVP reads that many bytes of the key. A
  cipher that reports otherwise is treated as absent. No test in the repository reaches that
  refusal: it would take a provider that reports another block size or key length. The
  file gained a 78th vector, `tag-last-bit-flipped-empty` — a tag failure on the 29-byte envelope
  of the empty text — so the unit suite runs 78 and the regression suite 63. The `54000` test
  passes its length through a set-returning function: with a constant the planner folded
  `repeat()` and kept a second copy, and the backend peaked at 547 MB instead of 285 MB.
- **What no test covers.** `54000` is tested where a conversion buffer is the limit — a 256 MB
  text sealed in an EUC_KR database — and not at the limits near a gigabyte, nor on the opening
  side. Any failure of an EVP call other than a tag mismatch or a refused allocation (O8,
  unchanged). The `PG_FINALLY` cleansing, which nothing outside the backend can observe. In a
  database that is not UTF-8 every call looks the conversion up in the catalog and calls it
  through the function manager; that cost is not measured before the load gate of Phase 4. The
  suites run on amd64 in CI and on arm64 on the development machine; on arm64 CI compiles and
  does not run them.

### Established in Phase 3 (2026-10-13)

- **The suite.** `tests/e2e/compose.yml` starts a primary and a replica from the official image —
  the build is installed into each when its container starts — and a runner (Python, `psycopg`)
  that only issues SQL, with keys as bind parameters. The replica is a `pg_basebackup` of the
  primary, streaming from it. Twenty-one scenarios, observed on PostgreSQL 15.19, 16.15, 17.11 and
  18.6 with OpenSSL 3.5.7, on 17.11 with OpenSSL 3.0.22 and on 19beta4. Three establish that the
  second node is what it is said to be: it is in recovery with a WAL receiver streaming from the
  primary, it refuses a write, and it has the extension's catalog entry although
  `CREATE EXTENSION` ran on the primary alone. Nine run on each node: every name comes back;
  notes sealed by the two-argument form open by it;
  `LIKE '%길%'` on the decrypted value finds the two names that contain it; a value sealed
  deterministically on the primary is found on either node by sealing it again there; the same
  value with another AAD is not; two tables join on their deterministic envelopes with no key in
  the query; a forged tag is `XX001` with `pg_gcm.strict` on and NULL with it off; and a NULL in
  each of the fifteen argument positions gives NULL. The runner waits for the replica to replay
  the primary's last WAL position before the first scenario, and fails if it does not within 30 s.
  Its exit status is 0 only when every scenario unittest ran was recorded as passed, at least one
  ran, and the two nodes ran the same shared scenarios; `run.py --self-test`, in the lint
  workflow, checks that this gate refuses a failure, an error, a skip, a failing subtest, an
  expected failure, an unexpected success and an empty run, and two classes whose scenarios
  differ or are none. The wait before the first scenario also covers the WAL receiver's state,
  so the scenario that asserts `streaming` does not meet a receiver that has only just connected.
- **docs/ops-constraints.md item 7, observed.** With the library left out of the replica's disk (a run of the
  twenty-one scenarios made by hand on 17.11), the catalog entry was still there and the join on
  envelopes still worked, and the seven scenarios that call a function there failed with `could
  not access file "$libdir/pg_gcm"`: 14 of 21 passed and the gate was closed. The NULL scenario
  passed there all the same: a `STRICT` function is not called for a NULL argument, so the
  library is never loaded for it.
- **What it does not show.** The suite's network carries keys and plaintext unencrypted between
  the runner and the servers; that is a test network with public test keys, not a deployment
  (docs/ops-constraints.md item 12). It does not test a logical subscriber, a promoted replica, a base backup restored
  later, or replication between different majors or different builds of the extension. It runs
  on amd64 in CI and on arm64 on the development machine.
- **CI.** `e2e.yml` runs the suite for every image of `docker/versions.json` on a push to `main`
  or `develop`, and on a pull request that changes the extension, the suite or what builds them. It is not a required
  check; `regress.yml` holds those.

### Established in Phase 4 (2026-10-13)

"Run" here is this repository's scripts on the development machine, and the workflow that would
take a gate; nothing was tagged and nothing was released.

- **The load gate.** `tests/load/run.py` loads N rows of Korean names sealed twice in one table
  — `gcm_encrypt` and `pgcrypto` `encrypt_iv(..., 'aes-cbc')` under the same key — and times,
  interleaved across `sessions` so that neither query owns the machine, the
  `gcm_decrypt(...) LIKE '%김%'` scan against the CBC one, reporting the p95 of each and their
  ratio. As in Phase S, JIT and parallel workers are off so both plans have the same shape, the
  table is `VACUUM (ANALYZE, FREEZE)`d, one warm-up scan of each query is discarded, and each cell
  collects about `samples` scans per query so the p95 is a percentile even at one session. The
  gate is the worst ratio over the gated cells — `gated_sessions` in the baseline, the
  low-concurrency ones — against `tests/load/baseline.json`, never a number of milliseconds, so it
  is portable; a high-session cell at 10k rows is scheduling-bound rather than crypto-bound and is
  recorded but not gated. `run.py --self-test` checks the verdict, the gated-cell rule and the
  ratio's direction over cases whose answer is known and runs in the lint workflow. Phase S's four
  runs are the expectation (the GCM query took 0.49–0.63 of the CBC one, step 7 above); the ceiling
  is 1.0, the design's requirement that GCM not be slower.
- **The micro-benchmarks.** `tests/bench/benchmark.cc` (Google Benchmark) measures the core's
  `gcm_seal` (random and deterministic) and `gcm_open` against a hand-rolled EVP AES-256-GCM of
  the same shape at 16, 256, 4096 and 65536 bytes, and gates three like-for-like ratios from
  `tests/bench/baseline.json` — the random seal and the open over bare EVP, and the deterministic
  seal over a bare deterministic seal that pays the same two HMAC-SHA256 passes and the same
  AES-GCM. Each benchmark runs five times in a random order and the gate reads the median, so one
  noisy repetition cannot move a ratio. The baseline's nonce is random, as the core's random seal
  is, so the seal ratio measures the core's own envelope and checks rather than a draw only one
  side pays; the ceilings are per size, because the core's fixed per-call cost is a larger share of
  a small message. The deterministic seal over the random one is recorded, never gated: an O17
  probe found it is not portable (the bullet below). The binary's `--self-test` checks the verdict,
  the ratio's direction and the gate over fixed measurements; no server and no PostgreSQL header is
  involved.
- **The distribution image.** `docker/server.Dockerfile` is the official `postgres:<major>`
  (base pinned by digest) with the built `pg_gcm.so`, `pg_gcm.control` and SQL installed into
  the directories that image's own `pg_config` names, and `docker/initdb.d/00-pg_gcm.sql` in
  `/docker-entrypoint-initdb.d`, so `CREATE EXTENSION pg_gcm` runs on first init.
  `scripts/smoke-image.sh` starts the image, waits on its `HEALTHCHECK`, and — with no
  `CREATE EXTENSION` of its own — seals and opens `홍길동` and checks `LIKE '%길%'`: a failure or
  a missing extension is a non-zero exit.
- **The release pipeline.** `scripts/package.sh` lays a build out as `pg_gcm-<version>/…` and
  writes `pg_gcm-<version>-pg<major>-<arch>.tar.gz` with its checksum;
  `scripts/release-guard.py` refuses a tag that is not `vMAJOR.MINOR.PATCH`, that disagrees with
  `pg_gcm.control`'s `default_version`, that is not an ancestor of `main`, or without a
  `## <version>` changelog section; `scripts/sbom.py` writes a CycloneDX 1.5 document naming the
  extension, its PostgreSQL and libcrypto dependencies and every artifact's SHA-256 — the
  extension only in `metadata.component`, so no `bom-ref` repeats. `release.yml` packages the
  supported majors on amd64 and arm64; `scripts/smoke-tarball.sh` layers each tarball onto the
  official image and runs the round trip, so the shipped bytes are loaded on every architecture;
  the `server` job builds and smokes the distribution image and only then pushes and signs it
  keyless with cosign, after every tarball has passed and only on a tag; the `publish` job writes
  the SBOM and `SHA256SUMS` (the SBOM's own file included), signs the checksums and creates the
  GitHub release. A `workflow_dispatch` run exercises everything except the pushes, the signature
  and the release. Both helper scripts' `--self-test`s run in the lint workflow.
- **What is not yet recorded, and what an O17 probe found.** The bench and load gates had never
  run on a CI runner: the ceilings in `tests/load/baseline.json` and `tests/bench/baseline.json`
  were the Phase S expectation and the placeholder of §8 Open O17, not a measurement of that
  runner. A throwaway probe (2026-10-14, `ci/perf-probe`, not counted among O17's three runs) ran
  both on GitHub runners and changed one gate. The load gate passed every run — worst gated ratio
  0.83–0.87 against the 1.0 the design requires, in about four minutes. The bench gate passed on
  some runners and failed on others: `seal` and `open` stayed at about 1.0 everywhere, but the
  deterministic seal over the random one ran from about 3.3 to 9.6 at 65536 bytes. That ratio
  compares a SHA-256-bound seal with an AES-bound one, and the runners' AES-GCM throughput differed
  about fivefold (AMD EPYC 7763, EPYC 9V74, EPYC 9V45, Intel Xeon 8573C) while SHA-256 barely moved,
  so the ratio is not a property of this code and cannot be gated. §8 Open O17 is redefined to gate
  the deterministic seal over a bare deterministic seal of the same shape instead. No tag has been
  cut and no release published, so the pipeline is exercised but not yet observed end to end, and
  the distribution image is smoke-tested only.

### Established in Phase 5 (2026-10-13)

"Run" here is this repository's scripts on the development machine; nothing was uploaded and no tag
was cut, so the PGXN path is exercised but not observed end to end.

- **`META.json`.** The distribution metadata is PGXN Meta Spec 1.0.0: `name` `pg_gcm`, a SemVer
  `version` that agrees with `pg_gcm.control`, `license` `postgresql`, `provides` naming the
  extension with the versioned SQL script as its `file` and `README.md` as its `docfile`, a
  `prereqs.runtime.requires.PostgreSQL` floor of 15.0.0, the repository, bug tracker and homepage
  as `resources`, and `tags` for search. `release_status` is `testing`: 0.1.0 is pre-release — the
  envelope format may change and nothing is for use — so PGXN must not offer it as a stable
  install. `no_index` keeps the agent configuration, the CI files and the development scripts out
  of PGXN's documentation index.
- **The checker.** `scripts/check-pgxn.py` implements the specification's rules — the required
  fields, the rules on their values, the unknown-key rule with its custom `x_` exception, and the
  prereq phases, relations and version ranges — and adds the cross-checks the specification cannot
  make: the version against the control file, the provided `file` and `docfile` against the working
  tree, the extension version and the distribution name against `pg_gcm` and the archive the
  distribution script builds, and a PostgreSQL floor that requires at least 15.0.0. `--self-test` gives 41
  verdicts — 37 documents broken one way at a time, three the checker must accept, and the valid
  document itself — and requires each to be as expected; observed, all 41. The lint workflow runs
  the checker, its `--self-test`, and `scripts/pgxn-dist.sh` over the archive layout.
- **The archive.** `scripts/pgxn-dist.sh` reads the version through the checker, refuses a dirty
  working tree, makes the outdir absolute — so a relative path given from another directory lands in
  the same place for the archive and for the layout check — and writes `pg_gcm-<version>.zip` with
  `git archive HEAD` and the prefix `pg_gcm-<version>/`. It then opens the archive and requires
  `META.json`, `Makefile` and `pg_gcm.control` at the prefix, exactly one top-level directory, and
  a version in the archive's own `META.json` that matches its name. Observed: an archive of HEAD
  passed all of that, a working tree with an uncommitted change was refused, and the pgxn client
  (1.3.2) built and installed that archive in the PostgreSQL 17 build image, where
  `CREATE EXTENSION pg_gcm` and the Korean `LIKE '%길%'` round trip then passed.
- **The release step.** `release.yml`'s `publish` job builds the archive outside `dist/`, so it
  never joins the checksummed assets; the build runs before the release, so metadata the upload
  would refuse fails there. It creates the GitHub release and then uploads to
  `manager.pgxn.org/upload` last — the reversible step before the irreversible one — and the
  release and the upload are idempotent, so a re-run finishes a partial release rather than failing
  on what is already done:
  `gh release view` skips a release that is there, and a version already published
  (`api.pgxn.org/dist/pg_gcm/<version>/META.json`) is left alone, one PGXN would refuse to take
  twice. The upload is `curl` with HTTP Basic authentication, the multipart field `archive`, and
  `X-Requested-With: XMLHttpRequest` so success is `200` and a rejected distribution is `409`.
  `PGXN_USER` and `PGXN_PASSWORD` are secrets of the `release` environment, the one with required
  reviewers. A `workflow_dispatch` run validates and builds the archive and uploads nothing.
- **What it does not show.** No upload has run, and the archive's build and the round trip above
  were done by hand on one major, not in CI: the archive's sources are the same tracked files the
  `build` and `regress` workflows compile, so they are covered there, and the upload is left for the
  first tag. The metadata has not yet been through PGXN Manager's own validator. Distribution
  packages (Debian, RPM) are not built (Phase 5 keeps them for demand). Phase 5 was done with §8
  Open O17 still open: the PGXN path does not pass through the two performance gates, so the
  recording they wait for is not a prerequisite for it.

### Open

Numbers are never reused. O2–O16 are answered above: O7, O13 and O16 in Phase 1, O14 and O15 in
Phase 2.

| # | Question | How to settle it |
|---|---|---|
| O1 | When does 19 join the supported majors? 15–18 are settled. 19 is at beta 4, with RC1 announced for 2026-10-15 and release for 2026-10-29 (pgsql-hackers, 2026-09-28); the extension builds and passes every suite on `19beta4`, in a CI job labelled pre-release that is not meant to be a required check | Move it from `prerelease` to `supported` in `docker/versions.json` when the release image exists |
| O17 | What are the load and micro-benchmark ratios on the CI runner, and how tight may the ceilings be? The ceilings in `tests/load/baseline.json` (1.0) and `tests/bench/baseline.json` (per size: seal, open and det 1.3–1.5) are a placeholder, not a measurement of that runner. An O17 probe (2026-10-14) found that the old det ratio — the deterministic seal over the random one — depends on the runner's relative AES-GCM and SHA-256 throughput and ranged from about 3.3 to 9.6 at 65536 bytes, so it is recorded, not gated | Record the worst ratio and the runner's CPU from three runs of each of `load.yml` and `bench.yml` in `docs/perf.md`; the bench det gate now compares like for like (the deterministic seal over a bare deterministic seal). Set each ceiling to the worst observed value across the three runs times 1.2, rounded up to one decimal, and never above the placeholder; then move O17 to Established |

## 9. References

- PostgreSQL 18 documentation, F.26 pgcrypto: https://www.postgresql.org/docs/18/pgcrypto.html
- PostgreSQL 18 documentation, pgcrypto security limitations: https://www.postgresql.org/docs/18/pgcrypto.html#PGCRYPTO-SECURITY-LIMITATIONS
- PostgreSQL 18 documentation, `CREATE FUNCTION` (`STRICT`, defaults): https://www.postgresql.org/docs/18/sql-createfunction.html
- PostgreSQL 18 documentation, C-language functions and `fmgr`: https://www.postgresql.org/docs/18/xfunc-c.html
- PostgreSQL 18 documentation, packaging related objects into an extension: https://www.postgresql.org/docs/18/extend-extensions.html
- PostgreSQL 18 documentation, extension building infrastructure (PGXS): https://www.postgresql.org/docs/18/extend-pgxs.html
- PostgreSQL 18 documentation, customized options: https://www.postgresql.org/docs/18/runtime-config-custom.html
- PostgreSQL versioning policy: https://www.postgresql.org/support/versioning/
- OpenSSL manual, `OPENSSL_malloc(3)` (`CRYPTO_set_mem_functions`) and `EVP_EncryptInit(3)`
- NIST SP 800-38D: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- Oracle `DBMS_CRYPTO` (19c and 23ai/26ai), SQL Server Always Encrypted cryptography — for §1.1 only
