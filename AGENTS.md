# postgres-gcm — AGENTS.md

An open-source project that adds AES-GCM encryption and decryption functions to PostgreSQL as a C
**extension** (`pg_gcm`) — AES-256 by default, with AES-192 and AES-128 selected by key length behind
`pg_gcm.min_key_bytes`. Codex, Cursor and OpenCode read this file
directly; Claude Code reads it through the import in `CLAUDE.md`. The full rationale is
`docs/design.md`. **To change the design, amend that document first and then change the code.**

## 1. One-line summary

PostgreSQL's `pgcrypto` offers AES only in CBC, CFB and ECB (`encrypt()`), and OpenPGP with a SHA-1
MDC (`pgp_sym_encrypt()`); it has no GCM or other AEAD mode (PostgreSQL 18 documentation). This
extension **registers new SQL functions**, **takes the key as a SQL argument** as `pgcrypto` does, and
**returns the decrypted value as `text` in the database encoding**, so partial-match search keeps
working through PostgreSQL's own `LIKE`, `ILIKE` and collations. It supports PostgreSQL 15–18 on a
server that links **OpenSSL 3.0 or later** (design §0).

## 2. Public surface (a change updates `docs/design.md`, `spec/` and the regression tests in the same PR)

```
gcm_encrypt(plaintext text, key bytea [, aad bytea])      -> bytea  VOLATILE  random nonce (RAND_bytes, 12 B)
gcm_encrypt_det(plaintext text, key bytea [, aad bytea])  -> bytea  STABLE    deterministic — joins, UNIQUE and exact match only
gcm_decrypt(ciphertext bytea, key bytea [, aad bytea])    -> text   STABLE    UTF-8 verified, converted to the database encoding
```

- All three are `PARALLEL SAFE` and **never `IMMUTABLE`**: an immutable function may appear in an index
  or a generated column, which would put a key literal into the catalog and plaintext into an index
  (design §5.3).
- All three are **`STRICT`**: NULL in any argument gives NULL with no cryptographic work.
  `[, aad bytea]` is **two overloads per function, never
  `DEFAULT NULL`**, so that omitting `aad` encrypts and an explicit NULL propagates. A NULL default
  cannot do both: under `STRICT` it makes the two-argument call return NULL, and without `STRICT` an
  explicit NULL would seal silently without AAD — the value would then open without the binding it
  was meant to carry, and nothing would say so. (`DEFAULT ''` would also work; overloading is the
  choice — design §2.1.)
- `key`: 32 bytes (AES-256), 24 (AES-192) or 16 (AES-128). Any other length is an error. **The key
  length selects the suite and nothing else does.** Keys are never folded, padded or hashed to fit.
- Plaintext is sealed as **UTF-8** whatever the database encoding, so an envelope does not
  depend on the database that sealed it. Decryption verifies UTF-8 and converts to the database
  encoding; a character the database encoding cannot hold is an error, never a silent substitution.
  Verification and conversion use the forms that report by return value (`pg_verify_mbstr(...,
  true)`, `pg_do_encoding_conversion_buf(..., true)`): `pg_any_to_server` and `pg_server_to_any` put
  the offending bytes — decrypted plaintext — into the error message (design §5.7).
- The associated data given to GCM is `A = version || aad`: every byte of an envelope is
  authenticated, the version byte included (design §8 O13).
- Deterministic nonce: `nonce_key = HMAC-SHA256(key, "pg_gcm/v1/det-nonce")`,
  `nonce = HMAC-SHA256(nonce_key, be64(len(A)) || A || plaintext)[:12]` — the AAD is an input, so one
  key may be used with any number of AAD values (design §8 O16).
- Envelope (normative definition: `spec/envelope.md`):

```
0x01  legacy AES-256-CBC — reserved; never produced and not opened in 0.1 (design §8 O6)
0x02  AES-256-GCM random        : 0x02 || nonce(12) || ciphertext || tag(16)
0x03  AES-256-GCM deterministic : 0x03 || nonce(12) || ciphertext || tag(16)
0x04  AES-128-GCM random        : same layout
0x05  AES-128-GCM deterministic : same layout
0x06  AES-192-GCM random        : same layout
0x07  AES-192-GCM deterministic : same layout
```

- GUCs: `pg_gcm.strict` (`PGC_USERSET`, default on) — on a tag mismatch, on gives an error and off
  gives NULL. `pg_gcm.min_key_bytes` (`PGC_SUSET`, default 32) — the smallest key the two encryption
  functions accept, so a truncated key cannot silently select a weaker suite; only a superuser (or a
  role granted `SET` on it) can lower it, and decryption ignores it.
- Out of scope from the start: keyring or KMS integration, key ids, a key stored in a GUC or a table.
  If asked for one, turn it back into a proposal to amend the design.

## 3. Repository layout

```
AGENTS.md / CLAUDE.md          Agent instructions (this file is the source)
.agents/rules/                 Rule sources, shared across tools
.agents/skills/                Skill sources, shared across tools
docs/design.md                 The design document — rationale, decisions, open questions, phases
docs/design-KO.md              Its Korean translation. The English file above is canonical
LICENSE                        The PostgreSQL License (design §7)
docs/ops-constraints.md        Operational constraints — also summarised on the README's first screen
docs/perf.md                   The load baseline and both performance gates
spec/envelope.md               The envelope (Part 1) and its PostgreSQL binding with the failure semantics (Part 2)
spec/test-vectors.json         NIST CAVP GCM KAT plus the project's own vectors, reproduced by scripts/check-vectors.py
src/                           The extension (C11)
  pg_gcm.{h,c}                 _PG_init, GUC registration, what the glue files share
  fn_encrypt.c fn_decrypt.c    The SQL-callable glue — argument checks, encoding, error translation only
  gcm.{h,c}                    The OpenSSL EVP wrapper and the fetched handles (no PostgreSQL header → unit testable)
  envelope.{h,c}               Envelope encoding and decoding (no OpenSSL either)
  nonce.{h,c}                  The synthetic nonce and the nonce_key derivation (EVP_MAC HMAC-SHA256)
pg_gcm.control                 Extension control file
META.json                      The PGXN distribution metadata (PGXN Meta Spec 1.0.0)
sql/pg_gcm--0.1.0.sql          The extension's install script (function declarations)
Makefile                       PGXS build (`make USE_PGXS=1`)
test/sql/, test/expected/      pg_regress suites — the real-server SQL scenarios (`make installcheck`)
tests/unit/                    GoogleTest — gcm/envelope/nonce, linking libcrypto alone with no server
tests/e2e/                     compose: primary + streaming replica + a Python SQL runner
tests/load/                    Load: decrypt + LIKE over 10k/100k/300k rows, gated against pgcrypto
tests/bench/                   Core micro-benchmarks (Google Benchmark) — ratios against bare EVP
scripts/                       dev-up.sh, build-in-docker.sh, verify.sh (+ verify.sql), unit-in-docker.sh, e2e.sh, load.sh,
                               bench.sh, server-image.sh, smoke-image.sh, smoke-tarball.sh, package.sh (+ sbom.py, release-guard.py),
                               pgxn-dist.sh (+ check-pgxn.py), agents-sync.sh, check-architecture.py, check-action-pins.py,
                               check-vectors.py, ci-matrix.py, lib.sh
scripts/spike/                 The Phase S measurements (measure.sh, ldd.sh, a never-shipped probe module)
docker/                        build.Dockerfile, server.Dockerfile, initdb.d/, versions.json
.github/workflows/             CI — added per phase (ci-release skill)
```

## 4. Build and verification commands (the skills hold the detail)

| Purpose | Command | Skill |
|---|---|---|
| Start a development server | `scripts/dev-up.sh 17` | `dev-container` |
| Build the extension | `scripts/build-in-docker.sh 17` | `pg-extension` |
| Unit tests | `cmake -S tests/unit -B build/unit && cmake --build build/unit && ctest --test-dir build/unit` (in the Linux build image: `scripts/unit-in-docker.sh 17`) | `unit-tests` |
| Regression tests | `scripts/verify.sh 17` (after the two rows above: installs the build into the dev container, runs `make installcheck`, then `scripts/verify.sql`) | `regress-tests` |
| E2E | `scripts/e2e.sh 17` (after the build: a primary, a streaming replica and the SQL runner of `tests/e2e/compose.yml`) | `e2e-load-tests` |
| Load | `scripts/load.sh 17` (after the build: the dev server, then the rows × sessions matrix of `tests/load/run.py` in a runner; the worst gcm/pgcrypto ratio is the gate) | `e2e-load-tests` |
| Core benchmarks | `scripts/bench.sh 17` (after the build image: the core's seal and open against bare OpenSSL EVP, gated as ratios) | `e2e-load-tests` |
| Distribution image | `scripts/server-image.sh 17 [tag]` then `scripts/smoke-image.sh <tag>` (before anything is pushed) | `ci-release` |
| Release artifacts | `scripts/package.sh 17 arm64 [outdir]`, `scripts/smoke-tarball.sh 17 <tarball>`, `python3 scripts/sbom.py …`, `python3 scripts/release-guard.py …` | `ci-release` |
| PGXN source distribution | `scripts/check-pgxn.py`, `scripts/pgxn-dist.sh [outdir]` | `ci-release` |
| Spec vectors | `python3 scripts/check-vectors.py`, and `--self-test` (needs `pip install -r scripts/requirements-lint.txt`) | `unit-tests` |
| Architecture boundaries | `python3 scripts/check-architecture.py` | `.agents/rules/architecture.md` |
| Agent adapters | `scripts/agents-sync.sh [--check]` | this file, §7 |

Every command exists as of Phase 4. A new one is created **as that skill prescribes**; do not introduce a
different build method on your own.

## 5. Absolute rules (the full text is in `.agents/rules/`)

**Crypto (`crypto-safety.md`, always applies)**
- Fetch by name with `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)`. Never call the `EVP_aes_256_gcm()`
  symbol directly.
- Use the libcrypto the server links. No static linking and no bundling of another version.
- Never put a key, plaintext or nonce in `elog`/`ereport`, an error detail or hint, or an assertion —
  and never call a server function that would (`pg_any_to_server`, `pg_server_to_any`,
  `pg_verify_mbstr` with `noError` false).
- `OPENSSL_cleanse` every copy of the key and plaintext **that the extension made** before `pfree` —
  `pfree` does not zero. **Never write to an argument in place**: one that was not detoasted is a
  cached plan's constant, a bind value or a shared buffer page (design §5.2).
- A tag verification failure is an error when `pg_gcm.strict` is on. Never return unauthenticated
  plaintext.
- The key length is 32, 24 or 16 bytes and selects the suite; the two encryption functions also refuse
  anything below `pg_gcm.min_key_bytes`.
- Do not put a key in a repository file, `postgresql.conf`, a GUC, an environment variable, a test
  fixture (the spec vectors excepted) or any DDL.
- No document may promise more than the trust boundary allows: keys and plaintext cross the client
  connection and exist in the server, so the connection must be protected (a local socket, or TLS with
  the server verified) and the server's administrators trusted (design §5.4, docs/ops-constraints.md item 12).

**Architecture (`architecture.md`)**
- The direction is SQL glue → core (`gcm` → `envelope`/`nonce`). The core does not include a
  PostgreSQL header and never calls `ereport` — it returns an error code, and the glue raises the error
  **after** releasing every OpenSSL resource, because `ereport(ERROR)` does not return.

**Extension (`extension-src.md`)**
- Version-1 calling convention (`PG_FUNCTION_INFO_V1`) and PGXS only. No server patch, no hook into the
  executor, no background worker.
- `_PG_init` fetches the OpenSSL handles before it registers the GUCs and never raises (design §5.8).

**Tests (`testing.md`)**
- Every test is **GWT (Given-When-Then)**, with given/when/then visible in the name too.
- No `if`, `else`, `for` or `while` in a test case body. Split the cases or parameterise.
- A behaviour-change PR brings unit *and* regression tests. An envelope or nonce change updates
  `spec/test-vectors.json`.
- The Korean partial-match regression test `LIKE '%길%'` must never be deleted (it is the reason the
  project exists).

**Product scope and Python**
- What ships is the PostgreSQL extension and its SQL API. No encryption client or SDK in any language.
- Python is used only for vector checks and for the SQL E2E and load runners, which encrypt and decrypt
  through the server's SQL functions.

**Review (`code-review.md`)**
- Comment priorities are **P1 / P2 / P3**, plus `Q`.
- A PR touching the crypto, envelope or GUC paths needs a `crypto-reviewer` pass and two human
  reviewers.

## 6. Current phase and roadmap

Current: **Phase 4 is complete; Phase 5's PGXN packaging is in place (2026-10-14).** The extension
implements `spec/envelope.md`: the three suites by key length, the AAD overloads, `pg_gcm.strict`
and `pg_gcm.min_key_bytes`. The unit suite runs all 78
vectors of `spec/test-vectors.json`, the regression suite the 63 envelope vectors, and the
end-to-end suite its scenarios on a primary and on a streaming replica, on 15–18; the `unit`,
`build`, `regress` and `e2e` workflows run them. A load gate watches the decrypt-and-`LIKE` scan
against `pgcrypto` and core micro-benchmarks watch the seal and the open against bare OpenSSL EVP
(`docs/perf.md`) — **both gates have run three times from the default branch `main` and their
ceilings come from those runs** (§8, O17 answered) — the distribution image and the release
pipeline exist, and the operational constraints are `docs/ops-constraints.md`. The PGXN metadata
(`META.json`) and the source-distribution pipeline (`scripts/check-pgxn.py`,
`scripts/pgxn-dist.sh`, the `publish` job of `release.yml`) are in place, and nothing has been
uploaded. **Nothing is released and it is not for use yet**: no tag has been cut and the format
may change until 0.1.0.

| Phase | Deliverable | Done when |
|---|---|---|
| S spike | A minimal extension passing `scripts/verify.sql` on 15–18 | `CREATE EXTENSION` · key-length check · `SET pg_gcm.strict` · Korean `LIKE` on a decrypted value · handles fetched before fork working in two backends · no raising call inside an OpenSSL window · the answers to design §8 "Open" recorded |
| 1 spec | `spec/envelope.md`, `spec/test-vectors.json` | Byte format, vectors and PostgreSQL failure semantics (SQLSTATEs, NULL handling, encoding) settled |
| 2 implementation | `src/`, `tests/unit`, `test/sql` | CI green, including the nonce collision boundary test |
| 3 SQL E2E | `tests/e2e` | Round trip, Korean `LIKE` and streaming replication pass |
| 4 distribution | Build matrix, packaging and the release pipeline, the distribution image, the load gate and the core micro-benchmarks (`docs/perf.md`), `docs/ops-constraints.md` and the README | Release artifacts plus checksums, a signature and an SBOM; a server image with the extension preinstalled; both performance gates run in CI |
| 5 ecosystem | The PGXN metadata and source distribution — `META.json`, `scripts/check-pgxn.py`, `scripts/pgxn-dist.sh` and the PGXN upload in `release.yml`; distribution packages await demand | `META.json` valid against the PGXN Meta Spec and cross-checked with the control file and the tree; the archive is the PGXN layout; a tag uploads it to PGXN Manager |

## 7. Where each tool's agent configuration lives

There is one source for each concept and the rest are adapters **generated by
`scripts/agents-sync.sh`**. Edit the source, re-run the script, and (once CI exists) `--check` fails a
PR whose adapters are stale. Never edit a generated file.

| Concept | Source | Claude Code | Codex | Cursor | OpenCode |
|---|---|---|---|---|---|
| Project instructions | `AGENTS.md` | `CLAUDE.md` (`@AGENTS.md`) | native | native | native |
| Path rules | `.agents/rules/*.md` | `.claude/rules/*.md` (generated) | read via this file | `.cursor/rules/*.mdc` (generated) | `opencode.json` `instructions` |
| Skills | `.agents/skills/*/SKILL.md` | `.claude/skills` → symlink | native | `.cursor/skills` → symlink | native |
| Subagents | `.claude/agents/*.md` | native | `.codex/agents/*.toml` (generated) | `.cursor/agents` → symlink | `.opencode/agents/*.md` (generated) |
| Permissions and hooks | `.claude/settings.json` + `.claude/hooks/guard.sh` | native | `sandbox_mode` per agent | — | `opencode.json` `permission` |

## 8. When to use a skill or a subagent

| Situation | Use |
|---|---|
| Before touching extension sources, the fmgr API, GUCs or the build | the `pg-extension` and `guc-config` skills |
| Writing or changing EVP, envelope or nonce code | the `gcm-crypto` skill → then the `crypto-reviewer` subagent |
| When a PostgreSQL or OpenSSL API signature is uncertain | the `pg-api-researcher` subagent (no guessing — check the headers) |
| Writing tests | the `unit-tests` / `regress-tests` / `e2e-load-tests` skills |
| Local verification, the Phase S checks | the `dev-container` skill → the `verify-runner` subagent |
| Reviewing a PR | the `code-review` skill → the `code-reviewer` subagent (plus `crypto-reviewer`) |
| CI and release workflows | the `ci-release` skill |
| A per-stack convention | `.agents/rules/stack-*.md` |

## 9. How to work

- Read the relevant section of `docs/design.md` before starting. If you need a judgement that differs
  from the design, propose a document amendment instead of writing the code.
- Confirm an unfamiliar PostgreSQL or OpenSSL API **against the headers and the official
  documentation** for every supported major. Do not guess a signature.
- Commits: Conventional Commits (`feat(ext): ...`, `fix(crypto): ...`, `test(regress): ...`, `ci: ...`,
  `docs: ...`). One commit, one concern.
- PRs: fill in every item of `.github/PULL_REQUEST_TEMPLATE.md`. Split a diff over 400 net lines.
  Branches: feature → `develop` → `main` → tag `v*`.
- **English first.** Everything committed is written in English. `README.md` and `docs/design.md` may
  carry a `-KO.md` translation; the English file is canonical and both change in the same PR. Korean
  strings in tests are **data** (`'홍길동'`, `LIKE '%길%'`) and are never translated. **Conversation
  with the user is in Korean.**
- Managed PostgreSQL (RDS, Aurora, Cloud SQL, Azure) does not load third-party C extensions; it is out
  of scope, as are proxies, poolers' own encryption and key management systems.
