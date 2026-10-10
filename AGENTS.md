# postgres-gcm — AGENTS.md

An open-source project that adds AES-GCM encryption and decryption functions to PostgreSQL as a C
**extension** (`pg_gcm`) — AES-256 by default, with AES-192 and AES-128 selected by key length behind
`pg_gcm.min_key_bytes`. It is the PostgreSQL sibling of
[mysql-gcm](https://github.com/devgyurak/mysql-gcm) and **shares its envelope format byte for byte**,
so a value sealed by one server opens on the other. Codex, Cursor and OpenCode read this file
directly; Claude Code reads it through the import in `CLAUDE.md`. The full rationale is
`docs/design.md`. **To change the design, amend that document first and then change the code.**

## 1. One-line summary

PostgreSQL's `pgcrypto` offers AES only in CBC, CFB and ECB (`encrypt()`), and OpenPGP with a SHA-1
MDC (`pgp_sym_encrypt()`); it has no GCM or other AEAD mode (PostgreSQL 18 documentation). This
extension **registers new SQL functions**, **takes the key as a SQL argument** as `pgcrypto` does, and
**returns the decrypted value as `text` in the database encoding**, so partial-match search keeps
working through PostgreSQL's own `LIKE`, `ILIKE` and collations.

## 2. Public surface (planned — a change updates `docs/design.md`, `spec/` and the regression tests in the same PR)

```
gcm_encrypt(plaintext text, key bytea [, aad bytea])      -> bytea  VOLATILE  random nonce (RAND_bytes, 12 B)
gcm_encrypt_det(plaintext text, key bytea [, aad bytea])  -> bytea  STABLE    deterministic — joins, UNIQUE and exact match only
gcm_decrypt(ciphertext bytea, key bytea [, aad bytea])    -> text   STABLE    UTF-8 verified, converted to the database encoding
```

- All three are `PARALLEL SAFE` and **never `IMMUTABLE`**: an immutable function may appear in an index
  or a generated column, which would put a key literal into the catalog and plaintext into an index
  (design §5.3).
- `key`: 32 bytes (AES-256), 24 (AES-192) or 16 (AES-128). Any other length is an error. **The key
  length selects the suite and nothing else does.** Keys are never folded, padded or hashed to fit.
- Plaintext is sealed as **UTF-8** whatever the database encoding, so envelopes are portable to
  mysql-gcm (whose `utf8mb4` is UTF-8). Decryption verifies UTF-8 and converts to the database
  encoding; a character the database encoding cannot hold is an error, never a silent substitution.
- Deterministic nonce: `nonce_key = HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")`,
  `nonce = HMAC-SHA256(nonce_key, plaintext)[:12]`. The label keeps its `mysql-gcm` spelling on
  purpose: changing it would make deterministic ciphertext differ between the two projects.
- Envelope (normative definition: `spec/envelope.md`, adopted from mysql-gcm in Phase 1):

```
0x01  legacy AES-256-CBC (dual-read only; never produced) — semantics to confirm in Phase S
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

## 3. Repository layout (planned; Phase S creates the first of it)

```
AGENTS.md / CLAUDE.md          Agent instructions (this file is the source)
.agents/rules/                 Rule sources, shared across tools
.agents/skills/                Skill sources, shared across tools
docs/design.md                 The design document — rationale, decisions, open questions, phases
docs/ops-constraints.md        Operational constraints — also duplicated on the README's first screen (Phase 4)
spec/envelope.md               The envelope and failure semantics (Phase 1, adopted from mysql-gcm)
spec/test-vectors.json         NIST CAVP GCM KAT plus the shared project vectors (Phase 1)
src/                           The extension (C11)
  pg_gcm.c                     _PG_init, GUC registration, the fetched-handle cache
  fn_encrypt.c fn_decrypt.c    The SQL-callable glue — argument checks, encoding, error translation only
  gcm.{h,c}                    The OpenSSL EVP wrapper (no PostgreSQL header → unit testable)
  envelope.{h,c}               Envelope encoding and decoding (no OpenSSL either)
  nonce.{h,c}                  The synthetic nonce and the nonce_key derivation (EVP_MAC HMAC-SHA256)
pg_gcm.control                 Extension control file
sql/pg_gcm--0.1.0.sql          The extension's install script (function declarations)
Makefile                       PGXS build (`make USE_PGXS=1`)
test/sql/, test/expected/      pg_regress suites — the real-server SQL scenarios (`make installcheck`)
tests/unit/                    GoogleTest — gcm/envelope/nonce, linking libcrypto alone with no server
tests/e2e/                     compose: primary + streaming replica + a mysql-gcm server + a Python SQL runner
tests/load/                    Load: decrypt + LIKE over 10k/100k/300k rows, gated against pgcrypto
tests/bench/                   Core micro-benchmarks (Google Benchmark) — ratios against bare EVP
scripts/                       dev-up.sh, build-in-docker.sh, verify.sh, agents-sync.sh, check-architecture.py
docker/                        build.Dockerfile (postgres:<major> + server-dev headers) + versions.json
.github/workflows/             CI — added per phase (ci-release skill)
```

## 4. Build and verification commands (the skills hold the detail)

| Purpose | Command | Skill |
|---|---|---|
| Start a development server | `scripts/dev-up.sh 17` | `dev-container` |
| Build the extension | `scripts/build-in-docker.sh 17` | `pg-extension` |
| Unit tests | `cmake -S tests/unit -B build/unit && cmake --build build/unit && ctest --test-dir build/unit` | `unit-tests` |
| Regression tests | `scripts/verify.sh 17` (installs into a container, runs `make installcheck`) | `regress-tests` |
| E2E | `docker compose -f tests/e2e/compose.yml up --exit-code-from runner` | `e2e-load-tests` |
| Load | `python tests/load/run.py --rows 300000 --baseline pgcrypto` | `e2e-load-tests` |
| Architecture boundaries | `python3 scripts/check-architecture.py` | `.agents/rules/architecture.md` |
| Agent adapters | `scripts/agents-sync.sh [--check]` | this file, §7 |

If a command does not exist yet (Phase S), **create it as that skill prescribes**. Do not introduce a
different build method on your own.

## 5. Absolute rules (the full text is in `.agents/rules/`)

**Crypto (`crypto-safety.md`, always applies)**
- Fetch by name with `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)`. Never call the `EVP_aes_256_gcm()`
  symbol directly.
- Use the libcrypto the server links. No static linking and no bundling of another version.
- Never put a key, plaintext or nonce in `elog`/`ereport`, an error detail or hint, or an assertion.
  `OPENSSL_cleanse` every copy of the key and plaintext before `pfree` — `pfree` does not zero.
- A tag verification failure is an error when `pg_gcm.strict` is on. Never return unauthenticated
  plaintext.
- The key length is 32, 24 or 16 bytes and selects the suite; the two encryption functions also refuse
  anything below `pg_gcm.min_key_bytes`.
- Do not put a key in a repository file, `postgresql.conf`, a GUC, an environment variable, a test
  fixture (the spec vectors excepted) or any DDL.

**Architecture (`architecture.md`)**
- The direction is SQL glue → core (`gcm` → `envelope`/`nonce`). The core does not include a
  PostgreSQL header and never calls `ereport` — it returns an error code, and the glue raises the error
  **after** releasing every OpenSSL resource, because `ereport(ERROR)` does not return.

**Extension (`extension-src.md`)**
- Version-1 calling convention (`PG_FUNCTION_INFO_V1`) and PGXS only. No server patch, no hook into the
  executor, no background worker.

**Tests (`testing.md`)**
- Every test is **GWT (Given-When-Then)**, with given/when/then visible in the name too.
- No `if`, `else`, `for` or `while` in a test case body. Split the cases or parameterise.
- A behaviour-change PR brings unit *and* regression tests. An envelope or nonce change updates
  `spec/test-vectors.json`.
- The Korean partial-match regression test `LIKE '%길%'` must never be deleted (it is the reason the
  project exists), nor the cross-database test that opens a mysql-gcm envelope.

**Product scope and Python (same as mysql-gcm)**
- What ships is the PostgreSQL extension and its SQL API. No encryption client or SDK in any language.
- Python is used only for vector checks and for the SQL E2E and load runners, which encrypt and decrypt
  through the server's SQL functions.

**Review (`code-review.md`)**
- Comment priorities are **P1 / P2 / P3**, plus `Q`.
- A PR touching the crypto, envelope or GUC paths needs a `crypto-reviewer` pass and two human
  reviewers.

## 6. Current phase and roadmap

Current: **Phase 0 — planning.** The agent workflow and `docs/design.md` exist; no code yet. Next is
Phase S.

| Phase | Deliverable | Done when |
|---|---|---|
| S spike | A minimal extension passing `scripts/verify.sql` on 15–18 | `CREATE EXTENSION` · key-length check · `SET pg_gcm.strict` · Korean `LIKE` on a decrypted value · `EVP_CIPHER_fetch` inside a backend · an `ereport` path that leaks nothing (valgrind or a counter) · the answers to design §8 "Open" recorded |
| 1 spec | `spec/envelope.md`, `spec/test-vectors.json` adopted from mysql-gcm | Byte format identical; PostgreSQL failure semantics (SQLSTATEs, NULL handling, encoding) settled |
| 2 implementation | `src/`, `tests/unit`, `test/sql` | CI green, including the nonce collision boundary test |
| 3 SQL E2E | `tests/e2e` | Round trip, Korean `LIKE`, streaming replication, and a mysql-gcm ↔ postgres-gcm envelope exchange pass |
| 4 distribution | Build matrix, README, `docs/ops-constraints.md`, load baseline | Release artifacts plus checksums and an SBOM; a server image with the extension preinstalled |
| 5 ecosystem | PGXN, distribution packages | Optional |

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
- Where mysql-gcm already settled a question (the envelope, the nonce construction, strict semantics,
  the operational responsibilities in its amendment A8 and A12), follow it and cite it. Diverge only
  through an amendment that says why PostgreSQL differs.
- Confirm an unfamiliar PostgreSQL or OpenSSL API **against the headers and the official
  documentation** for every supported major. Do not guess a signature.
- Commits: Conventional Commits (`feat(ext): ...`, `fix(crypto): ...`, `test(regress): ...`, `ci: ...`,
  `docs: ...`). One commit, one concern.
- PRs: fill in every item of `.github/PULL_REQUEST_TEMPLATE.md`. Split a diff over 400 net lines.
  Branches: feature → `develop` → `main` → tag `v*`, as in mysql-gcm.
- **English first.** Everything committed is written in English. `README.md` and `docs/design.md` may
  carry a `-KO.md` translation; the English file is canonical and both change in the same PR. Korean
  strings in tests are **data** (`'홍길동'`, `LIKE '%길%'`) and are never translated. **Conversation
  with the user is in Korean.**
- Managed PostgreSQL (RDS, Aurora, Cloud SQL, Azure) does not load third-party C extensions; it is out
  of scope, as are proxies, poolers' own encryption and key management systems.
