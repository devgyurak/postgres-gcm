# Changelog

Notable changes per release. Envelope changes get their own entry with a compatibility note.

## Unreleased

### Phase 3 — SQL E2E (2026-10-13)
- `tests/e2e`: a primary, a streaming replica taken from it with `pg_basebackup`, and a Python
  runner that only issues SQL with keys as bind parameters. Twenty-one scenarios: the replica is a
  streaming standby that refuses writes; the round trip, the Korean `LIKE`, deterministic lookups
  and joins, a forged tag under each setting of `pg_gcm.strict` and NULL arguments, on the node
  that sealed the rows and on the one that only replayed them.
- `scripts/e2e.sh <major>` runs it; the `e2e` workflow runs it for every image.

### Phase 2 — implementation and tests (2026-10-12)
- The extension implements `spec/envelope.md`. AES-128, AES-192 and AES-256 are selected by the key
  length (16, 24 or 32 bytes); each function has a three-argument form taking `aad`; the associated
  data is `version || aad` and the deterministic nonce is derived from it and the plaintext.
- `pg_gcm.min_key_bytes` (`PGC_SUSET`, default 32): the two encryption functions refuse a shorter
  key with `22023`. Decryption does not consult it.
- The encoding conversion is looked up in `pg_catalog` alone, not along `search_path` (design O14).
  The HMAC digest is still resolved by name on each deterministic call (design O15: kept).
- **Compatibility:** an envelope sealed by a Phase S build does not open any more. Nothing was
  released, so nothing stored is affected.
- Tests read `spec/test-vectors.json` and carry no known answer of their own: the unit suite runs
  all 78 vectors and a nonce collision test; the regression suite runs the 63 envelope vectors,
  the AAD forms, `pg_gcm.min_key_bytes` (placeholders included) and the conversion lookup.
- After review: `gcm_decrypt` sizes its result to the plaintext; a fetched cipher that does not
  report a block size of 1 and its suite's key length is not used; one more vector, `tag-last-bit-flipped-empty`.
- `pg_gcm.so` exports its SQL functions and nothing else on every major; on PostgreSQL 15 a build
  used to export the core's functions too. The build fails on a stray export.
- CI: the `unit`, `build` (every image × amd64 and arm64) and `regress` workflows, their matrices
  taken from `docker/versions.json`.

### Phase 1 — the spec (2026-10-12)
- `spec/envelope.md`: the envelope format (Part 1, free of PostgreSQL terms) and its PostgreSQL
  binding (Part 2): functions, keys, NULL, text and encodings, one SQLSTATE per failure class.
- **Format decisions, both changes to the construction.** The version byte is authenticated: the
  associated data given to GCM is `version || aad` (design O13). The deterministic nonce is derived
  from that associated data as well as the plaintext, so one key may be used with any number of AAD
  values (design O16); the earlier rule of one AAD convention per deterministic key is gone.
- **Compatibility:** an envelope sealed by a Phase S build does not open under the specification, and
  the reverse. Nothing was released, so nothing stored is affected. The code on `develop` is still the
  spike; Phase 2 brings it to the specification (issue #19).
- `spec/test-vectors.json`: 77 vectors — 15 NIST CAVP known answers for AES-GCM and 62 of the
  project's own, 30 that open and 32 that do not — and `scripts/check-vectors.py`, which re-derives
  every one with a second implementation and, with `--self-test`, checks that it notices a fixed
  list of broken inputs. Both run in the lint workflow.
- The SQLSTATEs are settled (design O7): a tag mismatch stays `XX001`.

### Phase S — the spike (2026-10-12)
- A minimal extension, not for use: AES-256-GCM only, the two-argument forms of `gcm_encrypt`,
  `gcm_encrypt_det` and `gcm_decrypt`, and `pg_gcm.strict`. No AAD, no 24- or 16-byte keys, no
  `pg_gcm.min_key_bytes`, no envelope specification yet.
- It builds with PGXS and passes the unit suite, 14 `pg_regress` files and the Phase S checks on
  PostgreSQL 15–18, on 19beta4, and on a server that links OpenSSL 3.0.22 (`scripts/verify.sh`).
- The development scripts (`build-in-docker.sh`, `dev-up.sh`, `verify.sh`, `unit-in-docker.sh`), the
  architecture and action-pin checks, the lint workflow, and the measurement scripts under
  `scripts/spike/`.
- `docs/design.md` §8 records what the spike established: O4, O6, O8, O11 and O12 are answered, O7 is
  narrowed, and O13 (the version byte is not authenticated), O14 (the conversion lookup follows
  `search_path`) and O15 (the HMAC digest is resolved by name on every deterministic call) are new. `0x01` is not implemented in 0.1. The functions are declared `COST` 50, 100
  and 200.

### Planned
- Phase 0: the agent workflow (`AGENTS.md`, rules, skills, subagents, guard hook, adapter sync) and
  `docs/design.md` with the function surface, GUCs, lifetimes, error model, operational constraints and
  the open questions for Phase S.
- License: the PostgreSQL License (`LICENSE`, design §7), with SPDX headers.
- `docs/design-KO.md`, the Korean translation of the design.
- Design revised after checking the plan against the PostgreSQL 15–18 sources and the official images
  (2026-10-10): every function `STRICT` with AAD as two overloads instead of `DEFAULT NULL`;
  text verified and converted through the `noError` server APIs so no error message carries plaintext
  bytes; the cleansing rule scoped to the extension's own copies; OpenSSL 3.0 or later required;
  `_PG_init` fetching before it registers GUCs; six of the ten open questions answered in design §8.
- The project stands alone: its own envelope specification and vectors, and its own deterministic-nonce
  label (`pg_gcm/v1/det-nonce`).
