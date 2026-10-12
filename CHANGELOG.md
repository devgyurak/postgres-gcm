# Changelog

Notable changes per release. Envelope changes get their own entry with a compatibility note.

## Unreleased

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
