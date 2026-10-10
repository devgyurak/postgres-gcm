# Changelog

Notable changes per release. Envelope changes get their own entry with a compatibility note, and
happen in lockstep with mysql-gcm.

## Unreleased

### Planned
- Phase 0: the agent workflow (`AGENTS.md`, rules, skills, subagents, guard hook, adapter sync) and
  `docs/design.md` with the function surface, GUCs, lifetimes, error model, operational constraints and
  the open questions for Phase S.
- License: the PostgreSQL License (`LICENSE`, design §7), with SPDX headers.
- `docs/design-KO.md`, the Korean translation of the design.
- Design revised after checking the plan against the PostgreSQL 15–18 sources, the official images and
  mysql-gcm (2026-10-10): every function `STRICT` with AAD as two overloads instead of `DEFAULT NULL`;
  text verified and converted through the `noError` server APIs so no error message carries plaintext
  bytes; the cleansing rule scoped to the extension's own copies; OpenSSL 3.0 or later required;
  `_PG_init` fetching before it registers GUCs; six of the ten open questions answered in design §8.
