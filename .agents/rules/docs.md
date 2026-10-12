---
paths:
  - "docs/**"
  - "spec/**"
  - "README.md"
  - "README-KO.md"
---
# Documentation and spec rules

## Language
- **English first.** Code, comments, commits, PRs, documents and specs are in English.
- Only `README.md` and `docs/design.md` may carry a translation, named `README-KO.md` and
  `docs/design-KO.md`. The English file is canonical, and both change in the same PR.
- Korean in tests and fixtures is data and is never translated.
- Conversation with the user is in Korean; that does not change what is committed.

## Documents
- `docs/design.md` is the source of rationale. Where code and design disagree, the code is wrong or
  the design is amended first. §8 is updated whenever a fact is established, with the command or link
  that established it.
- A fact about PostgreSQL behaviour cites the documentation for the major it was checked on, or the
  spike command that showed it. "PostgreSQL does X" without a version is not a fact.
- README first-screen order: one-line summary → operational constraints (all of design §6) → support
  matrix → install → function table.
- `spec/envelope.md` is implementation-neutral in its format part: a byte-offset table, the nonce
  derivation, worked hex examples and the vector schema, from which another implementation could be
  built. The PostgreSQL binding (SQLSTATEs, the encoding rule and the plaintexts it rejects, what SQL
  expects for a non-UTF-8 vector) is a clearly separated part (design §2.2).
- `spec/test-vectors.json` schema:
  `{ "version": 1, "vectors": [ { "id", "kind": "random|det|nist", "key_hex", "nonce_key_hex"?, "nonce_hex"?, "aad_hex", "plaintext_hex", "envelope_hex", "expect": "ok|bad_tag|bad_envelope" } ] }`.
  Adding a field is a minor change; changing the meaning of one is major.
- The license is **the PostgreSQL License** (design §7): full text in `LICENSE`,
  `SPDX-License-Identifier: PostgreSQL` at the head of every source and script file, and a link to
  `LICENSE` from both READMEs. The `pg_regress` inputs and expected outputs (`test/sql`,
  `test/expected`) are the exception: they begin with their `-- Given:` line, which is echoed into
  the output a reviewer reads. Changing it means amending design §7 first.
