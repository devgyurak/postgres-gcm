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
- The schema of `spec/test-vectors.json` is spec §1.11 and is not restated anywhere else. Adding a
  member is a minor change; changing the meaning of one is major and a new `version`.
- No hexadecimal example is typed into the spec by hand. Each worked example names its vector, and
  `scripts/check-vectors.py` checks runs of twelve or more hexadecimal digits, the bytes at stated
  offsets, the suite table and the outcomes table against it. It does not read prose: a claim made in
  words is the author's and the reviewer's to check.
- A vector is added as inputs and derived by the checker's implementation, never pasted from the
  extension's output; then `--self-test` must still pass.
- The license is **the PostgreSQL License** (design §7): full text in `LICENSE`,
  `SPDX-License-Identifier: PostgreSQL` at the head of every source and script file, and a link to
  `LICENSE` from both READMEs. The `pg_regress` inputs and expected outputs (`test/sql`,
  `test/expected`) are the exception: they begin with their `-- Given:` line, which is echoed into
  the output a reviewer reads. Changing it means amending design §7 first.
