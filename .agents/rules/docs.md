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
- `spec/envelope.md` stays byte-identical in its shared sections to mysql-gcm's at the pinned commit;
  the PostgreSQL-specific section (SQLSTATEs, encoding, NULL) is clearly separated.
- `spec/test-vectors.json` uses mysql-gcm's schema unchanged.
- The license is open (design §7). Do not add a `LICENSE` file or SPDX headers until it is decided.
