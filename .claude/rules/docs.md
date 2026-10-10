---
paths:
  - "docs/**"
  - "spec/**"
  - "README.md"
  - "README-KO.md"
---
<!-- Generated from .agents/rules/docs.md by scripts/agents-sync.py — edit the source. -->
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
- `spec/envelope.md` stays byte-identical in its shared sections to mysql-gcm's at the pinned commit.
  The shared sections are its §2 (layout), §3 (derivation), §5 (worked examples) and the vector schema
  in §6; mysql-gcm's §1 and §4 are written in MySQL's terms and are not compared. The PostgreSQL
  binding (SQLSTATEs, the encoding rule and its exceptions, what SQL expects for a non-UTF-8 vector) is
  a clearly separated part (design §2.2).
- `spec/test-vectors.json` uses mysql-gcm's schema unchanged.
- The license is **the PostgreSQL License** (design §7): full text in `LICENSE`,
  `SPDX-License-Identifier: PostgreSQL` at the head of every source and script file, and a link to
  `LICENSE` from both READMEs. Changing it means amending design §7 first.
- Never port code from mysql-gcm that someone other than its author contributed, without that
  contributor's written permission (design §7).
