<!-- Generated from .agents/rules/code-review.md by scripts/agents-sync.py — edit the source. -->
# Code review rules

A review asks first whether the change can return the wrong plaintext, leak a key, or crash or leak in
a backend. Style comes last.

## Priorities (every comment must carry a prefix)
| Prefix | Meaning | Handling |
|---|---|---|
| **P1** | Blocks the merge. Correctness, security, backend stability or data compatibility is broken | Cannot merge until resolved |
| **P2** | Resolve before merge. Maintainability, a missing test, a document that disagrees | To defer, leave the issue number |
| **P3** | Optional. Style, naming, taste | The author's call |
| **Q** | Question | Promote to P1–P3 after the answer if warranted |

- Format: `P1: <what is wrong and why>. Repro: <conditions>. Suggestion: <code or direction>`.
- An approval states what the reviewer actually ran ("`make installcheck` passes on 17").

## Flow
1. Author self-review against the PR template.
2. Automated review: `code-reviewer`, plus `crypto-reviewer` on a crypto path. A prerequisite before
   human review, not a substitute.
3. Human review: one reviewer; two for `src/gcm.c`, `envelope.c`, `nonce.c`, the GUC code and `spec/`.
4. Merge: CI green, approvals, zero open P1, zero undeferred P2.

## Reviewer checklist (in this order)
**Correctness (P1)**
- [ ] Envelope offsets and lengths match `spec/envelope.md`
- [ ] The tag-failure path discards the output and honours `pg_gcm.strict`
- [ ] The key-length check runs on every call, and `pg_gcm.min_key_bytes` on every encryption
- [ ] NULL, empty string and maximum-length arguments are handled
- [ ] Encryption seals UTF-8; decryption verifies UTF-8 and converts to the database encoding, erroring on an unrepresentable character
- [ ] Volatility in the SQL script: `VOLATILE` / `STABLE`, never `IMMUTABLE`; `PARALLEL SAFE`

**Safety (P1)** — the blocked patterns in `crypto-safety.md`; every copy of key and plaintext cleansed before `pfree`

**Backend stability (P1)** — no `ereport(ERROR)` while an OpenSSL resource is live; no leak across an
error (valgrind or the counting allocator in CI); no `palloc` inside the core

**Architecture (P1/P2)** — `architecture.md`; `python3 scripts/check-architecture.py` passes

**Tests (P2)** — GWT; no branching in a test body; unit and regression together; vectors updated; the
Korean `LIKE` case and the cross-database envelope case still present; every `expected/` change explained

**Compatibility (P1/P2)** — an envelope change happens in mysql-gcm too (or first); a function or GUC
change updates `spec/`, `docs/design.md` and the extension upgrade script (`pg_gcm--a--b.sql`)

**Documentation (P2)** — no conflict with `docs/design.md`; operational constraints reflected in the README

**Style (P3)** — `stack-*.md`

## PR size
- Over 400 net lines (excluding `expected/` and vector JSON), ask for a split. Never mix a refactor and
  a behaviour change.
