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
- [ ] NULL in any argument gives NULL (`STRICT`); the empty string and maximum-length arguments are handled
- [ ] Encryption seals UTF-8; decryption verifies UTF-8 and converts to the database encoding, erroring on an unrepresentable character — through the `noError` forms only, so no message carries a byte of the data
- [ ] The SQL script: `VOLATILE` / `STABLE`, never `IMMUTABLE`; `STRICT`; `PARALLEL SAFE`; an explicit `COST`; AAD as two overloads, never `DEFAULT NULL`

**Safety (P1)** — the blocked patterns in `crypto-safety.md`; every copy of key and plaintext the
extension made cleansed before `pfree`, on the `PG_FINALLY` paths too; no argument written to in place

**Backend stability (P1)** — no `ereport(ERROR)` while an OpenSSL resource is live; no leak across a
core error path (the unit suite's counting allocator — nothing can count inside a backend); no
`palloc` inside the core; `_PG_init` fetches before it registers GUCs and never raises

**Architecture (P1/P2)** — `architecture.md`; `python3 scripts/check-architecture.py` passes

**Tests (P2)** — GWT; no branching in a test body; unit and regression together; vectors updated; the
Korean `LIKE` case still present; every `expected/` change explained

**Compatibility (P1/P2)** — an envelope change updates `spec/envelope.md` and the vectors in the same PR; a function or GUC
change updates `spec/`, `docs/design.md` and the extension upgrade script (`pg_gcm--a--b.sql`)

**Documentation (P2)** — no conflict with `docs/design.md`; operational constraints reflected in the README

**Style (P3)** — `stack-*.md`

## PR size
- Over 400 net lines (excluding `expected/` and vector JSON), ask for a split. Never mix a refactor and
  a behaviour change.
