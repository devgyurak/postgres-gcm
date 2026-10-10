---
name: code-review
description: Reviewing a PR or diff in this repository against the P1/P2/P3 priorities and the reviewer checklist, in order, and reporting in the prescribed format. Use it for "review this", for PR review, and for a self-review request.
---

# code-review

The rule source is `.agents/rules/code-review.md`. Checklist order: correctness → safety → backend
stability → architecture → tests → compatibility → documentation → style.

## Procedure
1. Scope: `git diff --stat <base>...HEAD`. Over 400 net lines, ask for a split (P2) and continue.
2. If a changed file touches a crypto path (`src/gcm.c`, `envelope.c`, `nonce.c`, `src/pg_gcm.c` GUCs,
   `spec/**`, `scripts/check-vectors.py`), **the parent agent** starts both `code-reviewer` and
   `crypto-reviewer` and merges the reports. When `code-reviewer` reports `NEEDS: crypto-reviewer`, the
   parent runs it.
3. Automated checks with `rg` (0 = match, a P1 candidate; 1 = pass; 2 = "check failed", not a pass):
   ```
   python3 scripts/check-architecture.py
   rg -n --type c -e 'EVP_aes_' -e '\bHMAC\(' -e '\brandom\(' -e 'pg_prng_' -e '(elog|ereport|errdetail|errhint)\([^;]*(key|plain|nonce)' -e 'StringInfo[^;]*key' src
   rg -n --type c -e 'pg_any_to_server' -e 'pg_server_to_any' -e 'pg_verify_mbstr\([^;]*false' -e 'on_proc_exit' src
   rg -n -i -e 'immutable' -e 'default null' sql
   rg -n -e 'log_statement' -e 'auto_explain' scripts tests docker
   ```
   Check each match in context before raising it.
4. Read the diff against each checklist item; record only defects with reproduction conditions.
   Speculation is a `Q`.
5. Tests: a test per changed function, GWT, every `expected/` change explained.
6. Run what you can: `ctest --test-dir build/unit`, `scripts/verify.sh 17`. Report results or "not run".

## Report format
```
## Review: <PR title or branch>
Ran: unit ✅ / verify.sh 17 ✅ / crypto-reviewer ✅ (or why not)

P1 (N)
- src/fn_decrypt.c:88 — ereport(ERROR) while ctx is live. Repro: forged tag with strict on leaks one
  EVP_CIPHER_CTX per call (counting allocator). Suggestion: free ctx before translating the error.
P2 (N)
P3 (N)
Q (N)
Verdict: BLOCK | APPROVE-WITH-P2 | APPROVE
```
File:line, what and why, reproduction, suggestion — all four, or it is not a comment.
