## What / Why
<!-- one paragraph; link the docs/design.md section if this touches a decision -->

## Scope
- [ ] Net diff ≤ 400 lines (excluding `test/expected/` and vectors), single concern
- [ ] Touches a crypto path (`src/gcm.c` `envelope.c` `nonce.c`, GUC code, `spec/**`, vector checks) → 2 human reviewers + `crypto-reviewer` report attached

## Correctness & safety (P1 — reviewer blocks on these)
- [ ] Envelope offsets/lengths match `spec/envelope.md` (and mysql-gcm's, byte for byte)
- [ ] Tag failure discards output; `pg_gcm.strict` semantics preserved (on = error, off = NULL)
- [ ] Key length (32/24/16, selecting the suite) checked per call, `pg_gcm.min_key_bytes` on encryption; no key/plaintext in messages
- [ ] Every copy of key and plaintext cleansed before `pfree`; no `ereport(ERROR)` reachable while an OpenSSL object is live
- [ ] Only `EVP_CIPHER_fetch` / `EVP_MAC_fetch` by name; libcrypto is the server's
- [ ] SQL script: no `IMMUTABLE`; volatility and `PARALLEL SAFE` as designed; released scripts untouched, upgrade script added

## Tests (GWT)
- [ ] Unit tests added/updated, Given-When-Then in name and body, no branching in test bodies
- [ ] `pg_regress` case added; every `test/expected/` diff explained below
- [ ] Vectors unchanged, or updated in lockstep with mysql-gcm
- [ ] Korean `LIKE '%길%'` case and the cross-database envelope case still present

## Compatibility & docs
- [ ] Function surface / GUCs / envelope unchanged, or `docs/design.md` + `spec/` + tests updated here
- [ ] Operational constraints still accurate

## Verification run locally
```
python3 scripts/check-architecture.py →
ctest --test-dir build/unit          →
scripts/verify.sh 17                 →
```
