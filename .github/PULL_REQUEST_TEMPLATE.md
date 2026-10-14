## What / Why
<!-- one paragraph; link the docs/design.md section if this touches a decision -->

## Scope
- [ ] Net diff ≤ 400 lines (excluding `test/expected/` and vectors), single concern
- [ ] Touches a crypto path (`src/gcm.c` `envelope.c` `nonce.c`, GUC code, `spec/**`, vector checks) → 2 human reviewers + `crypto-reviewer` report attached

## Correctness & safety (P1 — reviewer blocks on these)
- [ ] Envelope offsets/lengths match `spec/envelope.md`
- [ ] Tag failure discards output; `pg_gcm.strict` semantics preserved (on = error, off = NULL)
- [ ] Key length (32/24/16, selecting the suite) checked per call, `pg_gcm.min_key_bytes` on encryption; no key/plaintext in messages
- [ ] NULL in any argument gives NULL (`STRICT`); the empty string and maximum-length arguments handled
- [ ] Text sealed as UTF-8, verified and converted on open through the `noError` forms only (`pg_verify_mbstr(..., true)`, `pg_do_encoding_conversion_buf(..., true)`)
- [ ] Every copy of key and plaintext the extension made cleansed before `pfree`, on the `PG_FINALLY` paths too; no argument written to in place
- [ ] No `ereport(ERROR)` reachable while an OpenSSL object is live; `_PG_init` fetches before it registers GUCs and never raises
- [ ] Only `EVP_CIPHER_fetch` / `EVP_MAC_fetch` by name; libcrypto is the server's
- [ ] SQL script: `VOLATILE` / `STABLE`, never `IMMUTABLE`; `STRICT`; `PARALLEL SAFE`; an explicit `COST`; AAD as two overloads, never `DEFAULT NULL`; released scripts untouched, upgrade script added

## Tests (GWT)
- [ ] Unit tests added/updated, Given-When-Then in name and body, no branching in test bodies
- [ ] `pg_regress` case added; every `test/expected/` diff explained below
- [ ] Vectors unchanged, or updated together with `spec/envelope.md` and reproducible (`scripts/check-vectors.py`)
- [ ] Korean `LIKE '%길%'` case still present

## Compatibility & docs
- [ ] Function surface / GUCs / envelope unchanged, or `docs/design.md` + `spec/` + tests updated here
- [ ] Operational constraints still accurate

## Verification run locally
```
python3 scripts/check-architecture.py →
ctest --test-dir build/unit          →
scripts/verify.sh 17                 →
```
