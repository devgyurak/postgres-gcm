---
name: gcm-crypto
description: Writing or changing the crypto core — EVP AES-GCM seal and open for the three suites, the HMAC-SHA256 deterministic nonce, envelope encoding and parsing, secret cleansing and error codes, in C11. Use it for any change to src/gcm.c, src/envelope.c or src/nonce.c, then run the crypto-reviewer subagent.
---

# gcm-crypto

Rules: `crypto-safety.md` (always), `architecture.md`. Spec: `spec/envelope.md`.

## Implement the spec, do not redesign
The construction is the spec's, byte for byte. The core is C11 with no RAII — use one cleanup label per
function — allocates with `OPENSSL_malloc`/`OPENSSL_clear_free`, and includes no server header.
Anything that changes a byte on the wire is a design amendment first.

## Seal
1. Pick the cached `EVP_CIPHER` by key length (32/24/16); the version byte follows from suite and
   variant.
2. Nonce: `RAND_bytes(nonce, 12) == 1` (random) or the HMAC construction (deterministic).
3. `EVP_EncryptInit_ex2(ctx, cipher, key, nonce, params)` with the IV length param 12; AAD through
   `EVP_EncryptUpdate(ctx, NULL, &n, aad, aad_len)` when present; data; `EVP_EncryptFinal_ex`;
   `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)`.
4. Write `version || nonce || ct || tag` into the caller's buffer, whose size the caller computed.

## Open
1. Parse the envelope (`envelope.c`): minimum length 29, known version, suite from the version byte,
   key length must match the suite (else `GCM_BAD_KEY_LEN`). Version `0x01` (legacy CBC: minimum 33,
   `0x01 || iv(16) || ciphertext`, no tag, no AAD) is **undecided** — design §8 O6. Until it is
   settled the core carries no CBC path and `0x01` is `GCM_BAD_ENVELOPE`, which the spec allows for an
   allocated-but-unimplemented version; do not write a v1 path ahead of that decision. The
   decision is about security policy as well as compatibility: v1 is unauthenticated, strict cannot
   see tampering, and its plaintext must already be UTF-8 (design §2.2).
2. Init with the nonce; AAD; data into the caller's buffer;
   `EVP_CTRL_AEAD_SET_TAG` **before** `EVP_DecryptFinal_ex`.
3. Final returns 0 → `OPENSSL_cleanse(out, len)` and `GCM_BAD_TAG`.

## Deterministic nonce
`nonce_key = HMAC-SHA256(key, "pg_gcm/v1/det-nonce")`; `nonce = HMAC-SHA256(nonce_key, plaintext)[:12]`
through `EVP_MAC` with `OSSL_MAC_PARAM_DIGEST = "SHA256"`. Cleanse `nonce_key` and the full MAC output.

## OpenSSL floor
OpenSSL 3.0 or later, the one the server links (design §0). `EVP_CIPHER_fetch`, `EVP_EncryptInit_ex2`
and `EVP_MAC` do not exist in 1.1.1; there is no legacy-API fallback.

## After any change
- `ctest --test-dir build/unit` (every vector, every suite) and `python scripts/check-vectors.py`.
- Run the `crypto-reviewer` subagent and attach its report to the PR.
