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
3. `EVP_EncryptInit_ex2(ctx, cipher, key, nonce, NULL)`, then check
   `EVP_CIPHER_CTX_get_iv_length(ctx) == 12`. **No `ivlen` param**: 12 is AES-GCM's default IV
   length, and before OpenSSL 3.0.12 a length passed in that call was applied after the IV had been
   copied (CVE-2023-5363; design §8). AAD through `EVP_EncryptUpdate(ctx, NULL, &n, aad, aad_len)`
   when present; data; `EVP_EncryptFinal_ex`; `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)`.
4. Write `version || nonce || ct || tag` into the caller's buffer, whose size the caller computed.

## Open
1. Parse the envelope (`envelope.c`): minimum length 29, known version, suite from the version byte,
   key length must match the suite (else `GCM_BAD_KEY_LEN`). Version `0x01` (legacy CBC: minimum 33,
   `0x01 || iv(16) || ciphertext`, no tag, no AAD) is **not implemented in 0.1** — design §8 O6,
   settled in Phase S. The core carries no CBC path and `0x01` is `GCM_BAD_ENVELOPE`, an
   allocated-but-unimplemented version; a v1 path is a design amendment first. The obstacle is
   security policy, not compatibility: v1 is unauthenticated, strict cannot see tampering, and its
   plaintext must already be UTF-8 (design §2.2).
2. Init with the nonce; AAD; data into the caller's buffer;
   `EVP_CTRL_AEAD_SET_TAG` **before** `EVP_DecryptFinal_ex`.
3. Final returns 0 → `OPENSSL_cleanse(out, len)` and `GCM_BAD_TAG`. A tag mismatch pushes nothing
   onto OpenSSL's error queue, and neither do a missing tag, key or IV on that path, so the queue
   cannot tell them apart: the code guarantees those three by construction (design §8).

## Deterministic nonce
`nonce_key = HMAC-SHA256(key, "pg_gcm/v1/det-nonce")`; `nonce = HMAC-SHA256(nonce_key, plaintext)[:12]`
through `EVP_MAC`: one `EVP_MAC_CTX_new` per call, `OSSL_MAC_PARAM_DIGEST = "SHA256"` in the first
`EVP_MAC_init`, and `NULL` params in the second, which re-keys the same context. **Do not** prepare a
keyless context once and `EVP_MAC_CTX_dup` it per call: that fails on OpenSSL 3.0.0 and drops a
digest reference each time (design §8 O15). Cleanse `nonce_key` and the full MAC output.

## OpenSSL floor
OpenSSL 3.0 or later, the one the server links (design §0). `EVP_CIPHER_fetch`, `EVP_EncryptInit_ex2`
and `EVP_MAC` do not exist in 1.1.1; there is no legacy-API fallback, and `nonce.h` refuses to compile
against anything older. Run a change on the 3.0 image too (`17-bookworm` in `docker/versions.json`).

## Handles and the error queue
The fetched `EVP_CIPHER` and `EVP_MAC` handles are static in `gcm.c`, fetched by `gcm_init()`, which
`_PG_init` calls and the unit suite calls from `main`. Seal and open both refuse to work unless every
handle is there (`gcm_ready()`). A failing core path ends with
`ERR_clear_error()`, so no entry of ours stays queued in the backend.

## After any change
- `ctest --test-dir build/unit` (every vector, every suite) and `python scripts/check-vectors.py`
  (from Phase 1).
- Run the `crypto-reviewer` subagent and attach its report to the PR.
