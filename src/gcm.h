/* SPDX-License-Identifier: PostgreSQL */
/*
 * gcm.h — the envelope construction of spec/envelope.md over OpenSSL's EVP interface.
 *
 * No PostgreSQL header, no palloc, no ereport: every function returns an enum gcm_error and
 * releases every OpenSSL object before it returns, so the glue can raise afterwards
 * (design §5.2). The key length selects the suite: 32, 24 or 16 bytes.
 */
#ifndef PG_GCM_GCM_H
#define PG_GCM_GCM_H

#include "envelope.h"

/*
 * Fetch the algorithm handles by name, once per process. Never raises; a failure is returned,
 * remembered, and reported again by every later call (design §5.8). Safe to call repeatedly.
 */
enum gcm_error gcm_init(void);

/* Whether gcm_init fetched every handle. Without all of them the core does no cryptography. */
int			gcm_ready(void);

/* Whether a key of this length names a suite: 16, 24 or 32. */
int			gcm_key_len_supported(size_t key_len);

/*
 * Seal plaintext into out, which must be exactly plaintext_len + GCM_ENVELOPE_OVERHEAD bytes
 * (spec 1.6). aad may be NULL when aad_len is 0; absent and empty are the same. The nonce is
 * random (RAND_bytes) or, when deterministic is non-zero, derived (nonce.h).
 */
enum gcm_error gcm_seal(const uint8_t *key, size_t key_len,
						const uint8_t *aad, size_t aad_len,
						const uint8_t *plaintext, size_t plaintext_len,
						int deterministic,
						uint8_t *out, size_t out_len);

/*
 * Open an envelope into out (spec 1.7, checks in that order). out must hold at least
 * env_len - GCM_ENVELOPE_OVERHEAD bytes and may not be NULL, even for an envelope whose
 * plaintext is empty. On every failure all out_cap bytes of out are cleansed and
 * *plaintext_len is 0: no unauthenticated plaintext is ever returned.
 */
enum gcm_error gcm_open(const uint8_t *key, size_t key_len,
						const uint8_t *aad, size_t aad_len,
						const uint8_t *env, size_t env_len,
						uint8_t *out, size_t out_cap, size_t *plaintext_len);

/* OPENSSL_cleanse, for the glue: it holds secret copies but includes no OpenSSL header. */
void		gcm_cleanse(void *ptr, size_t len);

/*
 * Test seams (.agents/rules/architecture.md §6). Never declared in the extension's SQL script
 * and never called by the glue.
 *
 * gcm_seal_with_nonce seals with a caller-supplied nonce, to reproduce an envelope vector.
 * gcm_aead_seal_raw is the bare primitive with the whole associated data given by the caller,
 * for NIST's known answers, which are not envelopes: ciphertext is plaintext_len bytes.
 */
enum gcm_error gcm_seal_with_nonce(const uint8_t *key, size_t key_len,
								   const uint8_t nonce[GCM_NONCE_LEN],
								   uint8_t version,
								   const uint8_t *aad, size_t aad_len,
								   const uint8_t *plaintext, size_t plaintext_len,
								   uint8_t *out, size_t out_len);
enum gcm_error gcm_aead_seal_raw(const uint8_t *key, size_t key_len,
								 const uint8_t nonce[GCM_NONCE_LEN],
								 const uint8_t *associated, size_t associated_len,
								 const uint8_t *plaintext, size_t plaintext_len,
								 uint8_t *ciphertext, uint8_t tag[GCM_TAG_LEN]);

#endif							/* PG_GCM_GCM_H */
