/* SPDX-License-Identifier: PostgreSQL */
/*
 * gcm.h — the AES-GCM construction over OpenSSL's EVP interface.
 *
 * No PostgreSQL header, no palloc, no ereport: every function returns an enum gcm_error and
 * releases every OpenSSL object before it returns, so the glue can raise afterwards
 * (design §5.2). Phase S implements AES-256 with no AAD (design §4, step 2).
 */
#ifndef PG_GCM_GCM_H
#define PG_GCM_GCM_H

#include "envelope.h"

/*
 * Fetch the algorithm handles by name, once per process. Never raises; a failure is returned,
 * remembered, and reported again by every later call (design §5.8). Safe to call repeatedly.
 */
enum gcm_error gcm_init(void);

/* Whether gcm_init fetched every handle. */
int			gcm_ready(void);

/* Whether a key of this length selects a suite this build implements. */
int			gcm_key_len_supported(size_t key_len);

/*
 * Seal plaintext into out, which must be exactly plaintext_len + GCM_ENVELOPE_OVERHEAD bytes.
 * The nonce is random (RAND_bytes) or, when deterministic is non-zero, derived (nonce.h).
 */
enum gcm_error gcm_seal(const uint8_t *key, size_t key_len,
						const uint8_t *plaintext, size_t plaintext_len,
						int deterministic,
						uint8_t *out, size_t out_len);

/*
 * Open an envelope into out, which must hold at least env_len - GCM_ENVELOPE_OVERHEAD bytes
 * and may not be NULL, even for an envelope whose plaintext is empty. On every failure all
 * out_cap bytes of out are cleansed and *plaintext_len is 0: no unauthenticated plaintext is
 * ever returned.
 */
enum gcm_error gcm_open(const uint8_t *key, size_t key_len,
						const uint8_t *env, size_t env_len,
						uint8_t *out, size_t out_cap, size_t *plaintext_len);

/* OPENSSL_cleanse, for the glue: it holds secret copies but includes no OpenSSL header. */
void		gcm_cleanse(void *ptr, size_t len);

/*
 * Test seam (.agents/rules/architecture.md §6): seal with a caller-supplied nonce, for
 * known-answer vectors. Never declared in the extension's SQL script and never called by the glue.
 */
enum gcm_error gcm_seal_with_nonce(const uint8_t *key, size_t key_len,
								   const uint8_t nonce[GCM_NONCE_LEN],
								   uint8_t version,
								   const uint8_t *plaintext, size_t plaintext_len,
								   uint8_t *out, size_t out_len);

#endif							/* PG_GCM_GCM_H */
