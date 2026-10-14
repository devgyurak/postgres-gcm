/* SPDX-License-Identifier: PostgreSQL */
/*
 * nonce.h — the deterministic variant's synthetic nonce (spec 1.8).
 *
 *   nonce_key = HMAC-SHA256(key, GCM_DET_NONCE_LABEL)
 *   nonce     = HMAC-SHA256(nonce_key, be64(len(A)) || A || plaintext)[0:12]
 *
 * A is the associated data GCM is given, version || aad, and the plaintext is the UTF-8 bytes
 * that are sealed. The nonce is a function of exactly what GCM then processes, so one key may
 * be used with any number of AAD values (design §8, O16).
 * No PostgreSQL header (.agents/rules/architecture.md §1).
 */
#ifndef PG_GCM_NONCE_H
#define PG_GCM_NONCE_H

#include "envelope.h"

#include <openssl/evp.h>
#include <openssl/opensslv.h>

/* EVP_CIPHER_fetch, EVP_*Init_ex2 and EVP_MAC do not exist before 3.0 (design §0). */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "pg_gcm needs OpenSSL 3.0 or later"
#endif

/* Domain separation: the encryption key is never the key of the HMAC over the plaintext. */
#define GCM_DET_NONCE_LABEL "pg_gcm/v1/det-nonce"

/* Not part of the library's dynamic interface: see envelope.h. */
#pragma GCC visibility push(hidden)

enum gcm_error gcm_nonce_derive(EVP_MAC *hmac,
								const uint8_t *key, size_t key_len,
								uint8_t version,
								const uint8_t *aad, size_t aad_len,
								const uint8_t *plaintext, size_t plaintext_len,
								uint8_t nonce[GCM_NONCE_LEN]);

#pragma GCC visibility pop

#endif							/* PG_GCM_NONCE_H */
