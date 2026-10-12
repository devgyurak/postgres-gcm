/* SPDX-License-Identifier: PostgreSQL */
/*
 * nonce.c — HMAC-SHA256 nonce derivation through EVP_MAC. No PostgreSQL header.
 */
#include "nonce.h"

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

#define GCM_HMAC_SHA256_LEN 32

/*
 * One HMAC-SHA256 over one message. EVP_MAC_init keys (or re-keys) ctx; params selects the
 * digest on the first use of a context and is NULL afterwards, when the context has it.
 */
static int
hmac_sha256(EVP_MAC_CTX *ctx, const OSSL_PARAM *params,
			const uint8_t *key, size_t key_len,
			const uint8_t *msg, size_t msg_len,
			uint8_t out[GCM_HMAC_SHA256_LEN])
{
	size_t		out_len = 0;

	if (EVP_MAC_init(ctx, key, key_len, params) != 1)
		return 0;
	if (msg_len > 0 && EVP_MAC_update(ctx, msg, msg_len) != 1)
		return 0;
	if (EVP_MAC_final(ctx, out, &out_len, GCM_HMAC_SHA256_LEN) != 1)
		return 0;
	return out_len == GCM_HMAC_SHA256_LEN;
}

/*
 * A fresh context per call, with the digest named in its first EVP_MAC_init. A keyless
 * context prepared once and duplicated per call would save resolving the digest name, but
 * EVP_MAC_CTX_dup of a keyless HMAC context fails on OpenSSL 3.0.0 and drops a digest
 * reference each time it does (design §8, O15).
 */
enum gcm_error
gcm_nonce_derive(EVP_MAC *hmac,
				 const uint8_t *key, size_t key_len,
				 const uint8_t *plaintext, size_t plaintext_len,
				 uint8_t nonce[GCM_NONCE_LEN])
{
	static const char label[] = GCM_DET_NONCE_LABEL;
	char		digest[] = "SHA256";
	OSSL_PARAM	params[2];
	EVP_MAC_CTX *ctx = NULL;
	uint8_t		nonce_key[GCM_HMAC_SHA256_LEN];
	uint8_t		mac[GCM_HMAC_SHA256_LEN];
	enum gcm_error rc = GCM_OPENSSL_FAILURE;

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
	params[1] = OSSL_PARAM_construct_end();

	/* A key is always given: gcm_seal has checked its length, and HMAC is never left unkeyed. */
	if (hmac == NULL || key == NULL || key_len == 0)
		goto done;
	ctx = EVP_MAC_CTX_new(hmac);
	if (ctx == NULL)
		goto done;
	if (!hmac_sha256(ctx, params, key, key_len,
					 (const uint8_t *) label, sizeof(label) - 1, nonce_key))
		goto done;
	if (!hmac_sha256(ctx, NULL, nonce_key, sizeof(nonce_key), plaintext, plaintext_len, mac))
		goto done;

	memcpy(nonce, mac, GCM_NONCE_LEN);
	rc = GCM_OK;

done:
	EVP_MAC_CTX_free(ctx);
	OPENSSL_cleanse(nonce_key, sizeof(nonce_key));
	OPENSSL_cleanse(mac, sizeof(mac));
	return rc;
}
