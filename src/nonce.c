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
 * A fresh context per call, with the digest named in its first EVP_MAC_init; the second
 * init re-keys it. A keyless context prepared once and duplicated per call would save
 * resolving the digest name, but EVP_MAC_CTX_dup of a keyless HMAC context fails on OpenSSL
 * 3.0.0 and drops a digest reference each time it does (design §8, O15).
 */
enum gcm_error
gcm_nonce_derive(EVP_MAC *hmac,
				 const uint8_t *key, size_t key_len,
				 uint8_t version,
				 const uint8_t *aad, size_t aad_len,
				 const uint8_t *plaintext, size_t plaintext_len,
				 uint8_t nonce[GCM_NONCE_LEN])
{
	static const char label[] = GCM_DET_NONCE_LABEL;
	char		digest[] = "SHA256";
	OSSL_PARAM	params[2];
	EVP_MAC_CTX *ctx = NULL;
	uint8_t		nonce_key[GCM_HMAC_SHA256_LEN];
	uint8_t		mac[GCM_HMAC_SHA256_LEN];
	uint8_t		a_len_be[8];
	uint64_t	a_len = (uint64_t) aad_len + 1; /* A = version || aad */
	size_t		out_len = 0;
	int			i;
	enum gcm_error rc = GCM_OPENSSL_FAILURE;

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
	params[1] = OSSL_PARAM_construct_end();
	for (i = 0; i < 8; i++)
		a_len_be[i] = (uint8_t) (a_len >> (56 - 8 * i));

	/* A key is always given: the caller has checked its length, and HMAC is never left unkeyed. */
	if (hmac == NULL || key == NULL || key_len == 0)
		goto done;
	ctx = EVP_MAC_CTX_new(hmac);
	if (ctx == NULL)
		goto done;

	/* nonce_key = HMAC(key, label) */
	if (EVP_MAC_init(ctx, key, key_len, params) != 1 ||
		EVP_MAC_update(ctx, (const uint8_t *) label, sizeof(label) - 1) != 1 ||
		EVP_MAC_final(ctx, nonce_key, &out_len, sizeof(nonce_key)) != 1 ||
		out_len != sizeof(nonce_key))
		goto done;

	/* nonce = HMAC(nonce_key, be64(len(A)) || version || aad || plaintext)[0:12] */
	if (EVP_MAC_init(ctx, nonce_key, sizeof(nonce_key), NULL) != 1 ||
		EVP_MAC_update(ctx, a_len_be, sizeof(a_len_be)) != 1 ||
		EVP_MAC_update(ctx, &version, 1) != 1 ||
		(aad_len > 0 && EVP_MAC_update(ctx, aad, aad_len) != 1) ||
		(plaintext_len > 0 && EVP_MAC_update(ctx, plaintext, plaintext_len) != 1) ||
		EVP_MAC_final(ctx, mac, &out_len, sizeof(mac)) != 1 ||
		out_len != sizeof(mac))
		goto done;

	memcpy(nonce, mac, GCM_NONCE_LEN);
	rc = GCM_OK;

done:
	EVP_MAC_CTX_free(ctx);
	OPENSSL_cleanse(nonce_key, sizeof(nonce_key));
	OPENSSL_cleanse(mac, sizeof(mac));
	return rc;
}
