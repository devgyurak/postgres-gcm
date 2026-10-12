/* SPDX-License-Identifier: PostgreSQL */
/*
 * gcm.c — AES-GCM seal and open through EVP. No PostgreSQL header.
 *
 * Every function that acquires an OpenSSL object has one exit label that frees it
 * (.agents/rules/stack-c.md). Nothing here can longjmp, so no context outlives its call.
 */
#include "gcm.h"
#include "nonce.h"

#include <limits.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/*
 * The fetched handles: the only state that outlives a call. They live for the life of the
 * process and are never released (design §5.8).
 */
static EVP_CIPHER *cipher_aes256_gcm = NULL;
static EVP_MAC *mac_hmac = NULL;

enum gcm_error
gcm_init(void)
{
	/* Fetch by name, never through a legacy per-cipher symbol (crypto-safety.md). */
	if (cipher_aes256_gcm == NULL)
		cipher_aes256_gcm = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
	if (mac_hmac == NULL)
		mac_hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (!gcm_ready())
	{
		ERR_clear_error();
		return GCM_OPENSSL_FAILURE;
	}
	return GCM_OK;
}

int
gcm_ready(void)
{
	return cipher_aes256_gcm != NULL && mac_hmac != NULL;
}

int
gcm_key_len_supported(size_t key_len)
{
	return gcm_version_for(key_len, 0) != 0;
}

void
gcm_cleanse(void *ptr, size_t len)
{
	OPENSSL_cleanse(ptr, len);
}

/* The cipher for a version byte. Phase S: AES-256 only. */
static const EVP_CIPHER *
cipher_for(uint8_t version)
{
	if (gcm_version_key_len(version) == GCM_KEY_LEN_AES256)
		return cipher_aes256_gcm;
	return NULL;
}

/*
 * The nonce length is fixed at 12, which is AES-GCM's default IV length in OpenSSL, so no
 * "ivlen" parameter is passed to EVP_*Init_ex2: before 3.0.12 that parameter was applied
 * after the IV had been copied (CVE-2023-5363). The default is checked instead of assumed.
 */
static int
nonce_len_is_default(const EVP_CIPHER_CTX *ctx)
{
	return EVP_CIPHER_CTX_get_iv_length(ctx) == GCM_NONCE_LEN;
}

enum gcm_error
gcm_seal_with_nonce(const uint8_t *key, size_t key_len,
					const uint8_t nonce[GCM_NONCE_LEN],
					uint8_t version,
					const uint8_t *plaintext, size_t plaintext_len,
					uint8_t *out, size_t out_len)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher;
	uint8_t    *ct = out + GCM_VERSION_LEN + GCM_NONCE_LEN;
	int			n = 0;
	int			fin = 0;
	enum gcm_error rc = GCM_OPENSSL_FAILURE;

	if (gcm_version_key_len(version) == 0 || key_len != gcm_version_key_len(version))
		return GCM_BAD_KEY_LEN;
	if (plaintext_len > (size_t) INT_MAX - GCM_ENVELOPE_OVERHEAD ||
		out_len != plaintext_len + GCM_ENVELOPE_OVERHEAD)
		return GCM_BAD_LENGTH;
	cipher = cipher_for(version);
	if (cipher == NULL)
		return GCM_OPENSSL_FAILURE;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		goto done;
	if (EVP_EncryptInit_ex2(ctx, cipher, key, nonce, NULL) != 1)
		goto done;
	if (!nonce_len_is_default(ctx))
		goto done;
	if (plaintext_len > 0 &&
		EVP_EncryptUpdate(ctx, ct, &n, plaintext, (int) plaintext_len) != 1)
		goto done;
	if (EVP_EncryptFinal_ex(ctx, ct + n, &fin) != 1)
		goto done;
	if ((size_t) n + (size_t) fin != plaintext_len)
		goto done;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_LEN, ct + plaintext_len) != 1)
		goto done;

	gcm_envelope_write_header(out, version, nonce);
	rc = GCM_OK;

done:
	EVP_CIPHER_CTX_free(ctx);
	if (rc != GCM_OK)
	{
		OPENSSL_cleanse(out, out_len);
		ERR_clear_error();
	}
	return rc;
}

enum gcm_error
gcm_seal(const uint8_t *key, size_t key_len,
		 const uint8_t *plaintext, size_t plaintext_len,
		 int deterministic,
		 uint8_t *out, size_t out_len)
{
	uint8_t		nonce[GCM_NONCE_LEN];
	uint8_t		version = gcm_version_for(key_len, deterministic);
	enum gcm_error rc;

	if (version == 0)
		return GCM_BAD_KEY_LEN;
	if (!gcm_ready())
		return GCM_OPENSSL_FAILURE;

	if (deterministic)
	{
		rc = gcm_nonce_derive(mac_hmac, key, key_len, plaintext, plaintext_len, nonce);
		if (rc != GCM_OK)
		{
			ERR_clear_error();
			return rc;
		}
	}
	else if (RAND_bytes(nonce, GCM_NONCE_LEN) != 1)
	{
		/* Any return other than 1 is a failure; there is no fallback source. */
		ERR_clear_error();
		return GCM_OPENSSL_FAILURE;
	}

	rc = gcm_seal_with_nonce(key, key_len, nonce, version, plaintext, plaintext_len, out, out_len);
	OPENSSL_cleanse(nonce, sizeof(nonce));
	return rc;
}

enum gcm_error
gcm_open(const uint8_t *key, size_t key_len,
		 const uint8_t *env, size_t env_len,
		 uint8_t *out, size_t out_cap, size_t *plaintext_len)
{
	struct gcm_envelope_view view;
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher;
	uint8_t		tag[GCM_TAG_LEN];
	int			n = 0;
	int			fin = 0;
	int			openssl_used = 0;
	enum gcm_error rc;

	if (plaintext_len == NULL)
	{
		rc = GCM_BAD_LENGTH;
		goto done;
	}
	*plaintext_len = 0;

	rc = gcm_envelope_parse(env, env_len, &view);
	if (rc != GCM_OK)
		goto done;
	rc = GCM_BAD_KEY_LEN;
	if (key_len != gcm_version_key_len(view.version))
		goto done;
	rc = GCM_BAD_LENGTH;
	if (out == NULL || view.ciphertext_len > (size_t) INT_MAX || out_cap < view.ciphertext_len)
		goto done;
	/* All or nothing, as in gcm_seal: without every handle the core does no cryptography. */
	rc = GCM_OPENSSL_FAILURE;
	cipher = cipher_for(view.version);
	if (!gcm_ready() || cipher == NULL)
		goto done;

	/* EVP_CTRL_AEAD_SET_TAG takes a non-const pointer; give it a copy, not a cast. */
	memcpy(tag, view.tag, GCM_TAG_LEN);

	openssl_used = 1;
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		goto done;
	if (EVP_DecryptInit_ex2(ctx, cipher, key, view.nonce, NULL) != 1)
		goto done;
	if (!nonce_len_is_default(ctx))
		goto done;
	if (view.ciphertext_len > 0 &&
		EVP_DecryptUpdate(ctx, out, &n, view.ciphertext, (int) view.ciphertext_len) != 1)
		goto done;
	/* The tag is set before Final; Final's return value is the tag check. */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_LEN, tag) != 1)
		goto done;

	/*
	 * A tag mismatch puts nothing on OpenSSL's error queue, and neither would a missing key,
	 * IV or tag here, so the queue cannot tell them apart. The three were set just above and
	 * each was checked, which leaves the mismatch as the only way Final returns 0.
	 */
	if (EVP_DecryptFinal_ex(ctx, out + n, &fin) != 1)
	{
		rc = GCM_BAD_TAG;
		goto done;
	}
	if ((size_t) n + (size_t) fin != view.ciphertext_len)
		goto done;

	*plaintext_len = view.ciphertext_len;
	rc = GCM_OK;

done:
	EVP_CIPHER_CTX_free(ctx);
	if (rc != GCM_OK)
	{
		/* Never hand back unauthenticated plaintext, not even in a buffer the caller owns. */
		if (out != NULL)
			OPENSSL_cleanse(out, out_cap);
		if (openssl_used)
			ERR_clear_error();
	}
	return rc;
}
