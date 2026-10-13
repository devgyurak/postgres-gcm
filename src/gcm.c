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
 * process and are never released (design §5.8). One cipher per key length.
 */
#define GCM_SUITES 3
static const char *const cipher_names[GCM_SUITES] = {"AES-128-GCM", "AES-192-GCM", "AES-256-GCM"};
static const size_t cipher_key_lens[GCM_SUITES] = {
	GCM_KEY_LEN_AES128, GCM_KEY_LEN_AES192, GCM_KEY_LEN_AES256
};
static EVP_CIPHER *ciphers[GCM_SUITES] = {NULL, NULL, NULL};
static EVP_MAC *mac_hmac = NULL;

enum gcm_error
gcm_init(void)
{
	int			i;

	/* Fetch by name, never through a legacy per-cipher symbol (crypto-safety.md). */
	for (i = 0; i < GCM_SUITES; i++)
	{
		if (ciphers[i] == NULL)
			ciphers[i] = EVP_CIPHER_fetch(NULL, cipher_names[i], NULL);
	}
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
	int			i;

	for (i = 0; i < GCM_SUITES; i++)
	{
		if (ciphers[i] == NULL)
			return 0;
	}
	return mac_hmac != NULL;
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

/* The fetched cipher for a key length, or NULL. */
static const EVP_CIPHER *
cipher_for(size_t key_len)
{
	int			i;

	for (i = 0; i < GCM_SUITES; i++)
	{
		if (cipher_key_lens[i] == key_len)
			return ciphers[i];
	}
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

/*
 * AES-GCM over (a1 || a2) as associated data. The envelope passes its version byte as a1
 * and the caller's AAD as a2 (spec 1.5); the raw seam passes everything as a1. Lengths have
 * been checked against INT_MAX by the callers.
 */
static enum gcm_error
aead_seal(const EVP_CIPHER *cipher, const uint8_t *key, const uint8_t *nonce,
		  const uint8_t *a1, size_t a1_len, const uint8_t *a2, size_t a2_len,
		  const uint8_t *plaintext, size_t plaintext_len,
		  uint8_t *ciphertext, uint8_t *tag)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int			n = 0;
	int			fin = 0;
	enum gcm_error rc = GCM_OPENSSL_FAILURE;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		goto done;
	if (EVP_EncryptInit_ex2(ctx, cipher, key, nonce, NULL) != 1)
		goto done;
	if (!nonce_len_is_default(ctx))
		goto done;
	if (a1_len > 0 && EVP_EncryptUpdate(ctx, NULL, &n, a1, (int) a1_len) != 1)
		goto done;
	if (a2_len > 0 && EVP_EncryptUpdate(ctx, NULL, &n, a2, (int) a2_len) != 1)
		goto done;
	n = 0;
	if (plaintext_len > 0 &&
		EVP_EncryptUpdate(ctx, ciphertext, &n, plaintext, (int) plaintext_len) != 1)
		goto done;
	if (EVP_EncryptFinal_ex(ctx, ciphertext + n, &fin) != 1)
		goto done;
	if ((size_t) n + (size_t) fin != plaintext_len)
		goto done;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_LEN, tag) != 1)
		goto done;
	rc = GCM_OK;

done:
	EVP_CIPHER_CTX_free(ctx);
	return rc;
}

static enum gcm_error
aead_open(const EVP_CIPHER *cipher, const uint8_t *key, const uint8_t *nonce,
		  const uint8_t *a1, size_t a1_len, const uint8_t *a2, size_t a2_len,
		  const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *tag_in,
		  uint8_t *out)
{
	EVP_CIPHER_CTX *ctx = NULL;
	uint8_t		tag[GCM_TAG_LEN];
	int			n = 0;
	int			fin = 0;
	enum gcm_error rc = GCM_OPENSSL_FAILURE;

	/* EVP_CTRL_AEAD_SET_TAG takes a non-const pointer; give it a copy, not a cast. */
	memcpy(tag, tag_in, GCM_TAG_LEN);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		goto done;
	if (EVP_DecryptInit_ex2(ctx, cipher, key, nonce, NULL) != 1)
		goto done;
	if (!nonce_len_is_default(ctx))
		goto done;
	if (a1_len > 0 && EVP_DecryptUpdate(ctx, NULL, &n, a1, (int) a1_len) != 1)
		goto done;
	if (a2_len > 0 && EVP_DecryptUpdate(ctx, NULL, &n, a2, (int) a2_len) != 1)
		goto done;
	n = 0;
	if (ciphertext_len > 0 &&
		EVP_DecryptUpdate(ctx, out, &n, ciphertext, (int) ciphertext_len) != 1)
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
	if ((size_t) n + (size_t) fin != ciphertext_len)
		goto done;
	rc = GCM_OK;

done:
	EVP_CIPHER_CTX_free(ctx);
	return rc;
}

enum gcm_error
gcm_aead_seal_raw(const uint8_t *key, size_t key_len,
				  const uint8_t nonce[GCM_NONCE_LEN],
				  const uint8_t *associated, size_t associated_len,
				  const uint8_t *plaintext, size_t plaintext_len,
				  uint8_t *ciphertext, uint8_t tag[GCM_TAG_LEN])
{
	const EVP_CIPHER *cipher;
	enum gcm_error rc;

	if (!gcm_key_len_supported(key_len))
		return GCM_BAD_KEY_LEN;
	if (associated_len > (size_t) INT_MAX || plaintext_len > (size_t) INT_MAX)
		return GCM_BAD_LENGTH;
	cipher = cipher_for(key_len);
	if (!gcm_ready() || cipher == NULL)
		return GCM_OPENSSL_FAILURE;

	rc = aead_seal(cipher, key, nonce, associated, associated_len, NULL, 0,
				   plaintext, plaintext_len, ciphertext, tag);
	if (rc != GCM_OK)
		ERR_clear_error();
	return rc;
}

enum gcm_error
gcm_seal_with_nonce(const uint8_t *key, size_t key_len,
					const uint8_t nonce[GCM_NONCE_LEN],
					uint8_t version,
					const uint8_t *aad, size_t aad_len,
					const uint8_t *plaintext, size_t plaintext_len,
					uint8_t *out, size_t out_len)
{
	const EVP_CIPHER *cipher;
	uint8_t    *ciphertext;
	enum gcm_error rc;

	if (gcm_version_key_len(version) == 0 || key_len != gcm_version_key_len(version))
		return GCM_BAD_KEY_LEN;
	if (out == NULL || aad_len > (size_t) INT_MAX ||
		plaintext_len > (size_t) INT_MAX - GCM_ENVELOPE_OVERHEAD ||
		out_len != plaintext_len + GCM_ENVELOPE_OVERHEAD)
		return GCM_BAD_LENGTH;
	cipher = cipher_for(key_len);
	if (!gcm_ready() || cipher == NULL)
		return GCM_OPENSSL_FAILURE;
	ciphertext = out + GCM_VERSION_LEN + GCM_NONCE_LEN;

	/* spec 1.5: the associated data is version || aad, so the version byte is authenticated. */
	rc = aead_seal(cipher, key, nonce, &version, GCM_VERSION_LEN, aad, aad_len,
				   plaintext, plaintext_len, ciphertext, ciphertext + plaintext_len);
	if (rc == GCM_OK)
		gcm_envelope_write_header(out, version, nonce);
	else
	{
		OPENSSL_cleanse(out, out_len);
		ERR_clear_error();
	}
	return rc;
}

enum gcm_error
gcm_seal(const uint8_t *key, size_t key_len,
		 const uint8_t *aad, size_t aad_len,
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
		rc = gcm_nonce_derive(mac_hmac, key, key_len, version, aad, aad_len,
							  plaintext, plaintext_len, nonce);
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

	rc = gcm_seal_with_nonce(key, key_len, nonce, version, aad, aad_len,
							 plaintext, plaintext_len, out, out_len);
	OPENSSL_cleanse(nonce, sizeof(nonce));
	return rc;
}

enum gcm_error
gcm_open(const uint8_t *key, size_t key_len,
		 const uint8_t *aad, size_t aad_len,
		 const uint8_t *env, size_t env_len,
		 uint8_t *out, size_t out_cap, size_t *plaintext_len)
{
	struct gcm_envelope_view view;
	const EVP_CIPHER *cipher;
	int			openssl_used = 0;
	enum gcm_error rc;

	if (plaintext_len == NULL)
	{
		rc = GCM_BAD_LENGTH;
		goto done;
	}
	*plaintext_len = 0;

	/* The order of spec 1.7: a key that names no suite, the envelope, the suite's key, the tag. */
	rc = GCM_BAD_KEY_LEN;
	if (!gcm_key_len_supported(key_len))
		goto done;
	rc = gcm_envelope_parse(env, env_len, &view);
	if (rc != GCM_OK)
		goto done;
	rc = GCM_BAD_KEY_LEN;
	if (key_len != gcm_version_key_len(view.version))
		goto done;
	rc = GCM_BAD_LENGTH;
	if (out == NULL || aad_len > (size_t) INT_MAX ||
		view.ciphertext_len > (size_t) INT_MAX || out_cap < view.ciphertext_len)
		goto done;
	/* All or nothing, as in gcm_seal: without every handle the core does no cryptography. */
	rc = GCM_OPENSSL_FAILURE;
	cipher = cipher_for(key_len);
	if (!gcm_ready() || cipher == NULL)
		goto done;

	openssl_used = 1;
	rc = aead_open(cipher, key, view.nonce, &view.version, GCM_VERSION_LEN, aad, aad_len,
				   view.ciphertext, view.ciphertext_len, view.tag, out);
	if (rc == GCM_OK)
		*plaintext_len = view.ciphertext_len;

done:
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
