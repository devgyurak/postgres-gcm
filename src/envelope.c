/* SPDX-License-Identifier: PostgreSQL */
/*
 * envelope.c — envelope encoding and parsing. C standard library only.
 */
#include "envelope.h"

#include <string.h>

size_t
gcm_version_key_len(uint8_t version)
{
	switch (version)
	{
		case GCM_V_AES256_RANDOM:
		case GCM_V_AES256_DET:
			return GCM_KEY_LEN_AES256;
		case GCM_V_AES128_RANDOM:
		case GCM_V_AES128_DET:
			return GCM_KEY_LEN_AES128;
		case GCM_V_AES192_RANDOM:
		case GCM_V_AES192_DET:
			return GCM_KEY_LEN_AES192;
		default:
			return 0;
	}
}

uint8_t
gcm_version_for(size_t key_len, int deterministic)
{
	switch (key_len)
	{
		case GCM_KEY_LEN_AES256:
			return deterministic ? GCM_V_AES256_DET : GCM_V_AES256_RANDOM;
		case GCM_KEY_LEN_AES128:
			return deterministic ? GCM_V_AES128_DET : GCM_V_AES128_RANDOM;
		case GCM_KEY_LEN_AES192:
			return deterministic ? GCM_V_AES192_DET : GCM_V_AES192_RANDOM;
		default:
			return 0;
	}
}

enum gcm_error
gcm_envelope_parse(const uint8_t *env, size_t env_len, struct gcm_envelope_view *view)
{
	/* The length is checked before any subtraction: no unsigned underflow on a short input. */
	if (env == NULL || view == NULL || env_len < GCM_ENVELOPE_OVERHEAD)
		return GCM_BAD_ENVELOPE;
	if (gcm_version_key_len(env[0]) == 0)
		return GCM_BAD_ENVELOPE;

	view->version = env[0];
	view->nonce = env + GCM_VERSION_LEN;
	view->ciphertext = env + GCM_VERSION_LEN + GCM_NONCE_LEN;
	view->ciphertext_len = env_len - GCM_ENVELOPE_OVERHEAD;
	view->tag = env + env_len - GCM_TAG_LEN;
	return GCM_OK;
}

void
gcm_envelope_write_header(uint8_t *env, uint8_t version, const uint8_t *nonce)
{
	env[0] = version;
	memcpy(env + GCM_VERSION_LEN, nonce, GCM_NONCE_LEN);
}
