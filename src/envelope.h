/* SPDX-License-Identifier: PostgreSQL */
/*
 * envelope.h — the envelope layout and the types the core and the glue share.
 *
 * Depends on the C standard library only: no PostgreSQL header and no OpenSSL header
 * (.agents/rules/architecture.md §1), so the byte format can be read and tested on its own.
 *
 *   version(1) || nonce(12) || ciphertext(n) || tag(16)
 */
#ifndef PG_GCM_ENVELOPE_H
#define PG_GCM_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>

#define GCM_VERSION_LEN 1
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16
#define GCM_ENVELOPE_OVERHEAD (GCM_VERSION_LEN + GCM_NONCE_LEN + GCM_TAG_LEN)

/* The version byte names the suite and the variant (AGENTS.md §2). */
#define GCM_V_LEGACY_CBC 0x01		/* reserved; never produced, never opened (spec 1.2) */
#define GCM_V_AES256_RANDOM 0x02
#define GCM_V_AES256_DET 0x03
#define GCM_V_AES128_RANDOM 0x04
#define GCM_V_AES128_DET 0x05
#define GCM_V_AES192_RANDOM 0x06
#define GCM_V_AES192_DET 0x07

#define GCM_KEY_LEN_AES128 16
#define GCM_KEY_LEN_AES192 24
#define GCM_KEY_LEN_AES256 32

/*
 * Nothing declared here is part of the library's dynamic interface. PGXS hides symbols by
 * default from PostgreSQL 16; on 15 it does not, and an exported function can be interposed
 * by a library loaded earlier. scripts/build-in-docker.sh checks what the build exports.
 */
#pragma GCC visibility push(hidden)

/* Errors cross the core's boundary as values; the core never raises (design §5.2). */
enum gcm_error
{
	GCM_OK = 0,
	GCM_BAD_ENVELOPE,			/* shorter than 29 bytes, or a version byte that names no suite */
	GCM_BAD_TAG,				/* authentication failed; the output was cleansed */
	GCM_BAD_KEY_LEN,			/* the key length names no suite, or not the envelope's */
	GCM_BAD_LENGTH,				/* a caller's buffer or length does not fit the operation */
	GCM_OPENSSL_FAILURE			/* a fetch, an allocation or an EVP call failed */
};

/* Pointers into the caller's envelope; nothing is copied. */
struct gcm_envelope_view
{
	uint8_t		version;
	const uint8_t *nonce;		/* GCM_NONCE_LEN bytes */
	const uint8_t *ciphertext;
	size_t		ciphertext_len;
	const uint8_t *tag;			/* GCM_TAG_LEN bytes */
};

/* The key length a version byte requires, or 0 for a byte that names no suite (0x01 included). */
size_t		gcm_version_key_len(uint8_t version);

/* The version byte for a key length and a variant, or 0 when the key length names no suite. */
uint8_t		gcm_version_for(size_t key_len, int deterministic);

/* Split an envelope into its fields. GCM_BAD_ENVELOPE if it is too short or the version is unknown. */
enum gcm_error gcm_envelope_parse(const uint8_t *env, size_t env_len,
								  struct gcm_envelope_view *view);

/* Write the version byte and the nonce; the ciphertext and the tag are written by the caller. */
void		gcm_envelope_write_header(uint8_t *env, uint8_t version, const uint8_t *nonce);

#pragma GCC visibility pop

#endif							/* PG_GCM_ENVELOPE_H */
