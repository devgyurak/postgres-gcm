/* SPDX-License-Identifier: PostgreSQL */
/*
 * pg_gcm.c — module magic, _PG_init, the GUC, and the glue's shared helpers.
 */
#include "postgres.h"

#include "fmgr.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_namespace.h"
#include "mb/pg_wchar.h"
#include "utils/guc.h"
#if PG_VERSION_NUM >= 160000
#include "varatt.h"
#endif

#include "gcm.h"
#include "pg_gcm.h"

PG_MODULE_MAGIC;

bool		pg_gcm_strict = true;
int			pg_gcm_min_key_bytes = GCM_KEY_LEN_AES256;

void		_PG_init(void);

/* pg_gcm.min_key_bytes is a key length: only the three that name a suite are values. */
static bool
check_min_key_bytes(int *newval, void **extra, GucSource source)
{
	(void) extra;
	(void) source;
	if (!gcm_key_len_supported((size_t) *newval))
	{
		GUC_check_errdetail("pg_gcm.min_key_bytes must be 16, 24 or 32.");
		return false;
	}
	return true;
}

/*
 * design §5.8: fetch the OpenSSL handles before registering anything, and never raise.
 * An ERROR here stops the postmaster under shared_preload_libraries, and after
 * DefineCustom*Variable it would leave a lazily loaded backend failing with "attempt to
 * redefine parameter". A failed fetch is remembered by the core; every call then reports it.
 */
void
_PG_init(void)
{
	(void) gcm_init();

	DefineCustomBoolVariable("pg_gcm.strict",
							 "Raises an error when gcm_decrypt cannot authenticate an envelope.",
							 "When off, gcm_decrypt returns NULL for a tag mismatch instead. "
							 "A malformed envelope and ill-formed text are errors either way.",
							 &pg_gcm_strict,
							 true,
							 PGC_USERSET,
							 0,
							 NULL, NULL, NULL);

	DefineCustomIntVariable("pg_gcm.min_key_bytes",
							"The shortest key gcm_encrypt and gcm_encrypt_det accept.",
							"The key length selects the cipher, so a key cut short would "
							"silently select a weaker one. gcm_decrypt does not consult this.",
							&pg_gcm_min_key_bytes,
							GCM_KEY_LEN_AES256,
							GCM_KEY_LEN_AES128,
							GCM_KEY_LEN_AES256,
							PGC_SUSET,
							0,
							check_min_key_bytes, NULL, NULL);

	MarkGUCPrefixReserved("pg_gcm");
}

/*
 * The lookup is in pg_catalog alone, not along search_path: a default conversion created in
 * another schema must not be handed the plaintext (design §8, O14).
 */
Oid
pg_gcm_conversion_proc(bool to_utf8)
{
	int			db_encoding = GetDatabaseEncoding();
	Oid			proc;

	if (db_encoding == PG_UTF8 || db_encoding == PG_SQL_ASCII)
		return InvalidOid;

	proc = FindDefaultConversion(PG_CATALOG_NAMESPACE,
								 to_utf8 ? db_encoding : PG_UTF8,
								 to_utf8 ? PG_UTF8 : db_encoding);
	if (!OidIsValid(proc))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_FUNCTION),
				 errmsg("default conversion function for encoding \"%s\" to \"%s\" does not exist in pg_catalog",
						pg_encoding_to_char(to_utf8 ? db_encoding : PG_UTF8),
						pg_encoding_to_char(to_utf8 ? PG_UTF8 : db_encoding))));
	return proc;
}

void
pg_gcm_raise_key_below_minimum(Size key_len)
{
	ereport(ERROR,
			(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			 errmsg("a %zu-byte key is shorter than pg_gcm.min_key_bytes (%d)",
					key_len, pg_gcm_min_key_bytes)));
}

void
pg_gcm_release_copy(struct varlena *value, Datum arg, bool secret)
{
	Size		size;

	/* The same test PG_FREE_IF_COPY uses: only a pointer that differs is our copy. */
	if (value == NULL || (Pointer) value == DatumGetPointer(arg))
		return;
	if (secret)
	{
		size = VARSIZE_ANY(value);
		gcm_cleanse(value, size);
	}
	pfree(value);
}

void
pg_gcm_raise(enum gcm_error rc, Size key_len, Size envelope_len)
{
	switch (rc)
	{
		case GCM_OK:
			return;
		case GCM_BAD_KEY_LEN:
			/* Either no suite has that key length, or the envelope's suite has another. */
			if (!gcm_key_len_supported(key_len))
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("key must be 16, 24 or 32 bytes, got %zu", key_len)));
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("a %zu-byte key does not fit the cipher this envelope was sealed with",
							key_len)));
			break;
		case GCM_BAD_ENVELOPE:
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_BINARY_REPRESENTATION),
					 errmsg("malformed envelope (%zu bytes)",
							envelope_len)));
			break;
		case GCM_BAD_TAG:
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("authentication failed: the envelope does not match its tag")));
			break;
		case GCM_BAD_LENGTH:
			ereport(ERROR,
					(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
					 errmsg("value is too long")));
			break;
		case GCM_OPENSSL_FAILURE:
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("OpenSSL could not complete the operation")));
			break;
	}
}
