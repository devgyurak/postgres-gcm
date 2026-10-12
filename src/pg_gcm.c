/* SPDX-License-Identifier: PostgreSQL */
/*
 * pg_gcm.c — module magic, _PG_init, the GUC, and the glue's shared helpers.
 */
#include "postgres.h"

#include "fmgr.h"
#include "utils/guc.h"
#if PG_VERSION_NUM >= 160000
#include "varatt.h"
#endif

#include "gcm.h"
#include "pg_gcm.h"

PG_MODULE_MAGIC;

bool		pg_gcm_strict = true;

void		_PG_init(void);

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

	MarkGUCPrefixReserved("pg_gcm");
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
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("key must be %d bytes, got %zu",
							GCM_KEY_LEN_AES256, key_len)));
			break;
		case GCM_BAD_ENVELOPE:
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_BINARY_REPRESENTATION),
					 errmsg("malformed or unsupported envelope (%zu bytes)",
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
