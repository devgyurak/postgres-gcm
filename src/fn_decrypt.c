/* SPDX-License-Identifier: PostgreSQL */
/*
 * fn_decrypt.c — gcm_decrypt: arguments, the strict policy, UTF-8 verification and
 * conversion to the database encoding, error translation.
 *
 * STRICT, so no argument is NULL here. The opened bytes are verified as UTF-8 and converted
 * with the forms that report by return value, so that no server message ever carries a byte
 * of decrypted text (design §5.7).
 */
#include "postgres.h"

#include "fmgr.h"
#include "catalog/namespace.h"
#include "mb/pg_wchar.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#if PG_VERSION_NUM >= 160000
#include "varatt.h"
#endif

#include "gcm.h"
#include "pg_gcm.h"

PG_FUNCTION_INFO_V1(gcm_decrypt);

/* Why an authenticated plaintext could not become text; decided inside PG_TRY, raised after. */
enum open_failure
{
	OPEN_OK = 0,
	OPEN_BAD_KEY_LEN,
	OPEN_NOT_UTF8,
	OPEN_UNTRANSLATABLE,
	OPEN_TOO_LONG
};

/* gcm_decrypt(ciphertext bytea, key bytea) -> text in the database encoding. STABLE. */
Datum
gcm_decrypt(PG_FUNCTION_ARGS)
{
	int			db_encoding = GetDatabaseEncoding();
	bool		direct = (db_encoding == PG_UTF8 || db_encoding == PG_SQL_ASCII);
	Oid			from_utf8 = InvalidOid;
	bytea	   *volatile key = NULL;
	bytea	   *volatile envelope = NULL;
	char	   *volatile opened = NULL; /* the opened UTF-8 bytes: the result's data, or scratch */
	volatile Size opened_cap = 0;
	char	   *volatile converted = NULL;
	volatile Size converted_cap = 0;
	text	   *volatile result = NULL;
	volatile bool result_complete = false;
	volatile Size key_len = 0;
	volatile Size envelope_len = 0;
	volatile enum open_failure failure = OPEN_OK;
	volatile enum gcm_error rc = GCM_OK;

	/* Can raise, holds no secret: the handle check and the conversion lookup. */
	if (!gcm_ready())
		pg_gcm_raise(GCM_OPENSSL_FAILURE, 0, 0);
	if (!direct)
	{
		from_utf8 = FindDefaultConversionProc(PG_UTF8, db_encoding);
		if (!OidIsValid(from_utf8))
			ereport(ERROR,
					(errcode(ERRCODE_UNDEFINED_FUNCTION),
					 errmsg("default conversion function for encoding \"%s\" to \"%s\" does not exist",
							pg_encoding_to_char(PG_UTF8), GetDatabaseEncodingName())));
	}

	/*
	 * design §5.2: the key copy and the opened plaintext are ours to cleanse, on the error
	 * path too. No OpenSSL object is live in this block; the core cannot raise.
	 */
	PG_TRY();
	{
		Size		opened_len = 0;

		key = PG_GETARG_BYTEA_PP(1);
		key_len = VARSIZE_ANY_EXHDR(key);
		if (!gcm_key_len_supported(key_len))
			failure = OPEN_BAD_KEY_LEN;

		if (failure == OPEN_OK)
		{
			envelope = PG_GETARG_BYTEA_PP(0);
			envelope_len = VARSIZE_ANY_EXHDR(envelope);

			/*
			 * The plaintext is never longer than the envelope, which is a varlena already,
			 * so this size needs no overflow check. In a UTF-8 (or SQL_ASCII) database the
			 * core opens straight into the result: one copy of the plaintext fewer.
			 */
			opened_cap = envelope_len;
			if (direct)
			{
				result = (text *) palloc(VARHDRSZ + opened_cap);
				opened = VARDATA(result);
			}
			else
				opened = palloc(opened_cap);

			rc = gcm_open((const uint8_t *) VARDATA_ANY(key), key_len,
						  (const uint8_t *) VARDATA_ANY(envelope), envelope_len,
						  (uint8_t *) opened, opened_cap, &opened_len);
		}

		if (failure == OPEN_OK && rc == GCM_OK)
		{
			/* false for anything that is not UTF-8, a zero byte included. */
			if (!pg_verify_mbstr(PG_UTF8, opened, (int) opened_len, true))
				failure = OPEN_NOT_UTF8;
			else if (direct)
			{
				SET_VARSIZE(result, VARHDRSZ + opened_len);
				result_complete = true;
			}
			else if (opened_len == 0)
			{
				/* Nothing to convert; an empty input makes the conversion's count ambiguous. */
				result = cstring_to_text_with_len("", 0);
				result_complete = true;
			}
			else if (opened_len > (MaxAllocSize - 1) / MAX_CONVERSION_GROWTH)
				failure = OPEN_TOO_LONG;
			else
			{
				int			consumed;

				converted_cap = opened_len * MAX_CONVERSION_GROWTH + 1;
				converted = palloc(converted_cap);
				consumed = pg_do_encoding_conversion_buf(from_utf8, PG_UTF8, db_encoding,
														 (unsigned char *) opened,
														 (int) opened_len,
														 (unsigned char *) converted,
														 (int) converted_cap,
														 true);
				/* Valid UTF-8 that stops short is a character the database cannot hold. */
				if ((Size) consumed < opened_len)
					failure = OPEN_UNTRANSLATABLE;
				else
				{
					result = cstring_to_text_with_len(converted, (int) strlen(converted));
					result_complete = true;
				}
			}
		}
	}
	PG_FINALLY();
	{
		if (converted != NULL)
		{
			gcm_cleanse(converted, converted_cap);
			pfree(converted);
		}
		if (direct)
		{
			/* The opened bytes live in the result; it is ours until it is complete. */
			if (result != NULL && !result_complete)
			{
				gcm_cleanse(result, VARHDRSZ + opened_cap);
				pfree(result);
			}
		}
		else if (opened != NULL)
		{
			gcm_cleanse(opened, opened_cap);
			pfree(opened);
		}
		pg_gcm_release_copy((struct varlena *) key, PG_GETARG_DATUM(1), true);
		pg_gcm_release_copy((struct varlena *) envelope, PG_GETARG_DATUM(0), false);
	}
	PG_END_TRY();

	/* Raised only now, with every copy cleansed. Lengths and encoding names, no data. */
	switch (failure)
	{
		case OPEN_OK:
			break;
		case OPEN_BAD_KEY_LEN:
			pg_gcm_raise(GCM_BAD_KEY_LEN, key_len, envelope_len);
			break;
		case OPEN_NOT_UTF8:
			ereport(ERROR,
					(errcode(ERRCODE_CHARACTER_NOT_IN_REPERTOIRE),
					 errmsg("decrypted value is not valid UTF-8")));
			break;
		case OPEN_UNTRANSLATABLE:
			ereport(ERROR,
					(errcode(ERRCODE_UNTRANSLATABLE_CHARACTER),
					 errmsg("decrypted value has a character with no equivalent in encoding \"%s\"",
							GetDatabaseEncodingName())));
			break;
		case OPEN_TOO_LONG:
			pg_gcm_raise(GCM_BAD_LENGTH, key_len, envelope_len);
			break;
	}

	/* A tag mismatch is the one failure pg_gcm.strict governs: error, or NULL. Nothing else. */
	if (rc == GCM_BAD_TAG && !pg_gcm_strict)
		PG_RETURN_NULL();
	pg_gcm_raise(rc, key_len, envelope_len);

	PG_RETURN_TEXT_P(result);
}
