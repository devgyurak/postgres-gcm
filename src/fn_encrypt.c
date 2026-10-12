/* SPDX-License-Identifier: PostgreSQL */
/*
 * fn_encrypt.c — gcm_encrypt and gcm_encrypt_det: arguments, encoding, error translation.
 *
 * The functions are STRICT, so no argument is NULL here. Each has two declarations, with
 * and without aad; the two-argument form is the three-argument form with an empty aad
 * (spec 2.1). The plaintext is sealed as UTF-8 whatever the database encoding (spec 2.4).
 */
#include "postgres.h"

#include "fmgr.h"
#include "mb/pg_wchar.h"
#include "utils/memutils.h"
#if PG_VERSION_NUM >= 160000
#include "varatt.h"
#endif

#include "gcm.h"
#include "pg_gcm.h"

PG_FUNCTION_INFO_V1(gcm_encrypt);
PG_FUNCTION_INFO_V1(gcm_encrypt_det);

/* Why the plaintext could not be sealed, decided inside PG_TRY and raised after it. */
enum seal_failure
{
	SEAL_OK = 0,
	SEAL_BAD_KEY_LEN,
	SEAL_KEY_BELOW_MINIMUM,
	SEAL_NOT_UTF8,
	SEAL_UNTRANSLATABLE,
	SEAL_TOO_LONG
};

static Datum
seal_text(FunctionCallInfo fcinfo, bool deterministic)
{
	int			db_encoding = GetDatabaseEncoding();
	bool		has_aad = PG_NARGS() > 2;
	Oid			to_utf8;
	bytea	   *volatile key = NULL;
	bytea	   *volatile aad = NULL;
	text	   *volatile plaintext = NULL;
	char	   *volatile converted = NULL;
	volatile Size converted_cap = 0;
	bytea	   *volatile result = NULL;
	volatile Size key_len = 0;
	volatile enum seal_failure failure = SEAL_OK;
	volatile enum gcm_error rc = GCM_OK;

	/*
	 * Everything that can raise and needs no secret comes first: the handle check (a fetch
	 * that failed in _PG_init surfaces here) and the catalog lookup of the conversion.
	 */
	if (!gcm_ready())
		pg_gcm_raise(GCM_OPENSSL_FAILURE, 0, 0);
	to_utf8 = pg_gcm_conversion_proc(true);

	/*
	 * design §5.2: from the first secret copy to the last, anything that can still raise —
	 * detoasting, palloc — is inside PG_TRY, and PG_FINALLY cleanses what this function
	 * copied. No OpenSSL object is live in this block: the core acquires and releases its
	 * own within each call and cannot raise.
	 */
	PG_TRY();
	{
		const char *utf8 = NULL;
		Size		utf8_len = 0;

		key = PG_GETARG_BYTEA_PP(1);
		key_len = VARSIZE_ANY_EXHDR(key);
		if (!gcm_key_len_supported(key_len))
			failure = SEAL_BAD_KEY_LEN;
		else if (key_len < (Size) pg_gcm_min_key_bytes)
			failure = SEAL_KEY_BELOW_MINIMUM;

		if (failure == SEAL_OK)
		{
			if (has_aad)
				aad = PG_GETARG_BYTEA_PP(2);
			plaintext = PG_GETARG_TEXT_PP(0);
			utf8 = VARDATA_ANY(plaintext);
			utf8_len = VARSIZE_ANY_EXHDR(plaintext);

			if (db_encoding == PG_SQL_ASCII)
			{
				/* The bytes carry no encoding; anything that is not UTF-8 is refused. */
				if (!pg_verify_mbstr(PG_UTF8, utf8, (int) utf8_len, true))
					failure = SEAL_NOT_UTF8;
			}
			else if (OidIsValid(to_utf8) && utf8_len > 0)
			{
				if (utf8_len > (MaxAllocSize - 1) / MAX_CONVERSION_GROWTH)
					failure = SEAL_TOO_LONG;
				else
				{
					int			consumed;

					converted_cap = utf8_len * MAX_CONVERSION_GROWTH + 1;
					converted = palloc(converted_cap);
					/* The noError form: the server never formats our bytes into a message. */
					consumed = pg_do_encoding_conversion_buf(to_utf8, db_encoding, PG_UTF8,
															 (unsigned char *) VARDATA_ANY(plaintext),
															 (int) utf8_len,
															 (unsigned char *) converted,
															 (int) converted_cap,
															 true);
					if ((Size) consumed < utf8_len)
						failure = SEAL_UNTRANSLATABLE;
					else
					{
						utf8 = converted;
						utf8_len = strlen(converted);
					}
				}
			}
		}

		if (failure == SEAL_OK)
		{
			if (utf8_len > MaxAllocSize - VARHDRSZ - GCM_ENVELOPE_OVERHEAD)
				failure = SEAL_TOO_LONG;
			else
			{
				Size		envelope_len = utf8_len + GCM_ENVELOPE_OVERHEAD;

				result = (bytea *) palloc(VARHDRSZ + envelope_len);
				SET_VARSIZE(result, VARHDRSZ + envelope_len);
				rc = gcm_seal((const uint8_t *) VARDATA_ANY(key), key_len,
							  aad == NULL ? NULL : (const uint8_t *) VARDATA_ANY(aad),
							  aad == NULL ? 0 : VARSIZE_ANY_EXHDR(aad),
							  (const uint8_t *) utf8, utf8_len,
							  deterministic,
							  (uint8_t *) VARDATA(result), envelope_len);
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
		pg_gcm_release_copy((struct varlena *) plaintext, PG_GETARG_DATUM(0), true);
		pg_gcm_release_copy((struct varlena *) key, PG_GETARG_DATUM(1), true);
		if (has_aad)
			pg_gcm_release_copy((struct varlena *) aad, PG_GETARG_DATUM(2), false);
	}
	PG_END_TRY();

	/* Raised only now, with every copy cleansed. Lengths and encoding names, no data. */
	switch (failure)
	{
		case SEAL_OK:
			break;
		case SEAL_BAD_KEY_LEN:
			pg_gcm_raise(GCM_BAD_KEY_LEN, key_len, 0);
			break;
		case SEAL_KEY_BELOW_MINIMUM:
			pg_gcm_raise_key_below_minimum(key_len);
			break;
		case SEAL_NOT_UTF8:
			ereport(ERROR,
					(errcode(ERRCODE_CHARACTER_NOT_IN_REPERTOIRE),
					 errmsg("value to encrypt is not valid UTF-8"),
					 errdetail("A SQL_ASCII database carries no encoding; only UTF-8 bytes are sealed.")));
			break;
		case SEAL_UNTRANSLATABLE:
			ereport(ERROR,
					(errcode(ERRCODE_UNTRANSLATABLE_CHARACTER),
					 errmsg("value to encrypt has a character with no equivalent in encoding \"%s\"",
							pg_encoding_to_char(PG_UTF8))));
			break;
		case SEAL_TOO_LONG:
			pg_gcm_raise(GCM_BAD_LENGTH, 0, 0);
			break;
	}
	pg_gcm_raise(rc, key_len, 0);

	PG_RETURN_BYTEA_P(result);
}

/* gcm_encrypt(plaintext text, key bytea [, aad bytea]) -> bytea. Random nonce; VOLATILE. */
Datum
gcm_encrypt(PG_FUNCTION_ARGS)
{
	return seal_text(fcinfo, false);
}

/*
 * gcm_encrypt_det(plaintext text, key bytea [, aad bytea]) -> bytea. Deterministic; STABLE.
 *
 * Equal plaintexts with equal aad under one key give equal envelopes, so this reveals
 * equality, frequency and length. For join keys, UNIQUE constraints and exact-match lookups
 * only — never free text (design §6, item 5).
 */
Datum
gcm_encrypt_det(PG_FUNCTION_ARGS)
{
	return seal_text(fcinfo, true);
}
