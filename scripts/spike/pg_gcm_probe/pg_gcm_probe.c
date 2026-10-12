/* SPDX-License-Identifier: PostgreSQL */
/*
 * pg_gcm_probe — a measurement-only module for Phase S (docs/design.md §4, steps 6 and 7).
 * It is not part of the extension and is never shipped. It answers two questions without
 * putting measurement code into pg_gcm itself:
 *
 *   O8   What does CRYPTO_set_mem_functions return inside a postmaster or a backend?
 *   O12  What does one PG_TRY / PG_FINALLY block cost per call?
 */
#include "postgres.h"

#include "fmgr.h"
#include "miscadmin.h"
#include "utils/builtins.h"

#include <openssl/crypto.h>

PG_MODULE_MAGIC;

void		_PG_init(void);

PG_FUNCTION_INFO_V1(probe_set_mem_functions);
PG_FUNCTION_INFO_V1(probe_plain);
PG_FUNCTION_INFO_V1(probe_try);

static int	set_mem_result = -1;
static bool loaded_by_postmaster = false;

void
_PG_init(void)
{
	CRYPTO_malloc_fn m;
	CRYPTO_realloc_fn r;
	CRYPTO_free_fn f;

	/*
	 * Offer OpenSSL the functions it already uses: whatever it answers, nothing changes.
	 * 1 would mean a counting allocator could still be installed here; 0 means OpenSSL has
	 * already allocated and refuses.
	 */
	CRYPTO_get_mem_functions(&m, &r, &f);
	set_mem_result = CRYPTO_set_mem_functions(m, r, f);
	loaded_by_postmaster = process_shared_preload_libraries_in_progress;

	elog(LOG, "pg_gcm_probe: CRYPTO_set_mem_functions returned %d (%s)",
		 set_mem_result,
		 loaded_by_postmaster ? "postmaster, shared_preload_libraries" : "backend, first call");
}

/* What _PG_init saw, for a query to print. */
Datum
probe_set_mem_functions(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(cstring_to_text(psprintf("returned %d in the %s",
											  set_mem_result,
											  loaded_by_postmaster ? "postmaster (preloaded)" : "backend (first call)")));
}

/* The same two additions, without and with a PG_TRY / PG_FINALLY block around them. */
Datum
probe_plain(PG_FUNCTION_ARGS)
{
	volatile int32 v = PG_GETARG_INT32(0);

	v += 1;
	v += 1;
	PG_RETURN_INT32(v);
}

Datum
probe_try(PG_FUNCTION_ARGS)
{
	volatile int32 v = PG_GETARG_INT32(0);

	PG_TRY();
	{
		v += 1;
	}
	PG_FINALLY();
	{
		v += 1;
	}
	PG_END_TRY();
	PG_RETURN_INT32(v);
}
