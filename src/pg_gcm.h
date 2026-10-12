/* SPDX-License-Identifier: PostgreSQL */
/*
 * pg_gcm.h — what the SQL glue files share: the GUC variable, argument release and error
 * translation. Included only by the glue (pg_gcm.c, fn_*.c), after postgres.h.
 */
#ifndef PG_GCM_PG_GCM_H
#define PG_GCM_PG_GCM_H

#include "envelope.h"

/* pg_gcm.strict — read at call time; PostgreSQL keeps it current for the backend. */
extern bool pg_gcm_strict;

/*
 * Free a detoasted copy of argument `arg`, cleansing it first when it holds a secret.
 * A value that needed no detoasting is the executor's own storage — a cached plan's constant,
 * a bind value, a tuple in a shared buffer page — and is never written to (design §5.2).
 */
extern void pg_gcm_release_copy(struct varlena *value, Datum arg, bool secret);

/*
 * Translate a core error into ereport(ERROR). Call it only after every secret copy has been
 * cleansed; the core has already released its OpenSSL objects. Returns only for GCM_OK.
 * Messages carry lengths and nothing else.
 */
extern void pg_gcm_raise(enum gcm_error rc, Size key_len, Size envelope_len);

#endif							/* PG_GCM_PG_GCM_H */
