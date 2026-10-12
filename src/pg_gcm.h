/* SPDX-License-Identifier: PostgreSQL */
/*
 * pg_gcm.h — what the SQL glue files share: the GUC variable, argument release and error
 * translation. Included only by the glue (pg_gcm.c, fn_*.c), after postgres.h.
 */
#ifndef PG_GCM_PG_GCM_H
#define PG_GCM_PG_GCM_H

#include "envelope.h"

/* The GUCs — read at call time; PostgreSQL keeps them current for the backend. */
extern bool pg_gcm_strict;
extern int	pg_gcm_min_key_bytes;

/*
 * The conversion procedure between the database encoding and UTF-8, or InvalidOid when the
 * database is UTF8 or SQL_ASCII and nothing is converted. Raises 42883 when pg_catalog has
 * no default conversion for the database encoding; a conversion in another schema is not
 * used (design §8, O14). A catalog lookup: call it before any secret copy exists.
 */
extern Oid	pg_gcm_conversion_proc(bool to_utf8);

/* Raise 22023 for a key that names a suite but is shorter than pg_gcm.min_key_bytes. */
extern void pg_gcm_raise_key_below_minimum(Size key_len);

/*
 * Free a detoasted copy of argument `arg`, cleansing it first when it holds a secret.
 * A value that needed no detoasting is the executor's own storage — a cached plan's constant,
 * a bind value, a tuple in a shared buffer page — and is never written to (design §5.2).
 */
extern void pg_gcm_release_copy(struct varlena *value, Datum arg, bool secret);

/*
 * Translate a core error into ereport(ERROR), with the SQLSTATE of spec 2.5. Call it only
 * after every secret copy has been cleansed; the core has already released its OpenSSL
 * objects. Returns only for GCM_OK. Messages carry lengths and nothing else.
 */
extern void pg_gcm_raise(enum gcm_error rc, Size key_len, Size envelope_len);

#endif							/* PG_GCM_PG_GCM_H */
