-- SPDX-License-Identifier: PostgreSQL
\echo Use "CREATE EXTENSION pg_gcm" to load this file. \quit

-- Phase S declares the two-argument forms for AES-256 (docs/design.md §4). The AAD overloads
-- and the 24- and 16-byte suites arrive with Phase 2, before 0.1.0 is released.
--
-- Every function is STRICT (NULL in gives NULL out, with no cryptographic work) and
-- PARALLEL SAFE, and its volatility is VOLATILE or STABLE and nothing stronger: a function
-- that an index or a generated column may use would put a key literal into the catalog
-- (design §5.3).
-- COST is in units of cpu_operator_cost. Phase S measured a call on a short value at 0.3-0.4
-- microseconds (decrypt), 0.6-1.0 (encrypt) and 1.0-1.2 (deterministic): tens to a couple of
-- hundred times a cost-1 operator, which is itself too small to measure closely (design §8).
-- The values are round on purpose; they make the planner order these after cheaper predicates.

CREATE FUNCTION gcm_encrypt(plaintext text, key bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'gcm_encrypt'
LANGUAGE C VOLATILE STRICT PARALLEL SAFE COST 100;

COMMENT ON FUNCTION gcm_encrypt(text, bytea) IS
'AES-GCM encryption with a random nonce; the result is a versioned envelope';

CREATE FUNCTION gcm_encrypt_det(plaintext text, key bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'gcm_encrypt_det'
LANGUAGE C STABLE STRICT PARALLEL SAFE COST 200;

COMMENT ON FUNCTION gcm_encrypt_det(text, bytea) IS
'Deterministic AES-GCM encryption: reveals equality, frequency and length. For joins, UNIQUE and exact match only, never free text';

CREATE FUNCTION gcm_decrypt(ciphertext bytea, key bytea)
RETURNS text
AS 'MODULE_PATHNAME', 'gcm_decrypt'
LANGUAGE C STABLE STRICT PARALLEL SAFE COST 50;

COMMENT ON FUNCTION gcm_decrypt(bytea, bytea) IS
'Opens an envelope and returns the text in the database encoding; pg_gcm.strict decides error or NULL on a tag mismatch';
