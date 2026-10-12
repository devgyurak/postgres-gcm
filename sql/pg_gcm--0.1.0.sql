-- SPDX-License-Identifier: PostgreSQL
\echo Use "CREATE EXTENSION pg_gcm" to load this file. \quit

-- The envelope and what these functions do with it are specified in spec/envelope.md.
--
-- Every function is STRICT (NULL in gives NULL out, with no cryptographic work) and
-- PARALLEL SAFE, and its volatility is VOLATILE or STABLE and nothing stronger: a function
-- that an index or a generated column may use would put a key literal into the catalog
-- (design §5.3).
-- The AAD is optional through two declarations of each function, not through a default: an
-- omitted aad seals, an explicit NULL gives NULL (design §2.1). The two-argument form is the
-- three-argument form with an empty aad.
-- COST is in units of cpu_operator_cost. Phase S measured a call on a short value at 0.3-0.4
-- microseconds (decrypt), 0.6-1.0 (encrypt) and 1.0-1.2 (deterministic): tens to a couple of
-- hundred times a cost-1 operator, which is itself too small to measure closely (design §8).
-- The values are round on purpose; they make the planner order these after cheaper predicates.

CREATE FUNCTION gcm_encrypt(plaintext text, key bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'gcm_encrypt'
LANGUAGE C VOLATILE STRICT PARALLEL SAFE COST 100;

CREATE FUNCTION gcm_encrypt(plaintext text, key bytea, aad bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'gcm_encrypt'
LANGUAGE C VOLATILE STRICT PARALLEL SAFE COST 100;

COMMENT ON FUNCTION gcm_encrypt(text, bytea) IS
'AES-GCM encryption with a random nonce; the result is a versioned envelope';
COMMENT ON FUNCTION gcm_encrypt(text, bytea, bytea) IS
'AES-GCM encryption with a random nonce, bound to additional authenticated data';

CREATE FUNCTION gcm_encrypt_det(plaintext text, key bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'gcm_encrypt_det'
LANGUAGE C STABLE STRICT PARALLEL SAFE COST 200;

CREATE FUNCTION gcm_encrypt_det(plaintext text, key bytea, aad bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'gcm_encrypt_det'
LANGUAGE C STABLE STRICT PARALLEL SAFE COST 200;

COMMENT ON FUNCTION gcm_encrypt_det(text, bytea) IS
'Deterministic AES-GCM encryption: reveals equality, frequency and length. For joins, UNIQUE and exact match only, never free text';
COMMENT ON FUNCTION gcm_encrypt_det(text, bytea, bytea) IS
'Deterministic AES-GCM encryption bound to additional authenticated data: equal only for equal value and equal aad';

CREATE FUNCTION gcm_decrypt(ciphertext bytea, key bytea)
RETURNS text
AS 'MODULE_PATHNAME', 'gcm_decrypt'
LANGUAGE C STABLE STRICT PARALLEL SAFE COST 50;

CREATE FUNCTION gcm_decrypt(ciphertext bytea, key bytea, aad bytea)
RETURNS text
AS 'MODULE_PATHNAME', 'gcm_decrypt'
LANGUAGE C STABLE STRICT PARALLEL SAFE COST 50;

COMMENT ON FUNCTION gcm_decrypt(bytea, bytea) IS
'Opens an envelope of either variant and returns the text in the database encoding; pg_gcm.strict decides error or NULL on a tag mismatch';
COMMENT ON FUNCTION gcm_decrypt(bytea, bytea, bytea) IS
'Opens an envelope sealed with additional authenticated data, which must be the same bytes';
