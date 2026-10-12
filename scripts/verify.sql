-- SPDX-License-Identifier: PostgreSQL
-- The Phase S checks of docs/design.md §4, one labelled row per check:
--
--   step | mode | check | observed | ok / FAIL / info
--
-- Run by scripts/verify.sh, which sets:
--   mode   lazy | preload            how the library reaches the backend
--   probe  0 | 1                     1 = the per-backend part of step 5 only
-- The probe part must be the first thing a fresh backend runs.
\set ON_ERROR_STOP on
\pset format unaligned
\pset tuples_only on
\pset fieldsep ' | '
-- The public 00..1f pattern key (.agents/rules/testing.md). Never a real key.
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
-- HMAC-SHA256(HMAC-SHA256(k, 'pg_gcm/v1/det-nonce'), utf8('홍길동'))[:12], from Python's hmac module.
\set det_nonce 'f55369153b2a94fcbc9b633f'

\if :probe
-- ---------------------------------------------------------------------------------------------
-- Step 5, per backend. verify.sh runs this in two backends and compares the nonce rows.
-- ---------------------------------------------------------------------------------------------
SELECT 'S5', :'mode', 'library loaded before this backend''s first call',
       coalesce(current_setting('pg_gcm.strict', true), 'no'),
       CASE WHEN (current_setting('pg_gcm.strict', true) IS NOT NULL) = (:'mode' = 'preload')
            THEN 'ok' ELSE 'FAIL' END;
SELECT 'S5', :'mode', 'first random nonce of this backend',
       encode(substring(gcm_encrypt('x', :k) FROM 2 FOR 12), 'hex'), 'info';
SELECT 'S5', :'mode', 'AES-256-GCM round trip',
       gcm_decrypt(gcm_encrypt('홍길동', :k), :k),
       CASE WHEN gcm_decrypt(gcm_encrypt('홍길동', :k), :k) = '홍길동' THEN 'ok' ELSE 'FAIL' END;
SELECT 'S5', :'mode', 'HMAC-SHA256 nonce known answer (O4)',
       encode(substring(gcm_encrypt_det('홍길동', :k) FROM 2 FOR 12), 'hex'),
       CASE WHEN encode(substring(gcm_encrypt_det('홍길동', :k) FROM 2 FOR 12), 'hex') = :'det_nonce'
            THEN 'ok' ELSE 'FAIL' END;
SELECT 'END', :'mode', 'probe', pg_backend_pid()::text, 'info';
\else
-- ---------------------------------------------------------------------------------------------
-- Setup: two throwaway databases, one UTF8 and one EUC_KR.
-- ---------------------------------------------------------------------------------------------
\c postgres
DROP DATABASE IF EXISTS pg_gcm_verify;
DROP DATABASE IF EXISTS pg_gcm_verify_euckr;
CREATE DATABASE pg_gcm_verify TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';
CREATE DATABASE pg_gcm_verify_euckr TEMPLATE template0 ENCODING 'EUC_KR' LC_COLLATE 'C' LC_CTYPE 'C';
\c pg_gcm_verify

-- Step 1: CREATE EXTENSION from the PGXS build.
CREATE EXTENSION pg_gcm;
SELECT 'S1', :'mode', 'server', current_setting('server_version'), 'info';
SELECT 'S1', :'mode', 'CREATE EXTENSION pg_gcm', extversion,
       CASE WHEN extversion = '0.1.0' THEN 'ok' ELSE 'FAIL' END
FROM pg_extension WHERE extname = 'pg_gcm';

-- The SQLSTATE and message a statement fails with, or 'no error'.
CREATE FUNCTION pg_temp.failure_of(q text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE q;
  RETURN 'no error';
EXCEPTION WHEN OTHERS THEN
  RETURN SQLSTATE || ': ' || SQLERRM;
END $$;

-- Step 2: AES-256, random nonce, no AAD.
SELECT 'S2', :'mode', 'round trip', gcm_decrypt(gcm_encrypt('홍길동', :k), :k),
       CASE WHEN gcm_decrypt(gcm_encrypt('홍길동', :k), :k) = '홍길동' THEN 'ok' ELSE 'FAIL' END;
SELECT 'S2', :'mode', 'envelope: version 0x02, 1 + 12 + 9 + 16 bytes',
       get_byte(e, 0) || ', ' || octet_length(e),
       CASE WHEN get_byte(e, 0) = 2 AND octet_length(e) = 38 THEN 'ok' ELSE 'FAIL' END
FROM gcm_encrypt('홍길동', :k) AS e;
SELECT 'S2', :'mode', 'two random envelopes of one plaintext differ', '',
       CASE WHEN gcm_encrypt('홍길동', :k) <> gcm_encrypt('홍길동', :k) THEN 'ok' ELSE 'FAIL' END;
SELECT 'S2', :'mode', 'empty string round trip', octet_length(gcm_encrypt('', :k))::text,
       CASE WHEN gcm_decrypt(gcm_encrypt('', :k), :k) = '' THEN 'ok' ELSE 'FAIL' END;
SELECT 'S2', :'mode', 'deterministic: version 0x03, equal envelopes', get_byte(gcm_encrypt_det('홍길동', :k), 0)::text,
       CASE WHEN gcm_encrypt_det('홍길동', :k) = gcm_encrypt_det('홍길동', :k)
             AND get_byte(gcm_encrypt_det('홍길동', :k), 0) = 3 THEN 'ok' ELSE 'FAIL' END;

-- Step 3: key length, and what pg_gcm.strict governs.
SELECT 'S3', :'mode', 'gcm_encrypt refuses a ' || n || '-byte key', f,
       CASE WHEN f LIKE '22023: %' THEN 'ok' ELSE 'FAIL' END
FROM unnest(ARRAY[0, 16, 24, 31, 33]) AS n,
     pg_temp.failure_of(format('SELECT gcm_encrypt(''x'', decode(repeat(''00'', %s), ''hex''))', n)) AS f;
SELECT 'S3', :'mode', 'gcm_decrypt refuses a 16-byte key', f,
       CASE WHEN f LIKE '22023: %' THEN 'ok' ELSE 'FAIL' END
FROM pg_temp.failure_of(format('SELECT gcm_decrypt(%L::bytea, decode(repeat(''00'', 16), ''hex''))',
                               gcm_encrypt('x', :k))) AS f;

SELECT gcm_encrypt('홍길동', :k) AS sealed \gset
-- The same envelope with the last bit of its tag flipped.
SELECT set_byte(:'sealed'::bytea, 37, get_byte(:'sealed'::bytea, 37) # 1) AS forged \gset

SET pg_gcm.strict = on;
SELECT 'S3', :'mode', 'forged tag, pg_gcm.strict = on: an error', f,
       CASE WHEN f LIKE 'XX001: %' THEN 'ok' ELSE 'FAIL' END
FROM pg_temp.failure_of(format('SELECT gcm_decrypt(%L::bytea, %s)', :'forged', :'k')) AS f;
SET pg_gcm.strict = off;
SELECT 'S3', :'mode', 'forged tag, pg_gcm.strict = off: NULL', coalesce(gcm_decrypt(:'forged'::bytea, :k), 'NULL'),
       CASE WHEN gcm_decrypt(:'forged'::bytea, :k) IS NULL THEN 'ok' ELSE 'FAIL' END;
SELECT 'S3', :'mode', 'intact envelope, pg_gcm.strict = off: the plaintext', gcm_decrypt(:'sealed'::bytea, :k),
       CASE WHEN gcm_decrypt(:'sealed'::bytea, :k) = '홍길동' THEN 'ok' ELSE 'FAIL' END;
SELECT 'S3', :'mode', 'truncated envelope (28 bytes), strict off: still an error', f,
       CASE WHEN f LIKE '22P03: %' THEN 'ok' ELSE 'FAIL' END
FROM pg_temp.failure_of(format('SELECT gcm_decrypt(substring(%L::bytea FROM 1 FOR 28), %s)', :'sealed', :'k')) AS f;
SELECT 'S3', :'mode', 'unimplemented version byte 0x01, strict off: still an error', f,
       CASE WHEN f LIKE '22P03: %' THEN 'ok' ELSE 'FAIL' END
FROM pg_temp.failure_of(format('SELECT gcm_decrypt(set_byte(%L::bytea, 0, 1), %s)', :'sealed', :'k')) AS f;
SELECT 'S3', :'mode', 'wrong key, strict off: NULL', '',
       CASE WHEN gcm_decrypt(:'sealed'::bytea, decode(repeat('00', 32), 'hex')) IS NULL THEN 'ok' ELSE 'FAIL' END;
RESET pg_gcm.strict;
SELECT 'S3', :'mode', 'a misspelt pg_gcm.* name is refused once the library is loaded (§5.6)', f,
       CASE WHEN f <> 'no error' THEN 'ok' ELSE 'FAIL' END
FROM pg_temp.failure_of('SET pg_gcm.strcit = off') AS f;

-- Step 6, as far as SQL can see it: an envelope this extension did not seal. NIST's GCM test
-- case 14 (key and IV all zero, sixteen zero bytes of plaintext) authenticates and then is not
-- text. The error carries no byte of the plaintext and strict does not hide it.
\set nist14 '\'\\x02000000000000000000000000cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919\'::bytea'
SET pg_gcm.strict = off;
SELECT 'S6', :'mode', 'authenticated plaintext that is not text (U+0000), strict off', f,
       CASE WHEN f = '22021: decrypted value is not valid UTF-8' THEN 'ok' ELSE 'FAIL' END
FROM pg_temp.failure_of(format('SELECT gcm_decrypt(%s, decode(repeat(''00'', 32), ''hex''))', :'nist14')) AS f;
RESET pg_gcm.strict;

-- Step 4: Korean LIKE on the decrypted value, in a UTF8 database...
SELECT 'S4', :'mode', 'LIKE ''%길%'' on a decrypted value, ' || current_setting('server_encoding'), '',
       CASE WHEN gcm_decrypt(gcm_encrypt('홍길동', :k), :k) LIKE '%길%' THEN 'ok' ELSE 'FAIL' END;
SELECT 'S4', :'mode', 'LIKE ''%순%'' does not match', '',
       CASE WHEN gcm_decrypt(gcm_encrypt('홍길동', :k), :k) NOT LIKE '%순%' THEN 'ok' ELSE 'FAIL' END;
SELECT gcm_encrypt('😀', :k) AS emoji \gset

-- ...and in an EUC_KR database.
\c pg_gcm_verify_euckr
CREATE EXTENSION pg_gcm;
CREATE FUNCTION pg_temp.failure_of(q text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE q;
  RETURN 'no error';
EXCEPTION WHEN OTHERS THEN
  RETURN SQLSTATE || ': ' || SQLERRM;
END $$;
SELECT 'S4', :'mode', 'LIKE ''%길%'' on a decrypted value, ' || current_setting('server_encoding'), '',
       CASE WHEN gcm_decrypt(gcm_encrypt('홍길동', :k), :k) LIKE '%길%' THEN 'ok' ELSE 'FAIL' END;
SELECT 'S4', :'mode', 'EUC_KR: 6 bytes of text are sealed as 9 bytes of UTF-8',
       octet_length('홍길동'::text) || ' -> ' || octet_length(gcm_encrypt('홍길동', :k)) - 29,
       CASE WHEN octet_length('홍길동'::text) = 6 AND octet_length(gcm_encrypt('홍길동', :k)) = 38
            THEN 'ok' ELSE 'FAIL' END;
SELECT 'S4', :'mode', 'EUC_KR: the nonce is derived from the UTF-8 bytes',
       encode(substring(gcm_encrypt_det('홍길동', :k) FROM 2 FOR 12), 'hex'),
       CASE WHEN encode(substring(gcm_encrypt_det('홍길동', :k) FROM 2 FOR 12), 'hex') = :'det_nonce'
            THEN 'ok' ELSE 'FAIL' END;
SELECT 'S4', :'mode', 'EUC_KR opens what the UTF8 database sealed', gcm_decrypt(:'sealed'::bytea, :k),
       CASE WHEN gcm_decrypt(:'sealed'::bytea, :k) = '홍길동' THEN 'ok' ELSE 'FAIL' END;
SELECT 'S4', :'mode', 'EUC_KR: a character it cannot hold is an error, no bytes in it', f,
       CASE WHEN f = '22P05: decrypted value has a character with no equivalent in encoding "EUC_KR"'
            THEN 'ok' ELSE 'FAIL' END
FROM pg_temp.failure_of(format('SELECT gcm_decrypt(%L::bytea, %s)', :'emoji', :'k')) AS f;
SELECT gcm_encrypt_det('홍길동', :k) AS from_euckr \gset

\c pg_gcm_verify
SELECT 'S4', :'mode', 'UTF8 opens what the EUC_KR database sealed', gcm_decrypt(:'from_euckr'::bytea, :k),
       CASE WHEN gcm_decrypt(:'from_euckr'::bytea, :k) = '홍길동'
             AND :'from_euckr'::bytea = gcm_encrypt_det('홍길동', :k) THEN 'ok' ELSE 'FAIL' END;

\c postgres
DROP DATABASE pg_gcm_verify_euckr;
SELECT 'END', :'mode', 'full', '', 'info';
\endif
