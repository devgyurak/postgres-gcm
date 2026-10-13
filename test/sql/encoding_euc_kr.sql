-- Given: a database whose encoding is EUC_KR
-- When: a Korean name and the empty string are sealed and opened there, with both variants
-- Then: LIKE '%길%' matches; nine bytes of UTF-8 were sealed, not six of EUC_KR; the
--       deterministic envelope is the one the UTF8 database gave, with and without an aad;
--       the empty string stays empty. A character EUC_KR holds and UTF-8 has no equivalent
--       for, and a text too long to convert, are errors that carry no byte of the value
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
SELECT current_database() AS home \gset
SELECT gcm_encrypt_det('홍길동', :k) AS det_from_utf8,
       gcm_encrypt_det('홍길동', :k, 'patients.name') AS det_aad_from_utf8 \gset
-- A run that stopped half-way may have left the database behind.
SET client_min_messages = warning;
DROP DATABASE IF EXISTS regress_pg_gcm_euckr;
RESET client_min_messages;
CREATE DATABASE regress_pg_gcm_euckr ENCODING 'EUC_KR' LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
\c regress_pg_gcm_euckr
-- pg_regress unsets PGCLIENTENCODING, so the new session would read this file as EUC_KR.
SET client_encoding = 'UTF8';
-- --load-extension covers only the database pg_regress made.
CREATE EXTENSION pg_gcm;

SELECT current_setting('server_encoding') AS server_encoding,
       gcm_decrypt(gcm_encrypt('홍길동', :k), :k) LIKE '%길%' AS hit,
       octet_length('홍길동'::text) AS text_bytes,
       octet_length(gcm_encrypt('홍길동', :k)) - 29 AS sealed_bytes,
       gcm_encrypt_det('홍길동', :k) = :'det_from_utf8'::bytea AS det_as_in_utf8,
       gcm_encrypt_det('홍길동', :k, 'patients.name') = :'det_aad_from_utf8'::bytea AS det_aad_as_in_utf8,
       gcm_decrypt(gcm_encrypt_det('홍길동', :k), :k) AS det_round_trip,
       gcm_decrypt(gcm_encrypt('', :k), :k) = '' AS empty_round_trip;

-- 0xC9A1 is a well-formed EUC_KR character in a user-defined row, which maps to nothing.
SELECT gcm_encrypt(convert_from('\xc9a1'::bytea, 'EUC_KR'), :k);
SELECT gcm_encrypt_det(convert_from('\xc9a1'::bytea, 'EUC_KR'), :k, 'patients.name');
\set VERBOSITY sqlstate
SELECT gcm_encrypt(convert_from('\xc9a1'::bytea, 'EUC_KR'), :k);
-- One byte more than a conversion buffer may be asked to hold: refused (54000) before the
-- buffer is allocated. Once only — the argument is 256 MB — so the message that shows the
-- refusal is the extension's is read back from psql. The length comes from a set-returning
-- function so that the planner does not fold repeat() into a constant and keep a second copy.
SELECT gcm_encrypt(repeat('x', n), :k) FROM generate_series(268435456, 268435456) AS n;
\echo :LAST_ERROR_MESSAGE

\c :home
DROP DATABASE regress_pg_gcm_euckr;
