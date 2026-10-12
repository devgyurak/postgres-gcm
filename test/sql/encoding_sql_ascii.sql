-- Given: a SQL_ASCII database, whose text carries no encoding
-- When: UTF-8 bytes are sealed and opened there, and then bytes that are not UTF-8 are sealed
-- Then: the UTF-8 value makes the round trip; the other is refused, with no byte of it in the
--       message — an envelope always holds UTF-8
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
SELECT current_database() AS home \gset
SET client_min_messages = warning;
DROP DATABASE IF EXISTS regress_pg_gcm_sqlascii;
RESET client_min_messages;
CREATE DATABASE regress_pg_gcm_sqlascii ENCODING 'SQL_ASCII' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
\c regress_pg_gcm_sqlascii
CREATE EXTENSION pg_gcm;

SELECT current_setting('server_encoding') AS server_encoding,
       gcm_decrypt(gcm_encrypt('홍길동', :k), :k) LIKE '%길%' AS hit,
       octet_length(gcm_encrypt('홍길동', :k)) - 29 AS sealed_bytes;
-- 0xB1 0xE6 is 길 in EUC_KR and is not UTF-8.
SELECT gcm_encrypt(convert_from('\xb1e6'::bytea, 'SQL_ASCII'), :k);

\c :home
DROP DATABASE regress_pg_gcm_sqlascii;
