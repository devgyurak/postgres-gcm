-- Given: an envelope sealed in the UTF8 database holding a character EUC_KR does not have
-- When: it is opened in an EUC_KR database
-- Then: it is an error that names the encoding and carries no byte of the character —
--       never a substitution
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
SELECT current_database() AS home \gset
SELECT gcm_encrypt('😀', :k) AS emoji \gset
SET client_min_messages = warning;
DROP DATABASE IF EXISTS regress_pg_gcm_untranslatable;
RESET client_min_messages;
CREATE DATABASE regress_pg_gcm_untranslatable ENCODING 'EUC_KR' LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
\c regress_pg_gcm_untranslatable
SET client_encoding = 'UTF8';
CREATE EXTENSION pg_gcm;

SELECT gcm_decrypt(:'emoji'::bytea, :k);

\c :home
DROP DATABASE regress_pg_gcm_untranslatable;
