-- Given: pg_gcm.min_key_bytes, which is 32 unless a superuser — or a role granted SET on it —
--        lowers it, and the public pattern key cut to 16, 24 and 32 bytes
-- When: it is set before the library is loaded and after, by a superuser and by a role that
--       is not one, and keys of each length are used to seal and to open
-- Then: sealing refuses a key shorter than the setting and states both lengths; opening does
--       not consult it; only 16, 24 and 32 are values; a role without the privilege cannot
--       lower it, directly or through a placeholder set before the library was loaded
-- This file needs a server that does not preload pg_gcm: each new connection below starts
-- without the library, so that SET makes a placeholder (scripts/verify.sh uses such a server).
-- The role and its grant are cluster-wide. A run cut off between the GRANT and the REVOKE
-- leaves a role the DROP below cannot remove: REVOKE SET ON PARAMETER by hand, or start the
-- development server again (its data directory is a tmpfs).
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
\set k24 '\'\\x000102030405060708090a0b0c0d0e0f1011121314151617\'::bytea'
\set k16 '\'\\x000102030405060708090a0b0c0d0e0f\'::bytea'
SET client_min_messages = warning;
DROP ROLE IF EXISTS regress_pg_gcm_plain;
RESET client_min_messages;
CREATE ROLE regress_pg_gcm_plain;

-- A placeholder a superuser set before the first call: it holds once the library is loaded.
SET pg_gcm.min_key_bytes = 16;
SELECT get_byte(gcm_encrypt('x', :k16), 0) AS version_of_a_16_byte_key;
SHOW pg_gcm.min_key_bytes;

-- A placeholder that is not a key length: refused with a warning when the library loads.
\c -
SET pg_gcm.min_key_bytes = 20;
SELECT gcm_encrypt('x', :k16);
SHOW pg_gcm.min_key_bytes;

-- A placeholder set by a role that may not set the parameter: it does not survive the load.
\c -
SET ROLE regress_pg_gcm_plain;
SET pg_gcm.min_key_bytes = 16;
SELECT gcm_encrypt('x', :k16);
SHOW pg_gcm.min_key_bytes;
-- Nor can that role set it once it is defined, until it is granted SET on it.
SET pg_gcm.min_key_bytes = 16;
RESET ROLE;
GRANT SET ON PARAMETER pg_gcm.min_key_bytes TO regress_pg_gcm_plain;
SET ROLE regress_pg_gcm_plain;
SET pg_gcm.min_key_bytes = 24;
SHOW pg_gcm.min_key_bytes;
RESET ROLE;
REVOKE SET ON PARAMETER pg_gcm.min_key_bytes FROM regress_pg_gcm_plain;
DROP ROLE regress_pg_gcm_plain;

-- The default: AES-256 keys only.
RESET pg_gcm.min_key_bytes;
SHOW pg_gcm.min_key_bytes;
SELECT gcm_encrypt('x', :k24);
SELECT gcm_encrypt_det('x', :k16);
SELECT gcm_encrypt('x', :k16, 'patients.name');
SELECT gcm_encrypt_det('x', :k24, 'patients.name');
-- A length that names no suite is that error, whatever the setting.
SELECT gcm_encrypt('x', decode(repeat('00', 31), 'hex'));

-- Only a key length is a value.
SET pg_gcm.min_key_bytes = 20;
SET pg_gcm.min_key_bytes = 8;
SET pg_gcm.min_key_bytes = 64;

-- 24: AES-192 and AES-256.
SET pg_gcm.min_key_bytes = 24;
SELECT get_byte(gcm_encrypt('x', :k24), 0) AS random_192,
       get_byte(gcm_encrypt_det('x', :k24), 0) AS det_192,
       get_byte(gcm_encrypt('x', :k), 0) AS random_256;
SELECT gcm_encrypt('x', :k16);

-- 16: every suite. The key length selects it and nothing else does.
SET pg_gcm.min_key_bytes = 16;
SELECT get_byte(gcm_encrypt('x', :k16), 0) AS random_128,
       get_byte(gcm_encrypt_det('x', :k16), 0) AS det_128,
       get_byte(gcm_encrypt('x', :k24), 0) AS random_192,
       get_byte(gcm_encrypt_det('x', :k), 0) AS det_256;
SELECT gcm_encrypt('홍길동', :k16) AS sealed_128, gcm_encrypt_det('홍길동', :k24) AS sealed_192 \gset

-- Opening does not consult the setting.
RESET pg_gcm.min_key_bytes;
SELECT gcm_decrypt(:'sealed_128'::bytea, :k16) AS opened_128,
       gcm_decrypt(:'sealed_192'::bytea, :k24) AS opened_192;
