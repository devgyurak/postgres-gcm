-- Given: keys whose length names no suite, and one whose length names another suite than the
--        envelope's
-- When: each is used to encrypt or to decrypt
-- Then: every call is an error that states the length and nothing else. (A 16- or 24-byte key
--       refused by pg_gcm.min_key_bytes is in min_key_bytes.sql.)
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
SELECT gcm_encrypt('x', ''::bytea);
SELECT gcm_encrypt('x', decode(repeat('00', 15), 'hex'));
SELECT gcm_encrypt('x', decode(repeat('00', 17), 'hex'));
SELECT gcm_encrypt('x', decode(repeat('00', 31), 'hex'));
SELECT gcm_encrypt('x', decode(repeat('00', 33), 'hex'));
SELECT gcm_encrypt('x', decode(repeat('00', 33), 'hex'), 'patients.name');
SELECT gcm_encrypt_det('x', decode(repeat('00', 33), 'hex'));
SELECT gcm_encrypt_det('x', decode(repeat('00', 25), 'hex'), 'patients.name');
SELECT gcm_decrypt(gcm_encrypt('x', :k), decode(repeat('00', 31), 'hex'));
SELECT gcm_decrypt(gcm_encrypt('x', :k), decode(repeat('00', 23), 'hex'), 'patients.name');
-- A key of another suite than the envelope's: a key-length error, not a tag failure, so
-- pg_gcm.strict = off does not turn it into NULL (spec §1.7).
SET pg_gcm.strict = off;
SELECT gcm_decrypt(gcm_encrypt('x', :k), decode(repeat('00', 16), 'hex'));
SELECT gcm_decrypt(gcm_encrypt('x', :k), decode(repeat('00', 24), 'hex'));
