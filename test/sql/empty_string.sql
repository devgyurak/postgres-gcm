-- Given: the empty string, which is not NULL
-- When: it is sealed with each variant and opened
-- Then: each envelope is the 29 bytes of version, nonce and tag alone, and the empty string
--       comes back — not NULL
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
SELECT octet_length(gcm_encrypt('', :k)) AS random_bytes,
       octet_length(gcm_encrypt_det('', :k)) AS det_bytes,
       gcm_decrypt(gcm_encrypt('', :k), :k) = '' AS random_round_trip,
       gcm_decrypt(gcm_encrypt_det('', :k), :k) = '' AS det_round_trip;
