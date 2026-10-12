-- Given: one plaintext and the public pattern key
-- When: it is sealed twice with gcm_encrypt_det, and once with another plaintext
-- Then: the two envelopes are equal, carry version byte 0x03 and the nonce
--       HMAC-SHA256(HMAC-SHA256(key, 'pg_gcm/v1/det-nonce'), plaintext)[:12] (from Python's
--       hmac module), and open to the plaintext; the other plaintext gives another envelope
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
SELECT gcm_encrypt_det('홍길동', :k) = gcm_encrypt_det('홍길동', :k) AS equal,
       get_byte(gcm_encrypt_det('홍길동', :k), 0) AS version,
       encode(substring(gcm_encrypt_det('홍길동', :k) FROM 2 FOR 12), 'hex') AS nonce,
       gcm_decrypt(gcm_encrypt_det('홍길동', :k), :k) AS round_trip,
       gcm_encrypt_det('홍길동', :k) <> gcm_encrypt_det('홍길순', :k) AS other_differs;
