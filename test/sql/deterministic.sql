-- Given: one plaintext and the public pattern key
-- When: it is sealed twice with gcm_encrypt_det, and once with another plaintext; and a
--       column of such envelopes carries UNIQUE and the version check of spec §2.9
-- Then: the two envelopes are equal, carry version byte 0x03 and open to the plaintext; the
--       other plaintext gives another envelope; the column refuses a second envelope of one
--       value and a random-nonce envelope, and an exact-match lookup finds the row.
--       The known answers are the det vectors, in vectors.sql.
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
SELECT gcm_encrypt_det('홍길동', :k) = gcm_encrypt_det('홍길동', :k) AS equal,
       get_byte(gcm_encrypt_det('홍길동', :k), 0) AS version,
       octet_length(gcm_encrypt_det('홍길동', :k)) AS bytes,
       gcm_decrypt(gcm_encrypt_det('홍길동', :k), :k) AS round_trip,
       gcm_encrypt_det('홍길동', :k) <> gcm_encrypt_det('홍길순', :k) AS other_differs;

CREATE TEMP TABLE member (id int, code_det bytea UNIQUE CHECK (get_byte(code_det, 0) = 3));
INSERT INTO member VALUES (1, gcm_encrypt_det('M-0001', :k)), (2, gcm_encrypt_det('M-0002', :k));
INSERT INTO member VALUES (3, gcm_encrypt_det('M-0001', :k));
INSERT INTO member VALUES (4, gcm_encrypt('M-0001', :k));
SELECT id FROM member WHERE code_det = gcm_encrypt_det('M-0002', :k);
