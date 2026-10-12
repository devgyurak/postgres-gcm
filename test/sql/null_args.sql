-- Given: the three functions, all declared STRICT
-- When: NULL is passed in each argument position
-- Then: every call returns NULL — no error, and no cryptographic work
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
SELECT gcm_encrypt(NULL, :k) IS NULL AS encrypt_null_plaintext,
       gcm_encrypt('x', NULL) IS NULL AS encrypt_null_key,
       gcm_encrypt_det(NULL, :k) IS NULL AS det_null_plaintext,
       gcm_encrypt_det('x', NULL) IS NULL AS det_null_key,
       gcm_decrypt(NULL, :k) IS NULL AS decrypt_null_ciphertext,
       gcm_decrypt('\x00'::bytea, NULL) IS NULL AS decrypt_null_key;
