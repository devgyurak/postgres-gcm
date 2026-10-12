-- Given: three Korean names sealed with a random nonce under the public 00..1f pattern key
-- When: the decrypted value is filtered with PostgreSQL's own LIKE '%길%'
-- Then: the two names that contain 길 come back, and the third does not
-- This test is the reason the project exists; it is never deleted (AGENTS.md §5).
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
CREATE TEMP TABLE people (id int, name_enc bytea);
INSERT INTO people VALUES
  (1, gcm_encrypt('홍길동', :k)),
  (2, gcm_encrypt('김영희', :k)),
  (3, gcm_encrypt('길동이', :k));

SELECT id, gcm_decrypt(name_enc, :k) AS name
FROM people
WHERE gcm_decrypt(name_enc, :k) LIKE '%길%'
ORDER BY id;
