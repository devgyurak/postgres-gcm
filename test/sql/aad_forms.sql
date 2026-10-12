-- Given: one plaintext, the public pattern key, and additional authenticated data (aad)
-- When: each function is called with and without its third argument
-- Then: two random envelopes of one plaintext differ, in either form; an envelope opens only
--       with the aad it was sealed with, which it does not store; the
--       two-argument form is the three-argument form with an empty aad; the deterministic
--       nonce depends on the aad (design §8, O16); a tag failure follows pg_gcm.strict
\set VERBOSITY terse
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
SELECT gcm_encrypt('홍길동', :k) <> gcm_encrypt('홍길동', :k) AS random_differs,
       gcm_encrypt('홍길동', :k, 'patients.name') <> gcm_encrypt('홍길동', :k, 'patients.name') AS random_differs_with_aad,
       gcm_decrypt(gcm_encrypt('홍길동', :k, 'patients.name'), :k, 'patients.name') AS random_round_trip,
       gcm_decrypt(gcm_encrypt_det('홍길동', :k, 'patients.name'), :k, 'patients.name') AS det_round_trip,
       octet_length(gcm_encrypt('홍길동', :k, 'patients.name')) AS envelope_bytes;

SELECT gcm_decrypt(gcm_encrypt('홍길동', :k), :k, '') AS sealed_without_opened_with_empty,
       gcm_decrypt(gcm_encrypt('홍길동', :k, ''), :k) AS sealed_with_empty_opened_without,
       gcm_encrypt_det('홍길동', :k) = gcm_encrypt_det('홍길동', :k, '') AS det_forms_equal;

SELECT gcm_encrypt_det('홍길동', :k, 'patients.name') = gcm_encrypt_det('홍길동', :k, 'patients.name') AS same_aad_same_envelope,
       substring(gcm_encrypt_det('홍길동', :k, 'patients.name') FROM 2 FOR 12)
         <> substring(gcm_encrypt_det('홍길동', :k, 'patients.alias') FROM 2 FOR 12) AS other_aad_other_nonce,
       substring(gcm_encrypt_det('홍길동', :k, 'patients.name') FROM 2 FOR 12)
         <> substring(gcm_encrypt_det('홍길동', :k) FROM 2 FOR 12) AS aad_and_none_differ_in_nonce;

-- An aad long enough to be stored out of line, which the function detoasts into its own copy.
CREATE TEMP TABLE context (aad bytea);
INSERT INTO context VALUES (convert_to(repeat('patients.name/', 20000), 'UTF8'));
SELECT octet_length(aad) AS aad_bytes,
       gcm_decrypt(gcm_encrypt('홍길동', :k, aad), :k, aad) AS random_round_trip,
       gcm_decrypt(gcm_encrypt_det('홍길동', :k, aad), :k, aad) AS det_round_trip
FROM context;

SET pg_gcm.strict = on;
SELECT gcm_decrypt(gcm_encrypt('홍길동', :k, 'patients.name'), :k);
SELECT gcm_decrypt(gcm_encrypt('홍길동', :k, 'patients.name'), :k, 'patients.alias');
SELECT gcm_decrypt(gcm_encrypt('홍길동', :k), :k, 'patients.name');
SELECT gcm_decrypt(gcm_encrypt_det('홍길동', :k, 'patients.name'), :k, 'patients.alias');

SET pg_gcm.strict = off;
SELECT gcm_decrypt(gcm_encrypt('홍길동', :k, 'patients.name'), :k) IS NULL AS aad_missing,
       gcm_decrypt(gcm_encrypt('홍길동', :k, 'patients.name'), :k, 'patients.alias') IS NULL AS aad_different,
       gcm_decrypt(gcm_encrypt('홍길동', :k), :k, 'patients.name') IS NULL AS aad_unexpected;
