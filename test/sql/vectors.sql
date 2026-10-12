-- Given: every envelope vector of spec/test-vectors.json, read from the file — no value is
--        copied into this test. The nist vectors are the unit suite's: no SQL function takes a
--        nonce. pg_regress runs psql in the directory make runs in, which holds spec/.
-- When: each is opened with pg_gcm.strict on and off; each whose aad is empty is opened by the
--       two-argument form as well; each deterministic one whose nonce is derived is sealed
--       again from its inputs, with pg_gcm.min_key_bytes lowered for the shorter keys
-- Then: every outcome is the one spec/envelope.md §2.5 and §2.8 give for the vector
\set VERBOSITY terse
\set vectors `cat spec/test-vectors.json`
CREATE TEMP TABLE vector AS
SELECT n, id, kind, expect, plaintext_class, coalesce(nonce_derived, true) AS nonce_derived,
       decode(key_hex, 'hex') AS key, decode(aad_hex, 'hex') AS aad,
       decode(plaintext_hex, 'hex') AS plaintext, decode(envelope_hex, 'hex') AS envelope
FROM jsonb_array_elements(:'vectors'::jsonb -> 'vectors') WITH ORDINALITY AS e(v, n),
     jsonb_to_record(v) AS r(id text, kind text, expect text, plaintext_class text,
                             nonce_derived boolean, key_hex text, aad_hex text,
                             plaintext_hex text, envelope_hex text)
WHERE kind <> 'nist';

-- spec §2.5 and §2.8: what gcm_decrypt gives for each outcome of Part 1.
CREATE TEMP TABLE specified (expect text, plaintext_class text, strict_on text, strict_off text);
INSERT INTO specified VALUES
  ('ok', 'text', 'the text', 'the text'),
  ('ok', 'not_utf8', '22021', '22021'),
  ('ok', 'contains_nul', '22021', '22021'),
  ('bad_tag', NULL, 'XX001', 'NULL'),
  ('bad_envelope', NULL, '22P03', '22P03'),
  ('bad_key_length', NULL, '22023', '22023');

-- What opening gave: 'the text' when it is the vector's plaintext, 'NULL', or the SQLSTATE.
-- A NULL aad asks for the two-argument form.
CREATE FUNCTION pg_temp.opened(envelope bytea, key bytea, aad bytea, plaintext bytea, strict text)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  t text;
BEGIN
  PERFORM set_config('pg_gcm.strict', strict, true);
  t := CASE WHEN aad IS NULL THEN gcm_decrypt(envelope, key) ELSE gcm_decrypt(envelope, key, aad) END;
  RETURN CASE WHEN t IS NULL THEN 'NULL'
              WHEN convert_to(t, 'UTF8') = plaintext THEN 'the text'
              ELSE 'another text' END;
EXCEPTION WHEN OTHERS THEN
  RETURN SQLSTATE;
END $$;

SELECT v.id, o.strict_on, o.strict_off,
       o.strict_on = s.strict_on AND o.strict_off = s.strict_off AS as_specified
FROM vector v
JOIN specified s ON s.expect = v.expect AND s.plaintext_class IS NOT DISTINCT FROM v.plaintext_class,
LATERAL (SELECT pg_temp.opened(v.envelope, v.key, v.aad, v.plaintext, 'on') AS strict_on,
                pg_temp.opened(v.envelope, v.key, v.aad, v.plaintext, 'off') AS strict_off) AS o
ORDER BY v.n;

-- Every envelope vector was joined to a specified outcome: none fell out of the query above.
SELECT count(*) AS envelope_vectors,
       count(s.expect) AS with_a_specified_outcome
FROM vector v
LEFT JOIN specified s ON s.expect = v.expect AND s.plaintext_class IS NOT DISTINCT FROM v.plaintext_class;

-- The two-argument form is the three-argument form with an empty aad (spec §2.1).
SELECT count(*) AS vectors_with_an_empty_aad,
       count(*) FILTER (WHERE pg_temp.opened(v.envelope, v.key, NULL, v.plaintext, 'on') = s.strict_on
                          AND pg_temp.opened(v.envelope, v.key, NULL, v.plaintext, 'off') = s.strict_off)
         AS as_specified_by_the_two_argument_form
FROM vector v
JOIN specified s ON s.expect = v.expect AND s.plaintext_class IS NOT DISTINCT FROM v.plaintext_class
WHERE v.aad = '';

-- Sealing: only a deterministic vector can be compared — a random nonce is drawn inside.
BEGIN;
SET LOCAL pg_gcm.min_key_bytes = 16;
SELECT id, octet_length(key) AS key_bytes,
       gcm_encrypt_det(convert_from(plaintext, 'UTF8'), key, aad) = envelope AS seals_to_the_vector
FROM vector
WHERE kind = 'det' AND expect = 'ok' AND plaintext_class = 'text' AND nonce_derived
ORDER BY n;
SELECT count(*) AS det_vectors_with_an_empty_aad,
       count(*) FILTER (WHERE gcm_encrypt_det(convert_from(plaintext, 'UTF8'), key) = envelope)
         AS sealed_to_the_vector_by_the_two_argument_form
FROM vector
WHERE kind = 'det' AND expect = 'ok' AND plaintext_class = 'text' AND nonce_derived AND aad = '';
COMMIT;
