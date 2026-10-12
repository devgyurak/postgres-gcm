-- Given: an envelope this extension did not seal — test case 14 of the GCM specification
--        (key and IV all zero), whose plaintext is sixteen zero bytes
-- When: it is decrypted, with pg_gcm.strict on and then off
-- Then: it authenticates and is then refused as text, with no byte of it in the message;
--       strict does not turn that into NULL
\set VERBOSITY terse
\set zero_key '\'\\x0000000000000000000000000000000000000000000000000000000000000000\'::bytea'
\set tc14 '\'\\x02000000000000000000000000cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919\'::bytea'
SET pg_gcm.strict = on;
SELECT gcm_decrypt(:tc14, :zero_key);
SET pg_gcm.strict = off;
SELECT gcm_decrypt(:tc14, :zero_key);
