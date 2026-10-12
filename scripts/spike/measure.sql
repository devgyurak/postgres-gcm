-- SPDX-License-Identifier: PostgreSQL
-- Phase S measurements (docs/design.md §4 step 7; §8 O6, O8, O12). Run by scripts/spike/measure.sh
-- inside the server container, so that \! can look at the server's own files.
-- Rows are:  question | what | value
\set ON_ERROR_STOP on
\pset format unaligned
\pset tuples_only on
\pset fieldsep ' | '
-- The public 00..1f pattern key (.agents/rules/testing.md). Never a real key.
\set k '\'\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\'::bytea'
\set khex '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
\set ivhex '000102030405060708090a0b0c0d0e0f'

CREATE EXTENSION IF NOT EXISTS pg_gcm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_gcm_probe;

SELECT 'env', 'server', current_setting('server_version');
SELECT 'O8', 'CRYPTO_set_mem_functions at library load', probe_set_mem_functions();

-- ---------------------------------------------------------------------------------------------
-- O6: is pgcrypto's encrypt_iv(..., 'aes-cbc') with a 32-byte key plain AES-256-CBC with PKCS#7
-- padding? Opened here by OpenSSL's own `enc` command, not by a CBC path in the extension.
-- ---------------------------------------------------------------------------------------------
SELECT encode(encrypt_iv(convert_to('홍길동', 'UTF8'), :k, decode(:'ivhex', 'hex'), 'aes-cbc'), 'hex') AS cbc \gset
SELECT 'O6', 'pgcrypto encrypt_iv aes-cbc, 32-byte key: ciphertext bytes', length(:'cbc') / 2;
\setenv CBC :cbc
\setenv KHEX :khex
\setenv IVHEX :ivhex
\! printf 'O6 | opened by: openssl enc -d -aes-256-cbc -K <key> -iv <iv> | %s\n' "$(perl -e 'print pack("H*", $ENV{CBC})' | openssl enc -d -aes-256-cbc -K "$KHEX" -iv "$IVHEX")"

-- ---------------------------------------------------------------------------------------------
-- Step 7: 300k rows of Korean names, sealed by gcm_encrypt and, for the baseline, by pgcrypto.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE plain_names AS
SELECT i AS id,
       (ARRAY['김','이','박','최','정','강','조','윤','장','임','길'])[1 + i % 11]
       || (ARRAY['민준','서연','도윤','지우','길동','하은','영희','철수'])[1 + i % 8]
       || i::text AS name
FROM generate_series(1, 300000) AS i;

CREATE TABLE people AS
SELECT id,
       gcm_encrypt(name, :k) AS name_gcm,
       encrypt_iv(convert_to(name, 'UTF8'), :k, decode(:'ivhex', 'hex'), 'aes-cbc') AS name_cbc
FROM plain_names;
VACUUM (ANALYZE, FREEZE) plain_names;
VACUUM (ANALYZE, FREEZE) people;

-- One backend, no parallel workers and no JIT: the question is the cost of one call.
SET max_parallel_workers_per_gather = 0;
SET jit = off;

-- The best "Execution Time" of several runs, in milliseconds.
CREATE FUNCTION pg_temp.best_ms(q text, runs int DEFAULT 7) RETURNS numeric LANGUAGE plpgsql AS $$
DECLARE
  j json;
  best numeric := 'Infinity';
BEGIN
  FOR i IN 1..runs LOOP
    EXECUTE 'EXPLAIN (ANALYZE, TIMING OFF, FORMAT JSON) ' || q INTO j;
    best := least(best, (j -> 0 ->> 'Execution Time')::numeric);
  END LOOP;
  RETURN best;
END $$;

-- The yardsticks cost a few nanoseconds a call, which 300k rows cannot resolve: the difference
-- between two scans is smaller than their run-to-run spread. They are measured over 3M calls.
CREATE TEMP TABLE numbers AS SELECT i FROM generate_series(1, 3000000) AS i;
VACUUM (ANALYZE, FREEZE) numbers;

CREATE TEMP TABLE timing (what text PRIMARY KEY, ms numeric);
INSERT INTO timing VALUES
  ('y_scan',   pg_temp.best_ms('SELECT count(i) FROM numbers')),
  ('y_int4ge', pg_temp.best_ms('SELECT count(i) FROM numbers WHERE i >= 0')),
  ('y_plain',  pg_temp.best_ms('SELECT count(probe_plain(i)) FROM numbers')),
  ('y_try',    pg_temp.best_ms('SELECT count(probe_try(i)) FROM numbers')),
  ('scan',     pg_temp.best_ms('SELECT count(*) FROM people')),
  ('decrypt',  pg_temp.best_ms(format('SELECT count(*) FROM people WHERE gcm_decrypt(name_gcm, %s) LIKE ''%%길%%''', :'k'))),
  ('pgcrypto', pg_temp.best_ms(format('SELECT count(*) FROM people WHERE convert_from(decrypt_iv(name_cbc, %s, decode(%L, ''hex''), ''aes-cbc''), ''UTF8'') LIKE ''%%길%%''', :'k', :'ivhex'))),
  ('scan_p',   pg_temp.best_ms('SELECT count(name) FROM plain_names')),
  ('encrypt',  pg_temp.best_ms(format('SELECT count(gcm_encrypt(name, %s)) FROM plain_names', :'k'))),
  ('det',      pg_temp.best_ms(format('SELECT count(gcm_encrypt_det(name, %s)) FROM plain_names', :'k')));

SELECT 'S7', 'rows matched by gcm_decrypt(...) LIKE ''%길%'' of 300000',
       (SELECT count(*) FROM people WHERE gcm_decrypt(name_gcm, :k) LIKE '%길%');
SELECT 'S7', what || ': best of 7, ms', ms FROM timing ORDER BY what;

-- Cost per call above the bare scan, in nanoseconds.
CREATE TEMP TABLE per_call AS
SELECT w AS what, (t.ms - b.ms) / n * 1e6 AS ns
FROM (VALUES ('y_int4ge', 'y_scan', 3000000), ('y_plain', 'y_scan', 3000000), ('y_try', 'y_scan', 3000000),
             ('decrypt', 'scan', 300000), ('pgcrypto', 'scan', 300000),
             ('encrypt', 'scan_p', 300000), ('det', 'scan_p', 300000)) AS v(w, base, n)
JOIN timing t ON t.what = w
JOIN timing b ON b.what = base;
SELECT 'S7', 'per call, ns: ' || what, round(ns, 1) FROM per_call ORDER BY what;

-- COST is in units of cpu_operator_cost. The yardstick is a cost-1 operator in a qual (int4ge).
-- It is a few nanoseconds, at the noise floor of a virtualised host even over 3M rows — it has
-- read anywhere from 1 to 11 ns, and y_plain has come out negative — so the ratio is good to a
-- factor of two or three, no better. The absolute per-call figures above are the stable ones.
SELECT 'S7', f.label || ' per call / int4ge qual per row', round(c.ns / nullif(y.ns, 0), 1)
FROM (VALUES ('decrypt', 'gcm_decrypt + LIKE'), ('encrypt', 'gcm_encrypt'), ('det', 'gcm_encrypt_det')) AS f(what, label)
JOIN per_call c ON c.what = f.what
JOIN per_call y ON y.what = 'y_int4ge'
ORDER BY f.label;
SELECT 'S7', 'gcm_decrypt + LIKE / pgcrypto decrypt_iv (CBC) + convert_from + LIKE, per row',
       round(d.ns / nullif(p.ns, 0), 2)
FROM per_call d, per_call p WHERE d.what = 'decrypt' AND p.what = 'pgcrypto';

-- O12: one PG_TRY / PG_FINALLY block per call.
SELECT 'O12', 'PG_TRY block per call, ns', round(t.ns - p.ns, 1)
FROM per_call t, per_call p WHERE t.what = 'y_try' AND p.what = 'y_plain';
SELECT 'O12', 'PG_TRY block as a share of gcm_decrypt + LIKE per row, percent',
       round(100 * (t.ns - p.ns) / nullif(d.ns, 0), 2)
FROM per_call t, per_call p, per_call d
WHERE t.what = 'y_try' AND p.what = 'y_plain' AND d.what = 'decrypt';

-- The plan itself. The query names the decryption first; the declared COST makes the planner
-- evaluate the cheap predicate before it (design §2.1).
EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF)
SELECT count(*) FROM people WHERE gcm_decrypt(name_gcm, :k) LIKE '%길%' AND id % 2 = 0;

-- When does a sort or a hash over decrypted text leave memory? work_mem is the default 4MB.
CREATE FUNCTION pg_temp.node_info(q text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  j json;
  p json;
BEGIN
  EXECUTE 'EXPLAIN (ANALYZE, TIMING OFF, FORMAT JSON) ' || q INTO j;
  p := j -> 0 -> 'Plan';
  RETURN concat_ws(', ', p ->> 'Node Type',
                   'method ' || (p ->> 'Sort Method'), (p ->> 'Sort Space Type') || ' ' || (p ->> 'Sort Space Used') || ' kB',
                   'peak memory ' || (p ->> 'Peak Memory Usage') || ' kB',
                   'disk ' || (p ->> 'Disk Usage') || ' kB',
                   'batches ' || (p ->> 'HashAgg Batches'));
END $$;
SELECT 'S7', 'work_mem', current_setting('work_mem');
SELECT 'S7', 'ORDER BY decrypted name, ' || n || ' rows',
       pg_temp.node_info(format('SELECT gcm_decrypt(name_gcm, %s) AS n FROM people WHERE id <= %s ORDER BY n', :'k', n))
FROM unnest(ARRAY[10000, 30000, 60000, 100000, 300000]) AS n;
SELECT 'S7', 'GROUP BY decrypted name, ' || n || ' rows',
       pg_temp.node_info(format('SELECT gcm_decrypt(name_gcm, %s) AS n, count(*) FROM people WHERE id <= %s GROUP BY 1', :'k', n))
FROM unnest(ARRAY[10000, 30000, 60000, 100000, 300000]) AS n;

-- What is in those temporary files? Hold a sorted cursor open and look, from the server's side.
SELECT pg_relation_filepath('people') AS relpath \gset
\setenv RELPATH :relpath
CHECKPOINT;
BEGIN;
DECLARE c NO SCROLL CURSOR FOR SELECT gcm_decrypt(name_gcm, :k) AS n FROM people ORDER BY n;
FETCH 1 FROM c \gset first_
SELECT 'S7', 'temporary files while the sorted cursor is open', count(*) || ' files, ' || coalesce(sum(size), 0) || ' bytes'
FROM pg_ls_tmpdir();
\! printf 'S7 | occurrences of the plaintext fragment "길동" in base/pgsql_tmp | %s\n' "$(cat "$PGDATA"/base/pgsql_tmp/* 2>/dev/null | grep -a -o '길동' | wc -l)"
\! printf 'S7 | occurrences of the plaintext fragment "길동" in the table file itself | %s\n' "$(grep -a -o '길동' "$PGDATA/$RELPATH" | wc -l)"
CLOSE c;
COMMIT;
