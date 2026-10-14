-- SPDX-License-Identifier: PostgreSQL
-- Which PL/pgSQL handler catches which SQLSTATE: the observation behind the choice of XX001 for a
-- tag mismatch (docs/design.md §8 O7; spec/envelope.md §2.5). No extension is needed.
--   docker exec -i pg-gcm-dev-<major> psql -X -q -U postgres < scripts/spike/sqlstate-handlers.sql
\set VERBOSITY terse
DO $$
BEGIN
  -- A class-level code catches the whole class: a wrong key length (22023) lands here.
  BEGIN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'a key-length error';
  EXCEPTION WHEN SQLSTATE '22000' THEN
    RAISE NOTICE 'SQLSTATE ''22000'' handler caught %', SQLSTATE;
  END;
  BEGIN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'a key-length error';
  EXCEPTION WHEN data_exception THEN
    RAISE NOTICE 'data_exception handler caught %', SQLSTATE;
  END;
  -- data_corrupted is specific: XX001, and neither XX000 nor XX002.
  BEGIN
    RAISE EXCEPTION USING ERRCODE = 'XX001', MESSAGE = 'a tag mismatch';
  EXCEPTION WHEN data_corrupted THEN
    RAISE NOTICE 'data_corrupted handler caught %', SQLSTATE;
  END;
  BEGIN
    RAISE EXCEPTION USING ERRCODE = 'XX000', MESSAGE = 'an internal error';
  EXCEPTION WHEN data_corrupted THEN
    RAISE NOTICE 'data_corrupted handler caught %', SQLSTATE;
  WHEN OTHERS THEN
    RAISE NOTICE 'data_corrupted handler did not catch %', SQLSTATE;
  END;
  BEGIN
    RAISE EXCEPTION USING ERRCODE = 'XX002', MESSAGE = 'an index is corrupted';
  EXCEPTION WHEN data_corrupted THEN
    RAISE NOTICE 'data_corrupted handler caught %', SQLSTATE;
  WHEN OTHERS THEN
    RAISE NOTICE 'data_corrupted handler did not catch %', SQLSTATE;
  END;
  -- The converse does not hold: internal_error is the class and catches XX001 too.
  BEGIN
    RAISE EXCEPTION USING ERRCODE = 'XX001', MESSAGE = 'a tag mismatch';
  EXCEPTION WHEN internal_error THEN
    RAISE NOTICE 'internal_error handler caught %', SQLSTATE;
  END;
END $$;
