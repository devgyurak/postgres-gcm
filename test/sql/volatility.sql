-- Given: the installed extension
-- When: the declarations are read from pg_proc (not \df+, whose columns differ by major)
-- Then: each function has a two- and a three-argument form; gcm_encrypt is volatile and the
--       other two stable; none is immutable; all are strict and parallel safe, each with the
--       cost declared in the install script; and no argument has a default
\set VERBOSITY terse
SELECT p.proname, p.pronargs, p.provolatile, p.proisstrict, p.proparallel, p.procost,
       p.pronargdefaults
FROM pg_proc p
JOIN pg_depend d ON d.objid = p.oid AND d.deptype = 'e'
JOIN pg_extension e ON e.oid = d.refobjid AND e.extname = 'pg_gcm'
ORDER BY p.proname, p.pronargs;
