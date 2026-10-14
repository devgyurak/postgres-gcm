# Operational constraints

`pg_gcm` encrypts values inside PostgreSQL. It does not manage keys, connections or the server it
runs in, and it cannot protect against a deployment that breaks one of the rules below. Every item is
a condition of the deployment, not a suggestion; the rationale is in
[`docs/design.md`](design.md) §5 and §6. The same list, condensed, is on the first screen of
[`README.md`](../README.md).

1. **Keys and plaintext can appear in logs and statistics.** `log_statement`, `auto_explain`,
   `pg_stat_activity.query` and — because `log_min_error_statement` defaults to `error` — the log line
   of any statement that fails, including a forged-tag error. Send the key as a **bind parameter**, so
   the statement text holds `$1` — **and set `log_parameter_max_length = 0`**. Its default of -1 logs
   every bind value in full on the lines that `log_statement`, `log_min_duration_statement` and the
   sampling settings write, so a bind parameter alone does not keep a key out of the slow-statement
   log. Leave `log_parameter_max_length_on_error` at its default of 0. Do not run `auto_explain` on a
   database that takes key-bearing statements: from 16 it logs "Query Parameters", and on every major
   a custom plan's text contains the parameter values. `LIKE` patterns are plaintext fragments too.
2. **Never put a key literal in DDL.** Views, column defaults, check constraints, rules, triggers,
   function bodies and policies are stored in the catalog and dumped by `pg_dump`. Do not wrap these
   functions in a function declared `IMMUTABLE` to index them (design §5.3).
3. **Decrypted values can reach disk.** A sort or hash over `gcm_decrypt(...)` that exceeds `work_mem`
   writes plaintext to temporary files. Phase S saw it at the default `work_mem` of 4MB: a sort of
   10–15-byte names left memory somewhere between 30,000 and 300,000 rows depending on the major, and
   the temporary file held the names in the clear while the table file held none (design §8). Encrypt
   the volume that holds `temp_tablespaces`.
4. **The functions are opaque to the planner.** `WHERE gcm_decrypt(col, $1) LIKE ...` scans the
   candidate set; selectivity must come from other predicates. There is no index on decrypted values,
   by design (design §5.3).
5. **`gcm_encrypt_det` reveals equality, frequency and length, and costs more than the random
   variant** (two HMAC-SHA256 passes for the nonce). Use it only for join keys, UNIQUE constraints
   and exact-match lookups, never for free text. The AAD is an input to its nonce (design §8 O16), so
   it may differ from call to call; values sealed with different AADs do not compare equal, which is
   the point of binding a value to a row and the end of joining on it. **`gcm_decrypt` opens either
   variant**, so where the uniqueness of a deterministic column matters, give the column a check on
   the version byte — `CHECK (get_byte(col, 0) = 3)` for AES-256 — or, more weakly, a key or AAD
   that no random-nonce column shares. Otherwise a random-nonce envelope of the same value can be
   stored beside it. Every distinct pair of AAD and value is a nonce of its own, so a per-row AAD
   spends the key's usage budget (item 9) once per row.
6. **Self-managed PostgreSQL only.** Managed services do not load this extension.
7. **Install on every node that decrypts.** Streaming replicas get the extension's catalog entries
   through WAL but need the shared library installed on disk; a logical subscriber needs both.
8. **`pg_gcm.min_key_bytes` guards against a truncated key.** The key length picks the suite, so a
   32-byte key cut to 24 or 16 bytes is a valid key for a weaker suite and would seal without
   complaint. The default of 32 refuses that; lower it only to use a smaller suite on purpose.
   Decryption never consults it, so raising it again cannot lock out data written while it was lower.
9. **Usage budgets, rotation and recovery are the operator's responsibility.** Before deployment, set
   a usage budget that sums every use of a key across servers, columns and applications, and the
   criteria for rotating it. The extension counts nothing, rotates nothing and detects no repeated
   nonce, and this project states no universal safe limit. Use independent, full-length random keys
   per suite and security domain. Rotation changes deterministic ciphertext, so plan the migration of
   joined and UNIQUE columns and keep old keys for old data and backups. Restoring a backup does not
   reset usage; if the usage history or the random-number state of any writer is uncertain, stop
   writing under that key and resume with a new one (NIST SP 800-38D §8).
10. **The server must link OpenSSL 3.0 or later.** The official `postgres` images do. The PGDG packages
    for RHEL/Rocky 8 link 1.1.1 and are not supported. OpenSSL 3.0 itself left upstream support on
    2026-09-07; prefer a platform on 3.5.
11. **A NULL argument gives NULL, silently.** A key parameter that was never bound stores NULL instead
    of failing. Put `NOT NULL` on an encrypted column whose plaintext is never NULL.
12. **Protect the connection, and trust the server's administrators.** Every key and plaintext travels
    from the client to the server. Connect over a protected local socket, or over TLS **with the
    server's certificate verified** (`sslmode=verify-full`); without that, bind parameters and the log
    settings in item 1 leave them readable on the network, or deliverable to an impostor server. The
    database superuser and the operating-system administrator of every node that decrypts can observe
    them and must be trusted — the same limitation `pgcrypto` documents.
