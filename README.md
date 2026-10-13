# postgres-gcm

**AES-GCM for PostgreSQL, with `LIKE` on the decrypted value.**

> **Implemented to the specification, not released — not for use yet.** The envelope format is
> defined in [`spec/envelope.md`](spec/envelope.md) with test vectors beside it, and the extension on
> `develop` implements it: its unit suite runs every vector, its regression suite every envelope
> vector, and an end-to-end suite runs the functions on a primary and a streaming replica, on
> PostgreSQL 15–18. The release packaging is in place but no tag has been cut, and the format may
> change until 0.1.0. The plan, decisions and open questions are in [`docs/design.md`](docs/design.md);
> the working rules for people and coding agents are in [`AGENTS.md`](AGENTS.md).

PostgreSQL's `pgcrypto` has AES only in CBC, CFB and ECB, and OpenPGP; it has no AES-GCM. This
extension adds AES-128/192/256-GCM selected by key length, and keeps partial-match search inside the
server. It targets self-managed PostgreSQL 15–18 on a server that links OpenSSL 3.0 or later.

## Operational constraints

These are the conditions under which `pg_gcm` protects anything. The full rationale and the detail
behind each line are in [`docs/ops-constraints.md`](docs/ops-constraints.md); read that document
before deploying.

1. **Keys and plaintext can appear in logs and statistics.** Send the key as a **bind parameter** and
   set `log_parameter_max_length = 0`; do not run `auto_explain` on a database that takes key-bearing
   statements. `LIKE` patterns are plaintext fragments too.
2. **Never put a key literal in DDL.** Views, defaults, constraints, triggers, function bodies and
   policies are stored and dumped; do not wrap these functions in an `IMMUTABLE` function to index
   them.
3. **Decrypted values can reach disk.** A sort or hash over `gcm_decrypt(...)` that spills to
   `temp_tablespaces` writes plaintext; encrypt that volume.
4. **The functions are opaque to the planner.** `WHERE gcm_decrypt(col, $1) LIKE ...` scans the
   candidate set; get selectivity from other predicates. There is no index on decrypted values.
5. **`gcm_encrypt_det` reveals equality, frequency and length.** Use it only for join keys, `UNIQUE`
   and exact-match lookups, never free text; its AAD is part of its nonce, and a deterministic column
   that must stay unique wants a version-byte check on it.
6. **Self-managed PostgreSQL only.** Managed services do not load third-party C extensions.
7. **Install on every node that decrypts.** A replica gets the catalog entry through WAL but needs the
   shared library on disk; a logical subscriber needs both.
8. **`pg_gcm.min_key_bytes` guards against a truncated key.** Its default of 32 refuses a 32-byte key
   cut to a weaker suite; decryption never consults it.
9. **Usage budgets, rotation and recovery are the operator's responsibility.** Nothing is counted,
   rotated or detected; use independent full-length random keys per suite and keep old keys for old
   data and backups.
10. **The server must link OpenSSL 3.0 or later.** The official `postgres` images do; the PGDG RHEL/Rocky
    8 packages link 1.1.1 and are not supported.
11. **A NULL argument gives NULL, silently.** A key parameter that was never bound stores NULL; put
    `NOT NULL` on an encrypted column whose plaintext is never NULL.
12. **Protect the connection, and trust the server's administrators.** Use a local socket or TLS with
    `sslmode=verify-full`; the database superuser and the OS administrator of every node that decrypts
    can observe keys and plaintext.

## Support matrix

| | Supported |
|---|---|
| PostgreSQL | 15, 16, 17, 18 (19 is built and tested as a pre-release) |
| OpenSSL | 3.0 or later (the server's own `libcrypto`) |
| Architecture | amd64, arm64 |
| Deployment | self-managed PostgreSQL on disk (not managed services) |

## Install

From source, with the server's headers on the machine that builds (`postgresql-server-dev-<major>`):

```sh
make USE_PGXS=1
sudo make USE_PGXS=1 install
psql -c 'CREATE EXTENSION pg_gcm'
```

A `postgres:<major>` image with the extension preinstalled and `CREATE EXTENSION pg_gcm` in its init
script is built from [`docker/server.Dockerfile`](docker/server.Dockerfile) (see the `release`
workflow).

From a release tarball (`pg_gcm-<version>-pg<major>-<arch>.tar.gz`, from the `release` workflow),
which holds the built `pg_gcm.so`, the control file and the SQL scripts. Install it into the
server's own directories, then create the extension:

```sh
tar -xzf pg_gcm-<version>-pg<major>-<arch>.tar.gz
cd pg_gcm-<version>
sudo install -m 0644 pg_gcm.so "$(pg_config --pkglibdir)/"
sudo install -m 0644 pg_gcm.control sql/*.sql "$(pg_config --sharedir)/extension/"
psql -c 'CREATE EXTENSION pg_gcm'
```

PGXN and distribution packages are Phase 5.

## SQL surface

```sql
CREATE EXTENSION pg_gcm;

gcm_encrypt(plaintext text, key bytea [, aad bytea])      -- random nonce
gcm_encrypt_det(plaintext text, key bytea [, aad bytea])  -- deterministic: joins, UNIQUE, exact match
gcm_decrypt(ciphertext bytea, key bytea [, aad bytea])    -- text in the database encoding

SELECT id FROM patients WHERE gcm_decrypt(name_enc, $1) LIKE '%길%';
```

| Function | Returns | Volatility | Cost | Notes |
|---|---|---|---|---|
| `gcm_encrypt(text, bytea [, bytea])` | `bytea` | `VOLATILE` | 100 | Random nonce; two calls differ. |
| `gcm_encrypt_det(text, bytea [, bytea])` | `bytea` | `STABLE` | 200 | Deterministic; for joins, `UNIQUE` and exact match only. |
| `gcm_decrypt(bytea, bytea [, bytea])` | `text` | `STABLE` | 50 | Opens either variant; `pg_gcm.strict` decides error or NULL on a tag mismatch. |

All three are `STRICT` and `PARALLEL SAFE`, none is `IMMUTABLE`, and the `aad` argument is a second
overload rather than a default. `key` is 32, 24 or 16 bytes, and its length selects AES-256, AES-192
or AES-128. The envelope is defined in [`spec/envelope.md`](spec/envelope.md).

The GUCs: `pg_gcm.strict` (`PGC_USERSET`, default on) — on a tag mismatch, on gives an error and off
gives NULL; `pg_gcm.min_key_bytes` (`PGC_SUSET`, default 32) — the smallest key the two encryption
functions accept, which only a superuser (or a role granted `SET`) may lower.

## Documentation

- [`docs/design.md`](docs/design.md) — the design, decisions and open questions (Korean:
  [`docs/design-KO.md`](docs/design-KO.md)).
- [`docs/ops-constraints.md`](docs/ops-constraints.md) — the operational constraints in full.
- [`docs/perf.md`](docs/perf.md) — the load baseline and how it is measured.
- [`spec/envelope.md`](spec/envelope.md) — the byte format and its PostgreSQL binding.

## License

Licensed under the [PostgreSQL License](LICENSE).
