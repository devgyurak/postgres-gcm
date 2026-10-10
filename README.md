# postgres-gcm

**AES-GCM for PostgreSQL, with `LIKE` on the decrypted value.** The PostgreSQL sibling of
[mysql-gcm](https://github.com/devgyurak/mysql-gcm), sharing its envelope format.

> **Planning stage.** Nothing is implemented or published yet. The plan, decisions and open questions
> are in [`docs/design.md`](docs/design.md); the working rules for people and coding agents are in
> [`AGENTS.md`](AGENTS.md).

Planned SQL surface:

```sql
CREATE EXTENSION pg_gcm;

gcm_encrypt(plaintext text, key bytea [, aad bytea])      -- random nonce
gcm_encrypt_det(plaintext text, key bytea [, aad bytea])  -- deterministic: joins, UNIQUE, exact match
gcm_decrypt(ciphertext bytea, key bytea [, aad bytea])    -- text in the database encoding

SELECT id FROM patients WHERE gcm_decrypt(name_enc, $1) LIKE '%길%';
```

PostgreSQL's `pgcrypto` has AES only in CBC, CFB and ECB, and OpenPGP; it has no AES-GCM. This
extension adds AES-128/192/256-GCM selected by key length, keeps partial-match search inside the server,
and produces envelopes that mysql-gcm can open and vice versa. It targets self-managed PostgreSQL
15–18 on a server that links OpenSSL 3.0 or later.

Licensed under the [PostgreSQL License](LICENSE).
