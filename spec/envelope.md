# The pg_gcm envelope

This document is the normative definition of the envelope: the byte string that `pg_gcm` stores in
place of a text value. Part 1 defines the format without reference to PostgreSQL, so that any
implementation can read and write it. Part 2 binds the format to PostgreSQL's SQL functions, types
and error codes. The rationale is in [`docs/design.md`](../docs/design.md); where the two disagree
about a byte, this document is right.

The worked examples below are vectors of [`test-vectors.json`](test-vectors.json).
`scripts/check-vectors.py` checks each against the vector it names: every run of twelve or more
hexadecimal digits, the bytes at each stated offset, the suite table and the outcomes table.

---

## Part 1 — The format

### 1.1 Notation

Bytes are written in hexadecimal. `a || b` is concatenation. `len(x)` is a length in bytes.
`x[i:j]` is the bytes of `x` from offset `i` up to, not including, offset `j`; offsets start at 0, and
`x[i:]` runs to the end. `be64(n)` is the integer `n` as eight bytes, most significant first.

### 1.2 Suites and version bytes

The first byte of an envelope is its **version byte**. It names the cipher and the variant.

| Version | Cipher | Key length | Variant |
|---|---|---|---|
| `0x02` | AES-256-GCM | 32 bytes | random nonce |
| `0x03` | AES-256-GCM | 32 bytes | deterministic nonce |
| `0x04` | AES-128-GCM | 16 bytes | random nonce |
| `0x05` | AES-128-GCM | 16 bytes | deterministic nonce |
| `0x06` | AES-192-GCM | 24 bytes | random nonce |
| `0x07` | AES-192-GCM | 24 bytes | deterministic nonce |

`0x01` is reserved for a legacy, unauthenticated AES-256-CBC layout. It is not part of this format:
no sealer produces it and every opener refuses it, as it refuses every value not in the table.

The key length selects the cipher and nothing else does. A key is used exactly as given: it is
never folded, padded, hashed or truncated to fit.

### 1.3 Layout

For a plaintext of `n` bytes, an envelope is `n + 29` bytes:

| Offset | Length | Field | Contents |
|---|---|---|---|
| 0 | 1 | version | A value from the table in 1.2 |
| 1 | 12 | nonce | The 96-bit GCM initialisation vector |
| 13 | n | ciphertext | The GCM ciphertext; the same length as the plaintext, possibly 0 |
| 13 + n | 16 | tag | The 128-bit GCM authentication tag |

The shortest envelope is 29 bytes and holds the empty plaintext. The nonce is always 12 bytes and the
tag always 16; no field carries a length, and none is variable but the ciphertext.

### 1.4 Inputs

- **key** — 16, 24 or 32 bytes.
- **plaintext** — a byte string. The format seals bytes. What a sealer accepts and what an opener
  does with authenticated bytes belong to its binding: Part 2 seals only the UTF-8 encoding of a
  text and refuses, after authentication, anything else.
- **aad** — the caller's additional authenticated data: a byte string, possibly empty. It is not
  stored in the envelope; the opener must be given the same bytes. Absent and empty are the same.

### 1.5 What is authenticated

The associated data handed to GCM is the version byte followed by the caller's `aad`:

```
A = version || aad
```

GCM authenticates the nonce by construction, and the ciphertext and `A` through the tag. Every byte
of an envelope is therefore covered: whichever byte is changed, the result opens only with the
probability of forging a 128-bit tag. In particular an envelope cannot be relabelled from one
variant to the other by someone who does not hold the key.

### 1.6 Sealing

Given a key, a plaintext `P`, an `aad` and a variant:

1. If `len(key)` is not 16, 24 or 32, fail with `bad_key_length`.
2. Take the version byte for that key length and variant from 1.2, and form `A` as in 1.5.
3. Choose the nonce: 12 bytes from a cryptographically secure random generator for the random
   variant, or the derivation of 1.8 for the deterministic one.
4. Compute `(C, T) = AES-GCM-Encrypt(key, nonce, A, P)` with a 128-bit tag.
5. The envelope is `version || nonce || C || T`.

### 1.7 Opening

Given a key, an envelope `E` and an `aad`, an opener makes these checks in this order. The first one
that fails is the outcome.

1. If `len(key)` is not 16, 24 or 32: `bad_key_length`.
2. If `len(E) < 29`, or `E[0]` is not a version byte of 1.2: `bad_envelope`.
3. If `len(key)` is not the key length of the suite `E[0]` names: `bad_key_length`.
4. Let `n = len(E) - 29`. Compute `AES-GCM-Decrypt(key, nonce = E[1:13], A = E[0] || aad,
   C = E[13:13+n], T = E[13+n:])`. If the tag does not verify: `bad_tag`. No byte of the decrypted
   data may be released, logged or left in a buffer the caller can read.
5. Otherwise the outcome is `ok` and the plaintext is the decrypted data.

Both variants open the same way. An opener does not recompute a deterministic nonce: an envelope
with version byte `0x03` and any nonce opens if its tag verifies (vector
`det-256-nonce-not-derived`).

A wrong key of the right length and a modified envelope are indistinguishable: both are `bad_tag`.

### 1.8 The deterministic nonce

`label` is the 19 ASCII bytes of `pg_gcm/v1/det-nonce`, with no terminator:
`70675f67636d2f76312f6465742d6e6f6e6365`.

```
nonce_key = HMAC-SHA256(key = key,       message = label)
nonce     = HMAC-SHA256(key = nonce_key, message = be64(len(A)) || A || P)[0:12]
```

`A` is the associated data of 1.5, so the nonce is a function of exactly what GCM will then
process: the version byte, the caller's `aad` and the plaintext. The length prefix makes the
message unambiguous — no two different pairs of (`A`, `P`) give the same message. The encryption key
is never used directly as the key of the HMAC over the plaintext.

What follows from that:

- Equal plaintexts with equal `aad` under one key give equal envelopes; change either and the
  nonce changes — barring a collision of the 96-bit derivation — and with it the ciphertext and the
  tag. The deterministic variant therefore reveals, for one key and one `aad`, equality and
  frequency, and always length. It is for join keys, uniqueness and exact-match lookups, never for
  free text.
- An `aad` may differ from call to call — a row or column identifier, for instance. Envelopes
  sealed with different `aad` values are simply unrelated, and no longer compare equal.
- **An opener accepts either variant.** Where the uniqueness of stored envelopes matters, the store
  itself must refuse the other variant: a random-nonce envelope of the same plaintext, sealed under
  the same key and `aad`, opens just as well and is a different byte string. The version byte says
  which variant an envelope is and cannot be changed without the key, so against a writer who does
  not hold the key a check on the first byte is enough. It is not a defence against a key holder,
  who can seal a second deterministic-labelled envelope of one plaintext with any nonce (1.7). A
  key or an `aad` that no random-nonce envelope is ever sealed with is a weaker substitute: nothing
  then refuses the foreign envelope when it is written; it fails when it is opened.

### 1.9 What the format does and does not give

- The plaintext length is visible: `len(P) = len(E) - 29`.
- A (key, nonce) pair must never be used for two different pairs of (`A`, `P`). The format makes
  that a matter of probability for both variants: a random nonce is 96 random bits, and a derived
  nonce is 96 bits of a keyed hash, so two different inputs collide with the same likelihood. Every
  seal under a key, of either variant, counts toward the same budget. This document states no
  limit: the operator sets a usage budget that sums every use of a key and decides when to rotate
  it.
- The derived nonce is neither of the IV constructions of NIST SP 800-38D, section 8.2, and a key
  used for both variants uses two where that section allows one. This document claims no
  conformance to section 8. It takes from it the requirement itself — one (key, IV) pair never on
  two distinct inputs — and from section 8.3 that a key's invocations be bounded.
- One GCM invocation takes at most 2^36 - 32 bytes of plaintext. A binding may be far stricter.
- An envelope carries no key identifier and no `aad`. Which key and which `aad` open it is the
  caller's knowledge.
- Authentication says the envelope was sealed by a holder of the key with that `aad`. It does not
  say which row or column it was sealed for unless the caller puts that into `aad`.

### 1.10 Worked examples

All three use the 32-byte key `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
and the plaintext `ed998deab8b8eb8f99`, the nine bytes of 홍길동 in UTF-8.

**Random variant, no `aad`** (vector `random-256-korean`). The nonce used was
`79034af827f85e657974d55b`, and `A` is the single byte 02.

| Field | Offset | Bytes |
|---|---|---|
| version | 0 | `02` |
| nonce | 1 | `79034af827f85e657974d55b` |
| ciphertext | 13 | `a059cc49a73a5de0c6` |
| tag | 22 | `58df1135eadd5cb99aac4f34dc6e24e6` |

Envelope, 38 bytes:
`0279034af827f85e657974d55ba059cc49a73a5de0c658df1135eadd5cb99aac4f34dc6e24e6`

**Deterministic variant, no `aad`** (vector `det-256-korean`). `A` is one byte, so the HMAC message
is the eight bytes 00 00 00 00 00 00 00 01, then 03, then the plaintext.

```
nonce_key = cc96adf399e906000670ad97411ee7f992f1564f2218782d7cc3d7a46daa09f1
A         = 03
nonce     = 1a49f653c2f84af97c389fb4
```

Envelope:
`031a49f653c2f84af97c389fb40907cb048f99a4719f083c9f401ed3f14ce55bca467eaff5b5`

**Deterministic variant, `aad` = the 13 ASCII bytes of `patients.name`** (vector `det-256-aad`).
`A` is 14 bytes, and because `A` is an input to the nonce, everything after the version byte differs
from the envelope above.

```
A         = 0370617469656e74732e6e616d65
nonce     = 6f766e445b3e1d4c8efc3140
```

Envelope:
`036f766e445b3e1d4c8efc3140a70414fdf040548355f081820b5a04d3731fba402eb8b648e9`

**Outcomes.** Starting from the first envelope above and the same key:

| Change | Vector | Outcome |
|---|---|---|
| Version byte 02 replaced by 03 | `version-02-as-03` | `bad_tag` |
| Last bit of the tag flipped | `tag-last-bit-flipped` | `bad_tag` |
| Opened with `aad` = `patients.name` | `aad-unexpected` | `bad_tag` |
| Last byte removed (37 bytes) | `last-byte-dropped` | `bad_tag` |
| Cut to 28 bytes | `envelope-28-bytes` | `bad_envelope` |
| Cut to 28 bytes, opened with a 16-byte key | `precedence-short-envelope-before-suite` | `bad_envelope` |
| Version byte replaced by 01 | `version-01-reserved` | `bad_envelope` |
| Opened with the first 16 bytes of the key | `key-16-bytes-for-aes-256` | `bad_key_length` |
| Opened with 31 bytes of key, envelope empty | `precedence-key-length-before-envelope` | `bad_key_length` |

### 1.11 Test vectors

`test-vectors.json` is an object with these members:

| Member | Meaning |
|---|---|
| `version` | `1`. Adding a member anywhere is a minor change; changing the meaning of one is a major change and a new `version` |
| `about`, `test_nonces` | Descriptions for a reader |
| `det_nonce_label` | The label of 1.8, as text |
| `nist_source` | Where the `nist` vectors came from: `url`, the `sha256` of that archive, and the day it was `retrieved` |
| `vectors` | The vectors |

Every binary value is lower-case hexadecimal in a member whose name ends in `_hex`; an empty string
is the empty byte string. Every vector has an `id`, unique in the file, a `kind` and an `expect`, and
may have a `note`.

**`kind: "nist"`** — a known answer for AES-GCM itself, taken unchanged from NIST's CAVP response
files. It is not an envelope: its associated data is NIST's, not `version || aad`. An implementation
runs it against the primitive it uses. Its `expect` is `ok`.

| Member | Meaning |
|---|---|
| `source` | The file, parameter set and count it was taken from |
| `key_hex`, `nonce_hex`, `aad_hex`, `plaintext_hex` | The inputs; `aad_hex` is the whole associated data |
| `ciphertext_hex`, `tag_hex` | The expected outputs |

**`kind: "random"` and `kind: "det"`** — an envelope and what opening it must give. `kind` is the
variant the envelope, or the envelope it was derived from, was sealed with.

| Member | Meaning |
|---|---|
| `key_hex` | The key presented to the opener |
| `aad_hex` | The caller's `aad` presented to the opener |
| `envelope_hex` | The envelope |
| `expect` | `ok`, `bad_tag`, `bad_envelope` or `bad_key_length`, as in 1.7 |
| `plaintext_hex` | When `expect` is `ok`: the plaintext |
| `nonce_hex` | When `expect` is `ok`: the nonce, `E[1:13]`. For `random` it is a fixed test value, not a random one (`test_nonces` says how it was chosen); a sealer under test must be given it to reproduce the envelope |
| `nonce_key_hex` | When `expect` is `ok` and `kind` is `det`: the nonce key of 1.8 |
| `nonce_derived` | Present and `false` on a `det` vector whose nonce is not the one 1.8 derives. An opener must open it; a sealer under test cannot reproduce it and skips it |
| `plaintext_class` | When `expect` is `ok`: `text` (UTF-8 with no U+0000), `contains_nul` (UTF-8 holding U+0000) or `not_utf8` |
| `derived_from` | When `expect` is not `ok`: the `id` of the valid vector it was made from |

An implementation conforms when every `nist` vector reproduces on its primitive; every envelope
vector opens to its `expect` and, when that is `ok`, to its plaintext; and, for every `ok` vector,
sealing its key, `aad` and plaintext gives its `envelope_hex` byte for byte — with `nonce_hex`
supplied for a `random` vector, and derived for a `det` vector unless `nonce_derived` is `false`.
The vectors exercise the format, which seals bytes: a binding that seals only text (Part 2) meets the
sealing half through whatever lets its tests seal bytes, and says what it does with the rest.

---

## Part 2 — The PostgreSQL binding

This part says how the `pg_gcm` extension presents Part 1 in SQL. It is normative for the extension
and irrelevant to any other reader or writer of the format.

### 2.1 Functions

| SQL | Part 1 |
|---|---|
| `gcm_encrypt(plaintext text, key bytea [, aad bytea]) → bytea` | 1.6, random variant |
| `gcm_encrypt_det(plaintext text, key bytea [, aad bytea]) → bytea` | 1.6, deterministic variant |
| `gcm_decrypt(ciphertext bytea, key bytea [, aad bytea]) → text` | 1.7 |

`[, aad bytea]` is two declarations of each function, never a default. The two-argument form is the
three-argument form with an empty `aad`: `gcm_encrypt_det(t, k)` and `gcm_encrypt_det(t, k, '')`
give the same envelope.

### 2.2 Keys

`key` is the `bytea` given, used as it is. Its length selects the suite (1.2). The two encryption
functions also refuse a key shorter than `pg_gcm.min_key_bytes` (default 32), so that a truncated key
cannot silently select a weaker suite. `gcm_decrypt` does not consult that setting.

### 2.3 NULL

Every function is `STRICT`: a NULL in any argument gives NULL, and nothing in Part 1 runs. NULL is
not an outcome of 1.7 and is not an `aad`; an empty `aad` is `''`.

### 2.4 Text

The plaintext of Part 1 is always UTF-8, whatever the database encoding.

- **Sealing.** The `text` argument is converted from the database encoding to UTF-8. A UTF8 database
  converts nothing. A SQL_ASCII database has no encoding to convert from, so the bytes are verified
  as UTF-8 and refused if they are not.
- **Opening.** After the tag has verified, the plaintext is verified as UTF-8 and converted to the
  database encoding. A UTF8 database and a SQL_ASCII database verify and convert nothing further.

The conversion is the default one in `pg_catalog`; a conversion in another schema is not used,
whatever `search_path` says. A database whose encoding has no default conversion to and from UTF-8
there cannot use the functions at all: every call fails with `42883` before anything is sealed or
opened.

Three plaintexts authenticate and are then refused. The first two can only come from an envelope
this extension did not seal:

| `plaintext_class` | The plaintext | Result of `gcm_decrypt` |
|---|---|---|
| `not_utf8` | is not valid UTF-8 | error, `22021` |
| `contains_nul` | holds U+0000, which `text` cannot | error, `22021` |
| `text` | holds a character the database encoding does not have | error, `22P05` |

None of these is a tag failure and `pg_gcm.strict` does not turn any of them into NULL.

### 2.5 Outcomes

When the outcome is `ok` and the plaintext is text the database can hold, the `text` is returned.
Everything else is one of these:

| What happened | SQLSTATE | Condition name | `pg_gcm.strict` |
|---|---|---|---|
| `bad_tag` | `XX001` | `data_corrupted` | **governs it**: an error when on (the default), NULL when off |
| `bad_envelope` | `22P03` | `invalid_binary_representation` | always an error |
| `bad_key_length`, or a key below `pg_gcm.min_key_bytes` | `22023` | `invalid_parameter_value` | always an error |
| Authenticated plaintext that is not UTF-8, or holds U+0000; SQL_ASCII text to seal that is not UTF-8 | `22021` | `character_not_in_repertoire` | always an error |
| A character with no equivalent in the target encoding | `22P05` | `untranslatable_character` | always an error |
| A value too long to seal or convert | `54000` | `program_limit_exceeded` | always an error |
| The database encoding has no default conversion to or from UTF-8 in `pg_catalog` | `42883` | `undefined_function` | always an error |
| OpenSSL could not complete the operation, or its algorithms could not be fetched | `XX000` | `internal_error` | always an error |

Each class of failure has a code of its own, so that a client can tell a forged envelope from a
mistyped key length. A class may cover more than one cause — `22021` has three — and no code is the
extension's alone: `42883` is also what an unknown function gives, and `XX001` is discussed below.
`pg_gcm.strict` governs `bad_tag` and nothing else; there is no third state. In particular a key of
the wrong suite for an envelope is `bad_key_length`, an error with `pg_gcm.strict` off too.

Why `bad_tag` is `XX001`, with what was observed on PostgreSQL 15 to 18
(`scripts/spike/sqlstate-handlers.sql`):

- An existing code was preferred to one of the extension's own, and among the existing ones a
  class-level code of class 22 would not do: in PL/pgSQL a handler for `SQLSTATE '22000'` or
  `data_exception` catches every class-22 error, a wrong key length included.
- `data_corrupted` is specific. A handler for it catches `XX001` and neither `XX000` nor `XX002`.
  The converse does not hold: a handler for `internal_error` catches the whole class, `XX001` too.
- It is not unique to this extension. The server raises `XX001` itself when it finds corrupted
  storage, so a client that must tell the two apart also reads the message.
- It sits in the internal-error class although the commonest cause is a wrong key, because Part 1
  cannot distinguish a wrong key from a modified envelope.

### 2.6 Messages

No error message, detail, hint or context carries a byte of a key, a plaintext, a nonce, a tag or a
ciphertext. Lengths, the version byte and the names of encodings are as far as a message goes.

### 2.7 Version byte `0x01`

Not implemented in 0.1. An envelope that begins with `0x01` is `bad_envelope`, whatever follows.

### 2.8 The vectors through SQL

| Vector | What SQL can check |
|---|---|
| `nist` | Nothing: there is no SQL function over the bare primitive and none takes a nonce. The unit suite runs them |
| `ok`, class `text` | `gcm_decrypt(envelope, key, aad)` is the text of `plaintext_hex` |
| `ok`, class `not_utf8` or `contains_nul` | `gcm_decrypt` raises `22021`, with `pg_gcm.strict` on or off |
| `ok`, `kind` `det`, class `text`, nonce derived | also: `gcm_encrypt_det(text, key, aad)` is `envelope_hex`, byte for byte |
| `ok`, `kind` `random` | sealing cannot be compared — the nonce is drawn inside — so `gcm_encrypt` is checked by property: length, version byte, two calls differ, round trip |
| `bad_tag` | an error `XX001` with `pg_gcm.strict` on, NULL with it off |
| `bad_envelope`, `bad_key_length` | the error of 2.5, with `pg_gcm.strict` on or off |

A vector's `aad_hex` is passed as the third argument; where it is empty, the two-argument form must
give the same result. Sealing a vector whose key is 24 or 16 bytes needs `pg_gcm.min_key_bytes` at or
below that length for the statement; opening one needs nothing.

### 2.9 A deterministic column

`gcm_decrypt` opens either variant (1.8). A deterministic column whose uniqueness matters therefore
carries a check on the version byte — for AES-256, `CHECK (get_byte(col, 0) = 3)` — so that a
random-nonce envelope of a value already present cannot be stored beside it by someone who can write
to the table but holds no key. The extension does not add or enforce that constraint.
