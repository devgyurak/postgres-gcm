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

