# PostgreSQL GCM 암호화 함수 (extension) — 설계와 절차

[English](design.md) | 한국어

> 이 문서는 `docs/design.md` 의 번역이다. 두 문서가 다르면 영어 문서가 맞고, 이 번역을 고친다.

상태: **Phase 1 완료** (2026-10-12). 봉투가 명세됐다 — `spec/envelope.md`, 그리고
`scripts/check-vectors.py` 가 재현하는 `spec/test-vectors.json` — 그리고 그 스파이크 (AES-256, AAD 없음,
`pg_gcm.strict`) 가 PostgreSQL 15~18 에서 빌드되고 점검을 통과한다 (§4, §8). **스파이크는 두 가지 점에서
명세보다 앞서 만들어졌다: version 바이트를 인증하지 않고, 결정적 nonce 를 평문만으로 유도한다** (§2.2).
스파이크가 봉인한 봉투는 명세대로는 열리지 않는다. Phase 2 가 코드를 명세에 맞춘다 (이슈 #19).
릴리스된 것은 없다. 설계가 기대는 PostgreSQL 동작에 관한 주장은 모두 §9 에 출처가 있거나, 근거와 함께
§8 에 기록되어 있거나, §8 "미확인" 목록에 있다. 이 계획은 2026-10-10 에 PostgreSQL 15~18 소스, 공식
이미지와 대조했고, 스파이크 실행과 명세 작성은 2026-10-12 에 했으며, 각각에서 확인된 것을 §8 에 적었다.

## 0. 목표와 범위

PostgreSQL 에 서버 안의 SQL 함수로 인증 암호화 AES-GCM 을 제공하고, 복호화한 값을 서버 자신의 `LIKE`
로 쓸 수 있게 하며, 문서화되고 version 이 붙은 봉투에 담는다.

범위 안: **서버가 OpenSSL 3.0 이상을 링크하는** 자체 운영 PostgreSQL 15~18 (19 는 출시되면, §8 O1)
을 위한 C extension (`pg_gcm`) 과 그 SQL API, GUC, 테스트, 릴리스 파이프라인, 문서.

범위 밖: 서드파티 C extension 을 올릴 수 없는 관리형 서비스, `EVP_CIPHER_fetch` 가 없는 OpenSSL 1.1.1
을 링크한 서버 (RHEL/Rocky 8 용 PGDG 패키지, §8), 키 관리·KMS·keyring 연동, 어떤 언어로든 암호화 SDK,
쿼리를 다시 쓰는 투명 암호화나 컬럼 단위 암호화, 암호문 검색용 인덱스.

## 1. 왜 필요한가

### 1.1 PostgreSQL 의 코어와 contrib 에는 SQL GCM 이 없다

대부분의 배포에 이미 있는 contrib 모듈 `pgcrypto` 가 주는 것은 다음과 같다.

- `encrypt()` / `decrypt()` — `aes` 를 `cbc`, `ecb` 모드로, PostgreSQL 18 부터는 `cfb` 로도. 인증이
  전혀 없다.
- `pgp_sym_encrypt()` — SHA-1 변조 검출 코드(MDC)가 붙는 OpenPGP 대칭 암호화. OpenPGP 의 의미로는
  인증이 되지만 GCM 은 아니고, "AES-GCM 을 쓰라"는 요구가 뜻하는 것도 아니다.

출처: PostgreSQL 18 `pgcrypto` 문서의 "Raw Encryption Functions" (§9), 그리고 15~18 과 19beta4 의
`contrib/pgcrypto/openssl.c` 암호 표 (§8). SQL Server 의 Always Encrypted 는 AEAD_AES_256_CBC_HMAC_SHA_256 을 쓰고 클라이언트 드라이버에서
복호화하며, secure enclave (SQL Server 2019 이상) 를 쓰면 enclave 안에서 패턴 매칭을 한다. Oracle 은
23ai 에서 `DBMS_CRYPTO` 에 `CHAIN_GCM` 을 추가했고, 19c 에는 없다.

규제 산업 — 이 프로젝트의 경우 헬스케어 — 은 저장된 개인정보에 인증 암호화를 점점 더 요구하고, 보통의
답은 AES-GCM 이다. 데이터베이스에 그것이 없으면 애플리케이션이 직접 암복호화한다.

### 1.2 애플리케이션에서 암호화하면 서버 쪽 검색을 잃는다

복호화 경로를 애플리케이션만 갖고 있으면, 암호화 컬럼에 대한 `WHERE name LIKE '%길%'` 은 SQL 로
불가능하다. 후보 행을 전부 애플리케이션으로 가져와 복호화하고 걸러야 한다. 이 프로젝트는 그 검색을
서버 안에 두려고 만든다. 복호화 결과가 DB 인코딩의 `text` 로 돌아오면
PostgreSQL 의 평범한 `LIKE`, `ILIKE`, 정규식, collation 이 새로 배울 것 없이 그대로 동작한다.

### 1.3 기존 extension 은 이 빈자리를 채우지 못한다

2026-10-10 에 확인했다 (저장소 메타데이터와 PGXN; 검색으로 "다른 것은 없다"를 증명할 수는 없다).

| 프로젝트 | 주는 것 | 답이 아닌 이유 |
|---|---|---|
| [pgsodium](https://github.com/michelp/pgsodium) | SQL 에서 쓰는 libsodium AEAD: ChaCha20-Poly1305-IETF, 결정적 XChaCha20-SIV, `crypto_secretbox`. PostgreSQL License, v3.1.11 (2026-06-10) | AES-GCM 이 없어 "AES-GCM 을 쓰라"는 요구를 채우지 못한다. Supabase 문서는 폐기 예정이라며 사용을 권하지 않는다 |
| [pgcrypsi](https://github.com/telkomdev/pgcrypsi) | 키를 인자로 받는 `pgcrypsi_aes_{128,192,256}_gcm_{encrypt,decrypt}`. MIT | 유지보수되지 않는다: 마지막 push 가 2023-09-11 이고, OpenSSL 1.1.1 과 `postgresql-server-dev-10` 기준이다 |
| pg_tde (Percona), pg_vault_tde | 저장 계층(table access method)의 암호화 | 저장 데이터의 투명 암호화다. SQL 함수가 없다 |

## 2. 무엇을 만드는가

### 2.1 함수 표면

```sql
gcm_encrypt(plaintext text, key bytea)                 RETURNS bytea  VOLATILE STRICT PARALLEL SAFE
gcm_encrypt(plaintext text, key bytea, aad bytea)      RETURNS bytea  VOLATILE STRICT PARALLEL SAFE
gcm_encrypt_det(plaintext text, key bytea)             RETURNS bytea  STABLE   STRICT PARALLEL SAFE
gcm_encrypt_det(plaintext text, key bytea, aad bytea)  RETURNS bytea  STABLE   STRICT PARALLEL SAFE
gcm_decrypt(ciphertext bytea, key bytea)               RETURNS text   STABLE   STRICT PARALLEL SAFE
gcm_decrypt(ciphertext bytea, key bytea, aad bytea)    RETURNS text   STABLE   STRICT PARALLEL SAFE
```

- extension 이름은 생태계의 `pg_` 관례를
  따라 `pg_gcm` 이고, GUC 는 라이브러리가 예약하는 `pg_gcm.` 접두사를 쓴다 (§5.6).
- **키 길이가 suite 를 고른다**: 32 → AES-256-GCM, 24 → AES-192-GCM, 16 → AES-128-GCM. 그 밖의
  길이는 오류이며, `key` 가 상수일 필요가 없으므로 호출마다 검사한다.
- **NULL 처리**: 어느 인자든 SQL NULL 이면 암호
  연산 없이 SQL NULL 이다. 그래서 모든 함수를 `STRICT` 로 선언하고, 서버가 함수를 부르지 않고 NULL 을
  돌려준다.
- **AAD 는 `DEFAULT NULL` 이 아니라 오버로드로 생략한다.** `aad` 를 생략한 호출은 암호화하고, 명시한
  NULL 은 전파되게 하려는 것이다. **NULL 기본값으로는 둘을 함께 얻을 수 없다.** `STRICT` 아래에서 기본값 NULL 은
  2 인자 호출이 아무것도 암호화하지 않고 NULL 을 돌려주게 만든다 (15~18 에서 재현, §8). 그렇다고 NULL
  을 "AAD 없음"으로 읽으려고 `STRICT` 를 빼면, 명시한 NULL — NULL 을 허용하는 컬럼, 바인딩하지 않은
  파라미터 — 이 조용히 AAD *없이* 봉인된다. 그 값은 원래 묶으려던 것 없이도 열리게 되고, 그 사실을
  알려 주는 것은 아무것도 없다. 오버로드 둘이면 2 인자 형태가 "AAD
  없음"이고, 3 인자 형태의 NULL `aad` 는 NULL 을 주며, 빈 `aad` (`''`) 는 2 인자 형태와 똑같이
  봉인한다.
  NULL 이 아닌 기본값으로도 둘을 함께 얻을 수 있다. `STRICT` 와 함께 쓴 `aad bytea DEFAULT ''` 는
  인자를 생략하면 빈 AAD 로 실행되고, 명시한 NULL 에는 여전히 NULL 을 돌려준다 (§8). 오버로드는 고른
  방식이지 유일하게 옳은 방식이 아니다. 표면을 인자 개수 둘로 두고, 설명해야 할 기본값 표현식을
  남기지 않는다.
- `STRICT` 의 귀결 하나를 함수를 문서화하는 모든 곳에 적는다. **키가 빠지면 오류가 아니라 NULL 이다.**
  평문이 NULL 일 수 없는 암호화 컬럼에는 `NOT NULL` 을 선언해, 바인딩하지 않은 키 파라미터가 NULL 을
  저장하는 대신 문장을 실패시키게 한다 (§6, 11 번).
- 함수마다 `COST` 를 명시한다: `gcm_decrypt` 50, `gcm_encrypt` 100, `gcm_encrypt_det` 200 으로, Phase S
  측정에서 나온 둥근 값이다 (§8). C 함수의 기본 비용은 1 이고 플래너는 한 스캔의 조건을 비용 순으로
  배열하므로, 명시하지 않으면 `gcm_decrypt(...) LIKE ...` 가 §6 4 번이 기대는 값싼 조건들 뒤에 놓이지
  않는다.
- 이진 평문(`bytea` 입력, `bytea` 출력)은 0.1 에 일부러 넣지 않는다. 첫 인자에서 `text` 와 `bytea` 를
  오버로드하면 타입 없는 리터럴이 모호해진다. 필요하면 개정을 거쳐 별도 이름(`gcm_encrypt_bytes`,
  `gcm_decrypt_bytes`)으로 넣는다.

### 2.2 봉투

봉투는 `version || nonce(12) || ciphertext || tag(16)` 이고, version 바이트 `0x02`~`0x07` 이 suite 와
변형을 나타낸다 (`AGENTS.md` §2). `spec/envelope.md` 가 규범 정의다. 바이트 오프셋
표, nonce 유도, hex 예시, 벡터 스키마를 담고, 어떤 구현이든 이 형식을 읽고 쓸 수 있도록 PostgreSQL
용어 없이 쓴다. PostgreSQL 바인딩 — SQLSTATE, 인코딩 규칙, 아래의 예외 — 은 같은 파일 안에 명확히
표시한 별도 부분이다.

**봉투의 모든 바이트가 인증된다.** GCM 에 주는 associated data 는 version 바이트 뒤에 호출자의 AAD 를
붙인 `version || aad` 다 (명세 §1.5; Phase 1 에서 결정, §8 O13). 그렇지 않으면 version 바이트가 tag
밖에 있는 유일한 바이트가 되고, 키 없이도 `0x03` 을 `0x02` 로 고쳐 같은 평문의 다른 봉투를 만들 수
있다. 결정적 nonce 는 바로 그 associated data 와 평문에서 유도하므로 (명세 §1.8; §8 O16), 결정적 키
하나로 AAD 값을 몇 가지든 쓸 수 있다.

봉투 안의 평문은 **UTF-8** 이다. `gcm_encrypt` 는 봉인 전에 인자를 DB 인코딩에서 UTF-8 로 변환하고,
`gcm_decrypt` 는 열린 바이트가 올바른 UTF-8 인지 확인한 뒤 DB 인코딩으로 변환한다 (어떻게 하는지,
그리고 왜 뻔한 서버 함수를 쓰지 않는지는 §5.7). UTF-8 DB(흔한 경우)에서는 변환이 일어나지 않는다.
평문 인코딩을 고정해 두면 봉투가 그것을 봉인한 데이터베이스에 묶이지 않는다.

**세 종류의 평문은 인증을 통과한 뒤에 실패하며**, `pg_gcm.strict` 가 가리지 않는 오류다. 앞의 둘은
이 extension 이 봉인하지 않은 봉투에서만 나올 수 있다.

1. U+0000 이 들어 있는 평문. PostgreSQL `text` 는 그것을 담지 못하고, UTF-8 검증은 지원하는 모든
   메이저에서 0 바이트를 거부한다 (§8).
2. UTF-8 이 아닌 평문.
3. UTF-8 이 아닌 DB 에서, DB 인코딩이 담을 수 없는 문자.

`0x01` 은 인증이 없는 레거시 AES-256-CBC dual-read 봉투 (`0x01 || iv(16) || CBC ciphertext`) 용으로
예약되어 있다. **0.1 은 이를 구현하지 않는다** (§8 O6, Phase S 에서 결정): 바이트는 할당된 채로 남고,
이 바이트를 가진 봉투는 잘못된 봉투로 실패한다. 걸림돌은 호환성이 아니다. `pgcrypto` 에서 32 바이트
키로 쓴 `encrypt_iv(data, key, iv, 'aes-cbc')` 는 PKCS#7 패딩의 AES-256-CBC 그대로라서,
`'\x01' || iv || …` 는 기존 pgcrypto 컬럼에 재암호화 없는 이관 경로를 줄 수 있다. 걸림돌은 보안
정책이다. 인증이 목적인 함수 뒤에 인증 없는 형식을 두게 된다. 나중에 구현하는 것은 이 문서의
개정이며, 이미 쓰인 어떤 봉투도 바꾸지 않는다.

구현한다면 두 조건이 따라오고, `0x01` 을 드러내는 모든 곳에 적는다.

- **앞에 붙이기만 하는 이관은 기존 평문이 이미 UTF-8 일 때만 성립한다.**
  `encrypt_iv` 는 `bytea` 를 받고 아무것도 변환하지 않으므로, LATIN1 바이트로 암호화한 컬럼 —
  `Müller` 가 `4D FC 6C 6C 65 72` — 은 열린 뒤 UTF-8 검증에서 실패한다. 시끄럽게 실패하지만,
  행마다 실패한다. 순수 ASCII 값은 통과하고
  나머지는 통과하지 못한다. 다른 인코딩의 데이터는 기존 방식으로 복호화하고, 변환한 뒤,
  `gcm_encrypt` 로 다시 봉인한다.
- **`0x01` 은 인증 보장의 예외다.** CBC 에는 tag 가 없다. IV 나 암호문 블록이 바뀌면 바뀐 평문이
  그대로 열리고, `pg_gcm.strict = on` 은 그것을 탐지하지 못하며, 틀린 키가 오류 대신 쓰레기를 돌려줄
  수 있다. 그래서 `0x01` 을 채택한다는 것은 이관이 끝난 뒤 그것을 어떻게 거부할지도 정한다는 뜻이다.
  기본은 그것을 애플리케이션에 맡기는 것이다. extension 안에 스위치를 두려면 새 GUC 와 개정이
  필요하다.

### 2.3 설정

```
# postgresql.conf — 정책만, 키 재료는 절대 넣지 않는다 (§5.4)
shared_preload_libraries = 'pg_gcm'   # 선택; 넣으면 아래 두 설정이 시작 때 검증된다
pg_gcm.strict = on
pg_gcm.min_key_bytes = 32
```

`pg_gcm.strict` 는 `PGC_USERSET` 이다. 어느 세션이든 자기 세션에 한해 완화할 수 있다.
`pg_gcm.min_key_bytes` 는 `PGC_SUSET` 이다. 낮추는 것은 관리자의
결정이고, PostgreSQL 15+ 에서는 `GRANT SET ON PARAMETER` 로 위임할 수 있다. 둘 다 호출마다 C 변수로
읽으며, PostgreSQL 이 backend 에 대해 그 값을 최신으로 유지한다. backend 는 단일 스레드 프로세스이므로
스레드 간 동기화 문제는 생기지 않는다.

preload 하지 않으면 라이브러리는 backend 에서 함수를 처음 부를 때 로드되고, 그때까지 `pg_gcm.*`
이름은 placeholder 다 (§8, 15~18 에서 확인).

- `SET` 은 어떤 값이든 어떤 철자든 받고, 그 뒤의 `SHOW` 는 검증되지 않은 그 값을 돌려준다.
  `SET pg_gcm.strict = off; SHOW pg_gcm.strict;` 는 extension 이 설치조차 안 된 서버에서 `off` 를
  찍는다. **`SHOW` 가 성공했다고 라이브러리가 로드됐거나 값이 검증됐다는 뜻이 아니다.** 한 번도
  설정하지 않은 이름만 실패한다 ("unrecognized configuration parameter").
- 라이브러리가 로드될 때, 권한 없는 role 이 설정해 둔 `pg_gcm.min_key_bytes` placeholder 는
  **WARNING 과 함께 버려지고 기본값 32 가 유지된다** — 미리 설정해 두는 방법으로 하한을 낮출 수 없다.
  철자가 틀린 이름은 WARNING 과 함께 제거된다.
- `postgresql.conf` 의 값은 로드 때 적용된다. 거기 있는 오타는 거부되지 않고, 라이브러리를 로드하는
  세션마다 경고만 난다.
- `ALTER SYSTEM SET pg_gcm.…` 은 15 와 16 에서는 그 세션에 라이브러리가 로드되어 있지 않으면 실패하고,
  17 과 18 에서는 검증 없이 받아들여진다.

서버가 시작할 때 설정을 검증받고 싶은 배포는 라이브러리를 preload 한다.

## 3. 한눈에 보는 extension

| 관심사 | 방식 |
|---|---|
| 패키징 | Extension, version-1 fmgr 함수, PGXS |
| 평문 인코딩 | 봉인 시 UTF-8 로 변환, 열 때 UTF-8 검증 후 되돌려 변환 |
| NULL 인자 | 어느 인자든 NULL 이면 NULL (`STRICT` 로) |
| ill-formed 평문 | 오류 (§2.2) |
| strict 범위 | 지원하는 모든 메이저에서 `PGC_USERSET` |
| 키 길이 하한 | `pg_gcm.min_key_bytes`, `PGC_SUSET` |
| 수명 | 라이브러리 로드(backend) / `FmgrInfo` (`fn_extra`) / operation |
| 오류 | 실패 종류별 SQLSTATE 를 붙인 `ereport(ERROR, errcode(...))` |
| 동시성 | backend 마다 프로세스 하나; 병렬 워커도 별도 프로세스 |
| 서버 테스트 | `pg_regress` (`make installcheck`) |
| 부하 기준선 | `pgcrypto` `decrypt()` (CBC) 와 `pgp_sym_decrypt()` |

## 4. 절차

### Phase S — 스파이크 (spec 전)

§8 의 미확인 질문에 답하는 가장 작은 extension 을 지원하는 메이저마다 만든다.

1. `postgres:<major>` 에, 이미지의 `PG_VERSION` 에 고정한 `postgresql-server-dev-<major>` 를 더한
   환경에서 PGXS 로 빌드해 `CREATE EXTENSION pg_gcm`.
2. AES-256 만, 무작위 nonce, AAD 없이 `gcm_encrypt`/`gcm_decrypt` — 측정하기에 충분한 만큼.
3. 길이가 틀린 키는 오류이고, `SET pg_gcm.strict = off` 이면 위조된 tag 가 NULL 이 된다.
4. `SELECT gcm_decrypt(gcm_encrypt('홍길동', k), k) LIKE '%길%'` 가 UTF-8 DB 에서도, `EUC_KR` DB 에서도
   참이다.
5. `shared_preload_libraries` 가 있을 때, postmaster 에서 fetch 한 핸들이 fork 된 두 backend 에서
   동작한다. AES-GCM 왕복과 HMAC-SHA256 nonce-key 벡터가 둘 다 통과하고 (O4), 두 backend 의 첫 무작위
   nonce 가 서로 다르다. 없을 때는 backend 에서 fetch 한 핸들에 대해 같은 것이 성립한다.
6. `EVP_CIPHER_CTX` 를 얻고 놓는 사이에 오류를 올릴 수 있는 호출이 없다. backend 안에서는 OpenSSL
   할당을 셀 방법이 없으므로 (§8), glue 의 구조와, 코어의 모든 오류 경로를 덮는 단위 테스트의 할당
   카운터로 이것을 보인다. `_PG_init` 에서 `CRYPTO_set_mem_functions` 가 돌려주는 값을 로그로 남겨
   그 사실을 기록해 둔다.
7. 30만 행에 대한 복호화 + LIKE 의 `EXPLAIN ANALYZE`, 정렬이나 해시가 복호화된 텍스트를 임시 파일로
   흘리는지, 그리고 `PG_TRY` 블록의 행당 비용 (O12).
8. 각 이미지에서 서버 바이너리를 arm64 뿐 아니라 amd64 에서도 `ldd` 한다 (O11).

모든 답을 그것을 만든 명령과 함께 §8 에 기록한다.

2026-10-12 에 15~18, 19beta4, 그리고 서버가 OpenSSL 3.0 을 링크하는 이미지에서 마쳤고, 답은 §8
"Phase S 에서 확인됨" 에 있다. 위에 적힌 단계와 다르게 한 것이 셋 있고, 이유는 §8 에 있다.
스파이크에 `gcm_encrypt_det` 가 들어 있다. 그 nonce 가 SQL 에서 HMAC 결과를 볼 수 있는 유일한
곳이기 때문이다 (5 단계). `CRYPTO_set_mem_functions` probe 와 `PG_TRY` 시간 측정은 extension 의
`_PG_init` 이 아니라 측정 전용 모듈에 있다 (6, 7 단계). 그리고 6 단계의 할당 카운터가 닿는 것은
할당 실패와 tag 불일치가 지나는 경로이지, EVP 호출이 겪을 수 있는 모든 실패가 아니다. 나머지는
구조로 보였다.

### Phase 1 — spec

`spec/envelope.md` 를 쓰고 `spec/test-vectors.json` 을 만든다. NIST CAVP GCM known-answer 테스트에 이
프로젝트의 자체 벡터를 더한 것이고, `scripts/check-vectors.py` 로 재현할 수 있다. PostgreSQL 바인딩을
별도 부분으로 더한다 (§2.2): 실패 종류별 SQLSTATE, 인코딩 규칙과 그것이 거부하는 평문, Phase S 에서
정한 `0x01` 결정, 그리고 평문이 UTF-8 이 아닌 벡터에 대해 SQL 계층이 기대하는 것.

2026-10-12 에 마쳤고, 답은 §8 "Phase 1 에서 확인됨" 에 있다. 처음 쓴 이 절과 다르게 된 것이 둘 있다.
version 바이트를 인증하면 (§2.2) NIST 벡터는 봉투가 아니다 — 그 associated data 는 `version || aad` 가
아니라 NIST 의 것이다 — 그래서 NIST known answer 는 단위 테스트에서 primitive 를 시험하고, SQL 은 이를
보지 않는다. "인증은 통과하고, 그다음 잘못된 UTF-8 오류" 는 평문이 UTF-8 이 아니거나 U+0000 을 담은
프로젝트 자체 벡터들이 대신 맡는다. 그리고 이 phase 는 넘겨받은 구성을 받아 적기만 하지 않았다. 명세
리뷰가 구성을 두 번 바꿨다: O13 과 O16.

### Phase 2 — 구현과 테스트

Phase 2 는 스파이크를 명세에 맞추는 일로 시작한다 (이슈 #19). version 바이트를 associated data 에 넣고,
결정적 nonce 도 associated data 에서 유도하고, 코어에 AAD 인자와 24 바이트, 16 바이트 suite 를 더하고,
스파이크 테스트의 인라인 known answer 를 단위 테스트와 회귀 테스트가 읽는 `spec/test-vectors.json` 으로
바꾼다.

코어(`gcm.c`, `envelope.c`, `nonce.c`)는 C11 이고 PostgreSQL 헤더를 포함하지 않는다. glue
(`fn_*.c`)는 인자, 인코딩, GUC, 오류를 다룬다. 단위 테스트는 서버 없이 모든 벡터로 코어를 돌리고,
`pg_regress` 가 SQL 동작을 덮는다. 호출 지점 단위의 키 스케줄 캐시는 기준선을 잰
뒤에 이 문서의 개정을 거쳐 넣으며, `flinfo->fn_extra` 와 키 사본을 지우는 메모리 컨텍스트 리셋
콜백을 쓴다. 그 개정은 수명 한계를 스스로 정해야 한다. `FmgrInfo` 는 한 문장보다
오래 살 수 있다 — PL/pgSQL 은 단순 표현식의 상태를 트랜잭션이 끝날 때까지 유지한다
(`pl_exec.c`, `shared_simple_eval_estate`).

### Phase 3 — SQL E2E

primary, 스트리밍 replica, Python 러너로 된 compose 파일: 왕복, 한국어 `LIKE`, 복제 (replica 가 자신이
암호화하지 않은 암호문을 읽는다), 그리고 NULL 인자가 NULL 을 주는 것.

### Phase 4 — 배포

메이저 × 아키텍처 빌드 매트릭스, 체크섬과 SBOM 이 붙은 tarball, extension 을 미리 설치한
`postgres:<major>` 이미지, README 와 `docs/ops-constraints.md`, 그리고 `docs/perf.md` 의 부하 기준선.

### Phase 5 — 생태계 (선택)

PGXN, 수요가 있으면 배포판 패키징.

## 5. 설계 결정과 근거

### 5.1 version-1 C 함수로 된 extension

서버를 고치지 않고 SQL 에서 부를 수 있는 네이티브 코드를 더하는 유일한 지원 방식이다.
`CREATE EXTENSION` 이 버전이 붙은 설치·업그레이드 스크립트를 주고, `DROP EXTENSION` 이 함수를 깔끔하게
지운다.

### 5.2 코어는 `ereport` 를 부르지 않는다, 그리고 glue 가 지우는 것

`ereport(ERROR)` 는 `longjmp` 로 빠져나가며 돌아오지 않는다. OpenSSL 이 할당한 `EVP_CIPHER_CTX` 는
PostgreSQL 메모리 컨텍스트가 추적하지 않으므로, 그것이 살아 있는 동안 오류가 나면 새고, 그 안의 키
사본은 지워지지 않는다. 그래서 코어는 오류 코드를 돌려주고, glue 가 모든 OpenSSL 자원을 해제하고 모든
비밀을 지운 뒤에 오류를 올린다. 오류 모델 때문에 이 경계는 필수다.
(`pgcrypto` 는 같은 문제를 ResourceOwner 콜백으로 푸는데, 그 API 가 15~16 과 17+ 에서
다르다. 오류를 올리는 호출을 그 구간 밖에 두는 쪽은 버전별 코드가 필요 없다.)

**지우기 규칙은 extension 이 만든 사본을, 그리고 그것만을 덮는다**: detoast 된 인자, 변환 버퍼, 작업
공간, 결과가 되기 전의 열린 평문.

- detoast 가 필요 없었던 인자는 executor 자신의 저장소다 — 캐시된 플랜의 상수, portal 의 파라미터 값,
  shared buffer 페이지의 튜플. **거기에는 절대 쓰지 않는다.** 제자리에서 지우면 캐시된 플랜의 키가
  0 이 되거나 테이블 페이지가 망가진다. 사본인지는 `PG_FREE_IF_COPY` 가 쓰는 방법
  (`PG_GETARG_POINTER` 와 포인터가 다른지)으로 판별한다.
- 결과 `text`, 호출자의 datum, 그리고 플래너가 `STABLE` 호출을 평가하며 만드는 사본 (§5.3) 은
  extension 의 손이 닿지 않는다. 서버가 우리를 위해 값을 detoast 할 때 쓰는 중간 버퍼 — 가져온
  조각들과 압축된 형태 — 도 마찬가지이고, 서버는 호출이 성공해도 이것들을 0 으로 지우지 않고
  해제한다. 지우기는 우리 버퍼에 대한 심층 방어이지, backend 메모리에 키 사본이 남지 않는다는
  보장이 아니다.
- 우리 자신의 비밀 사본을 쥔 채 아직 오류를 올릴 수 있는 glue 구간 — 이를테면 메모리 부족 때의
  `palloc` — 은 `PG_TRY` / `PG_FINALLY` 로 감싸서, 오류 경로에서도 사본이 지워지게 한다. 그런 블록
  안에는 살아 있는 OpenSSL 컨텍스트가 없다.

### 5.3 어떤 함수도 `IMMUTABLE` 이 아니다

`gcm_encrypt_det` 는 입력에 대해 결정적이므로 `IMMUTABLE` 이 자연스러워 보인다. 거부하는 이유는,
immutable 함수는 인덱스 표현식, 인덱스 조건절, 생성 컬럼, 파티션 키에 쓸 수 있고, 그러면 키가
카탈로그(`pg_index`, `pg_attrdef`)에 리터럴로 남아 `pg_get_indexdef` 로 읽히고 `pg_dump` 에 찍히기
때문이다. `gcm_decrypt(...)` 에 대한 표현식 인덱스는 평문을 인덱스에 저장하기도 한다. 게다가 `STABLE`
이 그냥 맞는 선언이다. 결과가 `pg_gcm.min_key_bytes` 와 `pg_gcm.strict` 에 따라 달라지기 때문이다.

`STABLE` 에서 세 가지가 따라 나오고, 각각 15~18 에서 확인했다 (§8).

- 결정적 변형이 쓸모를 유지한다. `WHERE det_col = gcm_encrypt_det($1, $2)` 는 암호문 컬럼의 btree
  인덱스를 쓸 수 있고, `VOLATILE` 함수였다면 쓸 수 없다.
- 플래너는 선택도를 추정하면서 상수나 바인드 인자를 가진 `STABLE` 함수를 실행할 수 있다. 그래서
  `gcm_decrypt` 오류가 단순한 `EXPLAIN` 이나 Bind 단계에서 나올 수 있고, 그 순간 플래너가 인자의 자기
  사본을 쥐고 있다.
- 장벽이 아니다. PostgreSQL 은 래퍼의 volatility 선언을 믿으므로, `gcm_decrypt` 를 `IMMUTABLE` SQL
  함수로 감싼 사용자는 그것에 인덱스를 걸 수 있다. 이것은 운영 제약 (§6, 2 번) 이고 extension 이 막을
  수 있는 일이 아니다.

### 5.4 키는 SQL 인자이고, 설정이 아니다

`postgresql.conf`, GUC, 테이블, 환경 변수에 키를 두지 않는다. 그 대가 —
문장이 있는 곳 어디서나 키가 보인다 — 는 운영 제약(§6)이며, 완화책은 extension 의 코드가 아니라 바인드
파라미터다.

서버 안에서 암호화하면 extension 이 옮길 수 없는 신뢰 경계가 그어진다. `pgcrypto` 가 스스로에 대해
문서화한 것과 같은 경계다 ("Security Limitations", §9). 키와 평문은 클라이언트 연결을 건너고, 관리자가
통제하는 서버의 메모리에 존재한다. 이 설계가 지키는 것은 저장된 컬럼, 백업, 그리고 암호문만 가진
replica 다. 보호되지 않은 연결, DB superuser, 서버의 OS 관리자로부터는 지키지 못한다 (§6, 12 번).

### 5.5 tag 불일치는 기본값에서 NULL 로 내려가지 않는다

strict 가 on 이면 오류, off 면 NULL 이다. 잘못된 봉투, 틀린 키 길이, 열기에 성공한
뒤의 잘못된 UTF-8 은 strict 와 상관없이 오류다.

### 5.6 GUC 접두사는 `pg_gcm.`

사용자 정의 GUC 의 접두사는 그것을 정의하는 라이브러리여야 `MarkGUCPrefixReserved("pg_gcm")` 가
적용된다. 그것으로 얻는 것은 들리는 것보다 좁다 (§2.3, §8). 라이브러리가 backend 에 로드된 뒤에는
`SET pg_gcm.strcit` 이 오류다. 그 전에는, 그리고 `postgresql.conf` 에서는, 오타가 placeholder 로
받아들여졌다가 로드 때 WARNING 과 함께 제거된다. 예약 접두사는 라이브러리 자신의 것이어야 하므로
더 짧은 `gcm.` 접두사는 쓰지 않는다.

### 5.7 서버가 메시지를 쓰게 두지 않는 인코딩 처리

뻔한 함수들이 틀린 함수다. `pg_any_to_server`, `pg_server_to_any`, `pg_verify_mbstr(..., noError =
false)` 는 실패를 알릴 때 문제 문자의 바이트를 최대 8 개까지 오류 메시지에 찍는다 (`invalid byte
sequence for encoding "UTF8": 0x…`, `character with byte sequence 0x… has no equivalent…`).
`gcm_decrypt` 에서 그 바이트는 복호화된 평문이고, 메시지는 클라이언트와 서버 로그로 간다. 또 이
함수들은 변환된 사본을 내부에서 할당하므로, 오류를 올릴 때 호출자에게는 지울 포인터가 없다.

그래서 glue 는 반환값으로 알리는 형태를 쓴다. 지원하는 모든 메이저에 있다 (§8).

- `pg_verify_mbstr(PG_UTF8, bytes, len, true)` — false 는 잘못된 UTF-8 이라는 뜻이고, 0 바이트도
  포함한다.
- `pg_do_encoding_conversion_buf(proc, src, dest, in, inlen, out, outlen, true)` 로 glue 가 할당한
  버퍼 (`inlen * MAX_CONVERSION_GROWTH + 1`, `MaxAllocSize` 에 대해 오버플로 검사) 에 변환한다. 검증에
  성공한 뒤에 반환한 개수가 `inlen` 보다 작으면 대상 인코딩이 담을 수 없는 문자가 있다는 뜻이다.
- 변환 프로시저는 `FindDefaultConversionProc` 로 얻는다. 카탈로그 조회라서 오류를 올릴 수 있다
  (메시지에 데이터는 없다). 비밀 사본이 생기기 전에 실행한다. 서버 자신의 클라이언트 인코딩 변환이
  그렇듯 `search_path` 를 통해 찾는다 (§8 O14).

| DB 인코딩 | `gcm_encrypt*` | `gcm_decrypt` |
|---|---|---|
| UTF8 | 바이트를 그대로 쓴다. 서버가 입력 때 검증했다 | 검증한 뒤 그대로 쓴다 |
| SQL_ASCII | UTF-8 로 검증한다. 바이트에 인코딩이 없으므로 UTF-8 이 아니면 오류다 | 검증한 뒤 그대로 쓴다 |
| 그 밖 | UTF-8 로 변환한다 | 검증한 뒤 DB 인코딩으로 변환한다 |

모든 실패는 glue 가 지우기를 마친 뒤에 올리며, 메시지에는 인코딩 이름과 길이만 들어간다.

### 5.8 `_PG_init` 은 fetch 를 먼저 하고, 오류를 올리지 않는다

`_PG_init` 은 GUC 를 등록하기 **전에** `EVP_CIPHER` 와 `EVP_MAC` 핸들을 fetch 하고, fetch 실패는
올리지 않고 기록만 한다. 그 뒤 함수 호출마다 OpenSSL 오류 분류로 실패한다. 라이브러리 로딩에 관한 두
사실이 이것을 요구한다 (§8). `shared_preload_libraries` 아래에서는 `_PG_init` 의 `ERROR` 가 postmaster
에게 치명적이라 서버가 뜨지 않는다. lazy 로딩에서는 `_PG_init` 이 돌아올 때까지 라이브러리가 로드된
것으로 표시되지 않으므로, `DefineCustom*Variable` 뒤의 `ERROR` 는 이후 모든 호출이 `_PG_init` 을 다시
돌려 "attempt to redefine parameter" 로 실패하게 만들고 진짜 원인을 가린다.

핸들은 코어 (`gcm.c`) 안의 static 이고 `gcm_init()` 이 fetch 한다. `_PG_init` 이 이를 부르고, 단위
테스트는 `main` 에서 부른다. 호출마다 여전히 찾는 것이 하나 있다. `EVP_MAC` 는 digest 를 이름으로
받으므로, 결정적 호출은 매번 `EVP_MAC_init` 에 SHA-256 이라는 이름을 넘긴다 (§8 O15).

핸들은 프로세스의 수명 동안 살고 해제하지 않는다. preload 중에 등록한 `on_proc_exit` 콜백은 backend
에서 실행되지 않고 — 자식이 postmaster 의 콜백을 버린다 — 어차피 프로세스가 끝나는 중이다.

## 6. 운영 제약 (초안 — Phase 4 에서 `docs/ops-constraints.md` 와 README 로 옮긴다)

1. **키와 평문이 로그와 통계에 나올 수 있다.** `log_statement`, `auto_explain`,
   `pg_stat_activity.query`, 그리고 — `log_min_error_statement` 의 기본값이 `error` 이므로 — 실패한
   모든 문장의 로그 줄, 위조된 tag 오류도 포함해서. 키는 **바인드 파라미터**로 보내 문장 텍스트에
   `$1` 만 남게 하고 — **`log_parameter_max_length = 0` 도 설정한다.** 기본값 -1 은 `log_statement`,
   `log_min_duration_statement`, 샘플링 설정이 쓰는 줄에 모든 바인드 값을 전부 남기므로, 바인드
   파라미터만으로는 키가 느린 문장 로그에 남는 것을 막지 못한다. `log_parameter_max_length_on_error`
   는 기본값 0 으로 둔다. 키가 실린 문장을 받는 DB 에서는 `auto_explain` 을 돌리지 않는다. 16 부터
   "Query Parameters" 를 찍고, 모든 메이저에서 custom plan 의 텍스트에 파라미터 값이 들어간다. `LIKE`
   패턴도 평문 조각이다.
2. **DDL 에 키 리터럴을 절대 넣지 않는다.** 뷰, 컬럼 기본값, check 제약, 규칙, 트리거, 함수 본문,
   정책은 카탈로그에 저장되고 `pg_dump` 에 찍힌다. 인덱스를 걸려고 이 함수들을 `IMMUTABLE` 로 선언한
   함수로 감싸지 않는다 (§5.3).
3. **복호화한 값이 디스크에 닿을 수 있다.** `gcm_decrypt(...)` 에 대한 정렬이나 해시가 `work_mem` 을
   넘으면 평문을 임시 파일에 쓴다. Phase S 에서 기본 `work_mem` 4MB 로 확인했다: 10~15 바이트
   이름의 정렬은 메이저에 따라 30,000 행과 300,000 행 사이 어딘가에서 메모리를 벗어났고, 임시
   파일에는 이름이 평문으로 있었지만 테이블 파일에는 없었다 (§8). `temp_tablespaces` 가 있는
   볼륨을 암호화한다.
4. **함수는 플래너에게 불투명하다.** `WHERE gcm_decrypt(col, $1) LIKE ...` 는 후보 집합을 스캔한다.
   선택도는 다른 조건에서 나와야 한다. 복호화한 값에 대한 인덱스는 설계상 없다 (§5.3).
5. **`gcm_encrypt_det` 는 같음, 빈도, 길이를 드러내고 무작위 변형보다 비싸다** (nonce 에 HMAC-SHA256
   을 두 번 돈다). 조인 키, UNIQUE 제약, 정확히 일치하는 조회에만 쓰고 자유 텍스트에는 쓰지 않는다.
   AAD 는 nonce 의 입력이므로 (§8 O16) 호출마다 달라도 된다. 서로 다른 AAD 로 봉인한 값은 같다고
   비교되지 않는데, 값을 행에 묶는다는 것이 바로 그 뜻이고 그 값으로 조인할 수 없게 된다는 뜻이기도
   하다. **`gcm_decrypt` 는 두 변형을 모두 연다.** 그래서 결정적 컬럼의 유일성이 중요하면 그 컬럼에
   version 바이트 검사를 건다 — AES-256 이면 `CHECK (get_byte(col, 0) = 3)` — 또는, 더 약한
   방법으로, 무작위 nonce 컬럼과 공유하지 않는 키나 AAD 를 쓴다. 그렇지 않으면 같은 값의 무작위
   nonce 봉투가 그 옆에 저장될 수 있다. AAD 와 값의 서로 다른 쌍마다 nonce 가 하나씩 쓰이므로,
   행마다 다른 AAD 는 키의 사용 예산 (9 번) 을 행마다 한 번씩 쓴다.
6. **자체 운영 PostgreSQL 만.** 관리형 서비스는 이 extension 을 올리지 않는다.
7. **복호화하는 모든 노드에 설치한다.** 스트리밍 replica 는 extension 의 카탈로그 항목을 WAL 로 받지만
   공유 라이브러리는 디스크에 따로 설치해야 한다. 논리 복제 구독자는 둘 다 필요하다.
8. **`pg_gcm.min_key_bytes` 가 잘린 키를 막는다.** 키 길이가 suite 를 고르므로, 24 나 16 바이트로
   잘린 32 바이트 키는 더 약한 suite 의 올바른 키이고 아무 말 없이 봉인된다. 기본값 32 가 그것을
   거부한다. 더 작은 suite 를 의도적으로 쓸 때만 낮춘다. 복호화는 이 값을 보지 않으므로, 다시 올려도
   낮았던 동안 쓴 데이터가 잠기지 않는다.
9. **사용 예산, 교체, 복구는 운영자의 책임이다.** 배포 전에, 한 키의 모든 사용을 서버·컬럼·
   애플리케이션에 걸쳐 합산하는 사용 예산과 교체 기준을 정한다. extension 은 아무것도 세지 않고,
   교체하지 않고, 반복된 nonce 를 탐지하지 않으며, 이 프로젝트는 보편적으로 안전한 한도를 제시하지
   않는다. suite 와 보안 영역마다 독립적인 전체 길이 무작위 키를 쓴다. 교체하면 결정적 암호문이
   바뀌므로 조인·UNIQUE 컬럼의 이관을 계획하고, 옛 데이터와 백업을 위해 옛 키를 보관한다. 백업을
   복원해도 사용량은 되돌아가지 않는다. 사용 이력이나 어느 writer 의 난수 상태가 불확실하면 그 키로
   쓰기를 멈추고 새 키로 재개한다 (NIST SP 800-38D §8).
10. **서버가 OpenSSL 3.0 이상을 링크해야 한다.** 공식 `postgres` 이미지는 그렇다. RHEL/Rocky 8 용 PGDG
    패키지는 1.1.1 을 링크하며 지원하지 않는다. OpenSSL 3.0 자체도 2026-09-07 에 상위 지원이 끝났으니
    3.5 를 쓰는 플랫폼을 권한다.
11. **NULL 인자는 조용히 NULL 을 준다.** 바인딩하지 않은 키 파라미터는 실패하는 대신 NULL 을 저장한다.
    평문이 NULL 일 수 없는 암호화 컬럼에는 `NOT NULL` 을 건다.
12. **연결을 보호하고, 서버의 관리자를 신뢰해야 한다.** 모든 키와 평문은 클라이언트에서 서버로
    이동한다. 보호된 로컬 소켓으로 접속하거나, **서버 인증서를 검증하는** TLS (`sslmode=verify-full`)
    로 접속한다. 그렇지 않으면 바인드 파라미터와 1 번의 로그 설정을 적용해도 키와 평문이 네트워크에서
    읽히거나 가짜 서버로 넘어갈 수 있다. 복호화하는 모든 노드의 DB superuser 와 OS 관리자는 그것을 볼
    수 있으므로 신뢰할 수 있어야 한다 — `pgcrypto` 가 문서화한 것과 같은 한계다.

## 7. 라이선스 — PostgreSQL License (2026-10-10 확정)

전문은 `LICENSE` 에 있고, 모든 소스 파일에 `SPDX-License-Identifier: PostgreSQL` 을 단다.

- **PostgreSQL License 를 고른 이유.** PostgreSQL 자체와 대부분의 contrib 모듈의 라이선스라서, 배포판이
  패키징하고 PGXN 에 올리고 커뮤니티가 읽는 데 라이선스 문제가 생기지 않는다. 짧은 허용 라이선스이고,
  OpenSSL 3 의 Apache-2.0 과 호환된다.
- **Apache-2.0 이 아닌 이유.** 특허 허여가 실질적인 장점이지만, 이 프로젝트는 공개되고 특허 부담이 없는
  구성(AES-GCM, HMAC-SHA256)을 구현하고 특허를 갖고 있지 않으며, 호스트 프로젝트에 맞추는 쪽이 더
  중요했다.

## 8. 확인된 사실 / 미확인 질문

### 확인됨 (출처 포함)

따로 적지 않으면 "소스"는 2026-10-10 시점 각 stable 브랜치 끝의 PostgreSQL 트리 (15.19, 16.15, 17.11,
18.6; 줄 번호는 `REL_17_STABLE`) 이고, "실행"은 같은 날 linux/arm64 에서 공식 `postgres:15`~`18`
이미지에 `psql` 로 돌린 것이다.

- 라이선스: PostgreSQL License (§7, `LICENSE`).
- `pgcrypto` 원시 암호화는 `bf` 와 `aes` 를 `cbc`, `ecb` 로, 18 부터는 `cfb` 로도 지원한다 (커밋
  9ad1b3d01). 15~18, 19beta4, master 어디에도 GCM 이나 AEAD 모드는 없다. PGP 함수는 SHA-1 MDC 를
  붙인다. (소스: `contrib/pgcrypto/openssl.c` 의 암호 표, `pgcrypto.sgml`, 18 릴리스 노트.)
- **O2 — 링크된 OpenSSL.** `postgres:15`~`18` (Debian trixie) 은 OpenSSL 3.5.7, `-alpine` 변형은
  3.5.8, `postgres:17-bookworm` 은 3.0.22 를 링크한다. Rocky 8 의 PGDG 서버는 15 와 18 모두
  `libcrypto.so.1.1` 을 링크한다. (실행: `ldd $(which postgres)` 와 `openssl version`, arm64 만 —
  amd64 는 O11.)
- **O3 — fork 뒤의 RAND.** OpenSSL 3 은 fork 된 자식에서 DRBG 를 다시 시드한다. `drbg.c` 가 generate
  마다 fork id (`getpid()`) 를 비교하며, 3.0 과 3.5 모두 그렇다. PostgreSQL 15~17 은 자식마다
  `RAND_poll()` 도 부른다 (`fork_process.c`). 18 은 부르지 않고 OpenSSL ≥ 1.1.1 에 맡긴다. (소스만.
  OpenSSL 매뉴얼은 이 동작을 문서화하지 않으므로 Phase S 5 단계에서 여전히 확인한다.)
- **O5 — 변환할 수 없는 문자.** 치환이 아니라 오류 (`22P05`) 이고, 0 바이트는 모든 메이저에서 UTF-8
  검증에 실패한다 (`22021`). 다만 기본 함수들은 문제 바이트를 메시지에 넣는다 (`mbutils.c:1851`,
  `:1898`). 그래서 §5.7 이 있다. (소스.)
- **noError 형태는 15~18 에 있다.** `pg_verify_mbstr(int, const char *, int, bool noError)` 와
  `pg_do_encoding_conversion_buf(Oid, int, int, unsigned char *, int, unsigned char *, int, bool
  noError)` (`mb/pg_wchar.h`; 후자는 14 부터). `pg_unicode_to_server_noerror` 는 16+ 에만 있고 쓰지
  않는다. (소스.)
- **detoast 되지 않은 인자는 executor 의 저장소다.** `pg_detoast_datum_packed` 는 압축됐거나 외부에
  있는 값만 복사한다. `Const` 는 플랜 트리의 datum 이고, 바인드 파라미터는 portal 컨텍스트에 살며,
  컬럼 값은 버퍼 페이지를 가리킨다. `xfunc.sgml`: "Never modify the contents of a pass-by-reference
  input value". (소스: `fmgr.c`, `execExpr.c`, `execTuples.c`.)
- **O8 — 누수 게이트.** `CRYPTO_set_mem_functions` 는 OpenSSL 이 무엇이든 할당한 뒤에는 0 을 돌려주고
  (`crypto/mem.c`, `allow_customize`), postmaster 는 preload 라이브러리를 올리기 전에 `RAND_bytes` 를
  부르므로, backend 안에서는 할당 카운터를 설치할 수 없다. `USE_VALGRIND` 없이 빌드한 서버의 valgrind
  는 거짓 양성을 낸다 (`pg_config_manual.h`). 공식 이미지는 `USE_VALGRIND` 로 빌드되어 있지 않다. 게이트는 단위
  테스트의 할당 카운터다. (소스; OpenSSL 3.0 과 3.5.)
- **O9 — 병렬 워커.** 워커는 리더의 라이브러리를 로드한 다음 기본값이 아닌 모든 GUC 를 복원하며,
  사용자 정의, `PGC_SUSET`, `SET LOCAL` 값도 포함한다 (`parallel.c:1446-1457`; `guc.c` 의
  `can_skip_gucvar`). (소스, 그리고 15~18 에서 세션 값과 `SET LOCAL` 값으로 실행.)
- **O10 — TAP 테스트.** `postgresql-client-<major>` 가 15~18 과 19beta4 에 대해 `pg_regress`,
  `enable_tap_tests = yes` 인 PGXS 의 `Makefile.global`, `PostgreSQL::Test::Cluster` 를 싣고 있다. TAP
  실행에는 `libipc-run-perl` 과 root 가 아닌 사용자도 필요하다. (2026-10-09 에 PGDG 패키지를 풀어서
  확인; 실행하지는 않았다.)
- **`STRICT` 와 NULL 기본값.** `aad DEFAULT NULL` 로 선언한 `STRICT` 함수는 `aad` 를 생략하면 NULL 을
  돌려준다 — 기본값이 보통 인자처럼 채워지므로 strict 검사가 NULL 을 본다. 오버로드 둘이면 2 인자
  본문이 호출되고, 명시한 NULL 은 NULL 을 준다. (15~18 에서 실행: 임시 `LANGUAGE sql STRICT` 함수 셋,
  `f(a, b DEFAULT NULL)`, `g(a)`, `g(a, b)`. `f('x')` 는 NULL, `g('x')` 는 NULL 이 아니고,
  `g('x', NULL)` 은 NULL 이다. 넷째 `h(a, b bytea DEFAULT '')` 는 생략하면 길이 0 인 `b` 로 실행되고
  `h('x', NULL)` 에는 NULL 을 준다.)
- **Placeholder.** 라이브러리가 로드되기 전에 `SHOW` 는 placeholder 에 설정된 값을 그대로 돌려주고,
  한 번도 설정하지 않은 이름에만 오류를 낸다 (15~18 에서 실행: extension 을 설치하지 않은 채
  `SET pg_gcm.strict = off; SHOW pg_gcm.strict;` 가 `off` 를 찍는다). 라이브러리가 로드되기 전에 권한
  없는 role 이 설정한 `pg_gcm.min_key_bytes` 값은
  `WARNING: permission denied to set parameter` 와 함께 버려지고 기본값이 유지된다. 로드 전에 설정한
  틀린 철자의 이름은 WARNING 과 함께 제거되고, 로드 뒤에 설정하면 오류다. 설정 파일은 예약 접두사
  검사를 받지 않는다. 알 수 없는 두 부분 이름에 대한 `ALTER SYSTEM` 은 15~16 에서 오류이고 17~18
  에서 받아들여진다. (소스: `guc.c:5001-5021`, `:1115`, `:1144-1160`, `:5305-5322`. 15~18 에서
  코어에 있는 lazy 로딩 `PGC_SUSET` 변수 `plpgsql.variable_conflict` 로 실행: `SET`, 그다음
  `DO $$ BEGIN END $$`, 그다음 `SHOW`.)
- **Volatility.** 인덱스 표현식과 조건절, 생성 컬럼, 파티션 키에는 `IMMUTABLE` 이 필요하다. `STABLE`
  함수를 감싼 `IMMUTABLE` 래퍼는 인덱스에 받아들여진다. 플래너는 추정할 때 상수나 바인드 인자를 가진
  `STABLE` 함수를 평가하므로 (`clauses.c:3816`) `EXPLAIN` 만으로 그 오류가 날 수 있다. `STABLE`
  호출은 인덱스 비교값으로 쓸 수 있고 `VOLATILE` 호출은 쓸 수 없다 (`indxpath.c`). (소스, 그리고
  15~18 에서 실행.)
- **바인드 파라미터 로깅.** `log_parameter_max_length` 의 기본값은 -1, `log_parameter_max_length_on_error`
  는 0 이다 (`guc_tables.c:3054-3073`). 문장 로깅 경로는 전자가 0 이 아니면 `Parameters:` 를 붙인다
  (`postgres.c:2506-2512`). `auto_explain.log_parameter_max_length` 는 16 부터 있다. (소스. 기본값은
  16 의 `pg_settings` 에서도 읽었다. 로그 줄 자체를 만들어 보지는 않았다.)
- **`_PG_init`.** 예외 스택이 없는 `ERROR` 는 `FATAL` 로 승격되고 (`elog.c:378-384`), preload 에서는
  그것이 postmaster 다. `dfmgr.c:287-296` 은 `_PG_init` 이 돌아온 뒤에야 라이브러리를 목록에 넣는다.
  `InitPostmasterChild` 는 `on_exit_reset()` 을 부른다 (`miscinit.c:129`). (소스.)
- **16 의 헤더 변경.** `VARDATA_ANY`, `VARSIZE_ANY_EXHDR`, `SET_VARSIZE` 가 `varatt.h` 로 옮겨 갔고,
  `postgres.h` 와 `fmgr.h` 는 그것을 include 하지 않는다. glue 는 `pgcrypto.c` 처럼
  `PG_VERSION_NUM >= 160000` 아래에서 include 한다. `MarkGUCPrefixReserved` 는 15 부터 있다. (소스.)
- **조건 순서.** C 함수의 기본 비용은 1 이고 (`functioncmds.c`) `order_qual_clauses` 는 비용으로
  정렬한다. (소스, 18.)
- **`\df+` 는 메이저마다 다르다.** 15 는 "Source code", 16~17 은 "Internal name" 을 찍고, 18 은
  "Leakproof?" 를 더한다 (`describe.c`). volatility 테스트는 대신 `pg_proc` 을 읽는다. (소스.)
- **`pg_regress` 와 `\c`.** `pg_regress` 는 `--encoding` 을 주지 않으면 `PGCLIENTENCODING` 을 지우고,
  psql 은 `\c` 뒤에 새 DB 의 인코딩을 클라이언트 인코딩으로 삼는다. `--load-extension` 은
  `pg_regress` 가 만드는 DB 에만 적용된다. (소스: `pg_regress.c`, `psql/command.c`; Phase S 에서 17 로
  실행했다, 아래.)

### Phase S 에서 확인됨 (2026-10-12)

여기서 "실행"은 linux/arm64 에서 이 저장소의 스크립트를 `docker/versions.json` 의 digest 고정
이미지에 돌린 것이다: `postgres:15`~`18` (15.19, 16.15, 17.11, 18.6; OpenSSL 3.5.7),
`postgres:19beta4`, `postgres:17-bookworm` (17.11; OpenSSL 3.0.22). 따로 적지 않으면 여섯 이미지에서
결과가 같았다. 이미지 `M` 마다 명령은 `scripts/build-in-docker.sh M`, `scripts/unit-in-docker.sh M`,
`scripts/dev-up.sh M`, `scripts/verify.sh M` (1~6 단계), `scripts/spike/measure.sh M` (7 단계, O6,
O8, O12), 그리고 `scripts/spike/ldd.sh all` (8 단계) 이다.

- **1~4 단계 통과.** PGXS 빌드는 `-Wall -Wextra -Werror` 에서 경고가 없고, `ldd` 로 보면 서버와
  `pg_gcm.so` 가 같은 `libcrypto.so.3` 을 쓴다. `CREATE EXTENSION` 은 0.1.0 을 설치한다.
  `pg_regress` 파일 14 개가 통과하고, `scripts/verify.sql` 의 점검 35 개도 라이브러리를 지연
  로드했을 때와 preload 했을 때 각각 통과한다. 32 바이트가 아닌 키는 오류다. 위조된 tag 는
  `pg_gcm.strict` 가 on 이면 오류, off 면 NULL 이고, 잘린 봉투, 구현하지 않은 version 바이트, 인증은
  되지만 텍스트가 아닌 평문 (GCM 명세의 테스트 케이스 14: 0 바이트 16 개) 은 off 에서도 오류다.
  복호화한 값에 대한 `LIKE '%길%'` 은 UTF8 DB 와 `EUC_KR` DB 에서 모두 참이다. `EUC_KR` DB 는 6
  바이트 텍스트를 UTF-8 9 바이트로 봉인하고 같은 결정적 nonce 를 유도하며, 두 DB 는 서로가 봉인한
  것을 열고, `EUC_KR` 이 담을 수 없는 문자는 그 바이트가 메시지에 없는 오류다. SQL_ASCII DB 는 UTF-8
  이 아닌 바이트의 봉인을 거부한다. `pg_gcm.strict = off` 인 병렬 스캔은 모든 워커에서 NULL 을
  돌려준다 (O9, 이제 실제 변수로 확인).
- **O4 — fork 뒤의 핸들.** 동작한다. `shared_preload_libraries = 'pg_gcm'` 이면 backend 의 첫 호출
  전부터 `pg_gcm.strict` 가 실제 변수이고 (라이브러리를 postmaster 가 로드했다), 두 backend 각각에서
  AES-256-GCM 왕복이 성공하며 `00..1f` 키로 `'홍길동'` 의 결정적 nonce 가 Python `hmac` 이 내는 값
  `f55369153b2a94fcbc9b633f` 이다. backend 가 상속하는 것은 fetch 한 `EVP_CIPHER` 와 `EVP_MAC` 이다.
  backend 가 직접 라이브러리를 로드할 때도 같다.
- **O3, 실행.** preload 여부와 관계없이 모든 실행에서 두 backend 의 첫 랜덤 nonce 가 달랐다.
- **O6 — `0x01`.** 호환성: 맞는다. `pgcrypto` 의 `encrypt_iv(convert_to('홍길동','UTF8'), key32, iv,
  'aes-cbc')` 는 16 바이트를 내고, `openssl enc -d -aes-256-cbc -K … -iv …` 가 그것을 `홍길동` 으로
  연다. PKCS#7 패딩을 쓴 AES-256-CBC 그대로다. (extension 의 CBC 경로가 아니라 OpenSSL 자체 명령으로
  열었다.) 결정: 0.1 에서는 구현하지 않고 바이트는 예약으로 둔다 (§2.2). 이를 뒤집는 것은 설계
  개정이며 어떤 봉투도 깨지 않는다.
- **O7 — SQLSTATE, 스파이크가 정한 데까지.** 스파이크는 키 길이에 `22023`, 잘못된 봉투에 `22P03`,
  tag 불일치에 `XX001`, UTF-8 이 아닌 텍스트에 `22021`, 변환할 수 없는 문자에 `22P05`, 너무 긴 값에
  `54000`, OpenSSL 실패에 `XX000` 을 올린다. 모두 15~18 의 `errcodes.txt` 에 있고, 회귀 테스트가
  그중 넷을 되읽는다. 하나는 여기서 미결로 두었다가 아래 Phase 1 에서 확정했다: `XX001` 은 가장 흔한
  운영 실패인 틀린 키를 내부 오류 분류에 넣는다.
- **O8, 실행.** `CRYPTO_set_mem_functions` 는 preload 하는 postmaster 에서도, 첫 호출에 로드하는
  backend 에서도 0 을 돌려줬다 (probe 모듈의 `_PG_init`; 로그에 남고 SQL 로 읽을 수 있다). 단위
  테스트에서는 `main` 에서 가장 먼저 불러 1 을 돌려준다. 한 번의 호출은 봉인에 2 번, 열기에 2 번,
  결정적 봉인에 13 번 (3.0.22 에서는 19 번) OpenSSL 할당을 한다. 테스트는 처음 32 번의 할당을 하나씩
  거부한다: 모든 호출이 가져간 것을 전부 돌려주고, 그 실패를 tag 불일치로 보고하지 않으며, 올바른
  출력이나 지워진 버퍼만 남긴다. **이것이 실행하지 못하는 것:** 컨텍스트가 살아 있는 동안 다른
  이유로 실패하는 EVP 호출. 그 출구들은 구조에 기댄다 — 함수마다 `done:` 레이블 하나, 컨텍스트
  획득과 그 레이블 사이에 `return` 없음 — 이것은 `scripts/check-architecture.py` 가 강제한다. 6
  단계는 거기까지만 보인 것이다.
- **O11 — amd64.** amd64 에서도 15~18 과 19beta4 의 `postgres` 는
  `/lib/x86_64-linux-gnu/libcrypto.so.3` 을 링크하고 `openssl version` 은 3.5.7 로 arm64 와 같다.
  `17-bookworm` 은 양쪽 모두 3.0.22 다.
- **O12 — `PG_TRY`.** `PG_TRY` / `PG_FINALLY` 블록 하나는 호출당 수 ns 다. 열 번의 실행 대부분에서
  2~7 ns 였고 (블록이 있는 함수와 블록이 없는 같은 함수를 300만 번씩 호출), 한 번은 0 보다 작게
  읽혔다 — 차이가 잡음 수준이다. 복호화 + `LIKE` 한 행의 많아야 2% 정도다. 부하 게이트를 바꾸지
  않는다.
- **7 단계 — 비용.** 10~15 바이트 한글 이름 30만 행, backend 하나, JIT 끔: `gcm_decrypt(...) LIKE
  '%길%'` 은 맨 스캔 위에 행당 0.30~0.41 µs, `gcm_encrypt` 는 0.64~1.00 µs, `gcm_encrypt_det` 는
  0.99~1.18 µs, `pgcrypto` 의 `convert_from(decrypt_iv(..., 'aes-cbc'), 'UTF8') LIKE` 는 0.58~0.68
  µs 다. GCM 쿼리는 CBC 쿼리의 0.49~0.63 배가 든다. 비용 1 짜리 연산자 단위로는 답이 거칠다.
  `int4ge` 조건 하나는 수 ns 로 이 실행들의 잡음 수준이라 (1~11 ns 로 읽혔다) 비율은 2~3 배까지만
  믿을 수 있다 — 잣대가 버틴 네 번의 실행에서 복호화 37~65, 암호화 64~111, 결정적 변형 88~190.
  그래서 선언한 `COST` 는 둥근 값이다: 50, 100, 200. 이 값이 있으면 `gcm_decrypt(...) LIKE '%길%'
  AND id % 2 = 0` 으로 쓴 쿼리가 `id % 2 = 0` 을 먼저 평가하도록 계획된다.
- **7 단계 — 임시 파일.** `work_mem` 이 기본값 4MB 일 때, 복호화한 이름으로 `ORDER BY` 하면 30,000
  행에서는 모든 메이저에서 메모리에 남고, 15 는 60,000 행, 16 은 100,000 행, 17~19 는 300,000 행에서
  external merge 가 된다. `GROUP BY` 는 15~17 에서 100,000 행, 18~19 에서 300,000 행에 디스크로
  넘친다. 정렬된 30만 행에 커서를 열어 둔 동안 `base/pgsql_tmp` 에는 약 7 MB 파일 하나가 있고 그
  안에 `길동` 조각이 약 37,500 번 나온다. 테이블 파일에는 한 번도 없다.
- **OpenSSL, 3.0 과 3.5 소스에서.** `EVP_*Init_ex2` 에 넘긴 `ivlen` 파라미터는 3.0.12 / 3.1.4 전까지
  IV 를 복사한 뒤에 적용됐다 (CVE-2023-5363). 12 는 AES-GCM 의 기본값이므로 코어는 파라미터를 넘기지
  않고 `EVP_CIPHER_CTX_get_iv_length` 를 검사한다. `EVP_DecryptFinal_ex` 의 tag 불일치는 오류 큐에
  아무것도 넣지 않고, 그 경로에서 키, IV, tag 가 빠진 경우도 마찬가지다. `ERR_clear_error` 는 항목의
  데이터 버퍼를 재사용하려고 남겨 두고, OpenSSL 은 DRBG 와 스레드의 오류 상태를 프로세스 수명 동안
  유지하므로, 단위 테스트는 기준선을 잡기 전에 모든 경로를 한 번씩 돌린다.
- **PostgreSQL, 15~18 소스에서.** `pg_do_encoding_conversion_buf` 는 소비한 원본 바이트 수를
  돌려주고, 출력을 NUL 로 끝내며, 대상 크기가 `srclen * MAX_CONVERSION_GROWTH + 1` 이면 입력 전체를
  변환에 넘긴다. 빈 입력에서는 0 이 모호하므로 glue 는 빈 입력을 변환하지 않는다.
  `FindDefaultConversionProc` 는 `search_path` 를 따라간다 ("미확인" O14). `-Wextra` 는 서버 자신의
  헤더 (static inline 의 쓰지 않는 파라미터) 에서 실패하므로, `-Werror` 빌드는 그 헤더를 `-isystem`
  으로 받는다.
- **`pg_regress` 와 `\c`, 17 에서 실행.** `PGCLIENTENCODING` 이 없는 상태에서 `EUC_KR` DB 로 `\c`
  하면 `SHOW client_encoding` 이 `EUC_KR` 이고 UTF-8 리터럴은 `invalid byte sequence for encoding
  "EUC_KR"` 로 실패한다. `SET client_encoding = 'UTF8'` 로 해결된다. `pg_regress` 는 expected 파일이
  없는 첫 테스트에서 멈춘다.
- **공식 이미지, 실행.** 초기화 중의 임시 서버는 진짜 서버가 뜨기 전에 소켓으로 `pg_isready` 에
  응답한다. TCP 로 검사하면 그렇지 않다. preload 하는 서버는 시작 전에 라이브러리가 디스크에 있어야
  한다 (`docker create`, `docker cp`, `docker start`).
- **O1, 지금까지.** 스파이크는 `postgres:19beta4` 에서 `postgresql-server-dev-19` 로 빌드되고 위의
  모든 것을 통과한다. 19 는 릴리스 이미지가 나올 때까지 지원 목록 밖에 둔다.
- **무엇이 어디에 있나** (만들면서 정했다; `AGENTS.md` §3 과 `architecture.md` 도 같게 적었다).
  fetch 한 핸들은 코어 안의 static 이고 `gcm_init()` 뒤에 있다. 단위 테스트가 서버 없이 핸들을 써야
  하기 때문이다. glue 는 OpenSSL 헤더를 include 하지 않고 `gcm_cleanse` 로 지운다. 스파이크에는 2
  인자 `gcm_encrypt_det` 가 들어 있다. 그 nonce 가 SQL 에서 HMAC 결과를 볼 수 있는 유일한 곳이기
  때문이다 (5 단계). `CRYPTO_set_mem_functions` probe 와 `PG_TRY` 시간 측정은 extension 이 아니라
  측정 전용 모듈 `scripts/spike/pg_gcm_probe` 에 있다.

### Phase 1 에서 확인됨 (2026-10-12)

- **O13 — version 바이트를 인증한다.** 결정: GCM 에 주는 associated data 는 `version || aad` 다
  (§2.2; 명세 §1.5). 다른 선택은 이 약점을 받아들인다고 기록하는 것이었다. 택하지 않은 이유는 약점이
  구체적이기 때문이다 — 키 없이도 봉투 하나를 같은 평문으로 열리는 다른 봉투로 바꿀 수 있었다 —
  그리고 막는 비용은 associated data 1 바이트이고 전송되는 바이트는 그대로다. 이것으로 막지 못하는
  것은 옮겨 심기다. `gcm_decrypt` 는 두 변형을 모두 열므로, 같은 키와 AAD 로 봉인한 같은 값의 무작위
  nonce 봉투는 여전히 두 번째 봉투가 된다. 결정적 컬럼이 이에 대해 할 일은 §6 5 번에 있다. 이 phase
  에 미친 영향이 하나 있다. NIST 벡터는 더 이상 봉투가 아니므로 (그 associated data 는 NIST 의
  것이다) NIST known answer 는 primitive 의 벡터이고 SQL 은 이를 보지 않는다.
- **O16 — 결정적 nonce 도 associated data 에서 유도한다.** Phase 1 암호 리뷰에서 제기되어 같은 날
  결정했다: `A = version || aad` 일 때 `nonce = HMAC-SHA256(nonce_key, be64(len(A)) || A ||
  P)[0:12]` (명세 §1.8). AAD 는 입력이 아니라던 이전 규칙을 뒤집는 것이다. 그 규칙에서는 한 평문을
  두 AAD 로 봉인하면 (키, nonce) 쌍 하나를 두 번 쓰게 되는데, GCM 에서 이는 국소적인 실패가 아니다.
  두 tag 의 차이는 인증 부분키에 대한 다항식이고 그 계수는 두 associated data 이므로, 두 AAD 를 아는
  사람은 부분키를 풀어낼 수 있다 (Joux; SP 800-38D 부록 A). 그러면 그 키로 이미 봉인된 모든 봉투를
  (변형과 무관하게) 고칠 수 있다 — ciphertext, version 바이트, 그리고 봉투가 응답하는 AAD 까지 —
  그리고 검증되는 tag 를 붙일 수 있다. 이전의 답은 운영 규칙 — 결정적 키마다 AAD 규칙은 하나 —
  이었지만, 함수의 시그니처 자체가 호출자에게 이를 어기도록 권했다. 행마다 다른 AAD 는 그 인자의
  자연스러운 쓰임이고 바로 그것이 금지된 경우였다. 잃는 것은 없다. AAD 가 다른 봉투는 tag 가 달라서
  원래도 같다고 비교되지 않았다. 길이 접두가 HMAC 메시지를 모호하지 않게 만든다. 지금 바꾸면 비용이
  없고, 나중이었다면 저장된 모든 결정적 봉투가 비용이었다.
- **O7 — SQLSTATE 확정** (명세 §2.5). 스파이크의 표를 그대로 두고 tag 불일치의 `XX001` 도 유지하며,
  UTF-8 과의 기본 변환이 없는 DB 인코딩에 대한 `42883` 을 더한다 (스파이크가 이미 올리는 코드다).
  자체 코드보다 기존 코드를 택했다. 22 분류의 분류 수준 코드가 대안이었고, 이를 기각한 근거는 15~18
  에서 실행해 확인했다 (`scripts/spike/sqlstate-handlers.sql`). PL/pgSQL 에서 `WHEN SQLSTATE
  '22000'` 과 `WHEN data_exception` 은 둘 다 `22023` 을 잡는다. `WHEN data_corrupted` 는 `XX001` 을
  잡고 `XX000` 과 `XX002` 는 잡지 않는다. `WHEN internal_error` 는 분류 전체이므로 `XX001` 도
  잡는다. `XX001` 은 이 extension 만의 코드가 아니다 — 서버가 손상된 저장소에 대해 올린다 — 그리고
  가장 흔한 원인이 틀린 키인데도 내부 오류 분류에 있는 것은, 형식상 틀린 키와 변조된 봉투를 구분할
  수 없기 때문이다.
- **벡터.** `spec/test-vectors.json` 에는 77 개가 있다. 15 개는 AES-GCM 의 NIST CAVP known answer
  로, 키 크기마다 5 개씩 NIST 의 `gcmtestvectors.zip` (URL 은 파일 안에 있다; SHA-256
  `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`, 2026-10-12 에 받음) 의
  `gcmEncryptExtIV128/192/256.rsp` 에서 그대로 가져왔다: IV 96 비트, tag 128 비트이고 (평문, AAD)
  길이가 (0, 0), (128, 0), (0, 128), (104, 160), (408, 720) 비트인 파라미터 세트의 `Count = 0`. 62
  개는 이 프로젝트의 것이다. 30 개는 열린다: 여섯 version 바이트 전부, AAD 가 있는 것과 없는 것
  (하나는 300 바이트다), 블록 경계 주변, 빈 텍스트, 4 바이트 문자, UTF-8 이 아닌 평문 (다른 인코딩의
  바이트 쌍, overlong 형태, surrogate, 잘린 문자) 이나 U+0000 을 담은 평문, 그리고 결정적이라고
  표시됐지만 nonce 가 유도된 값이 아닌 봉투 하나. 32 개는 열리지 않는다 (`bad_tag` 14,
  `bad_envelope` 10, `bad_key_length` 8). 각각 유효한 벡터에서 명시된 변경으로 만들었고, 그중 넷은
  유효한 봉투에서 version 바이트만 바꾼 것으로 (`version-02-as-03`, `version-03-as-02`,
  `version-04-as-05`, `version-06-as-07`) 모두 `bad_tag` 다 — 바이트로 본 O13 이다. 키는 공개된
  것이다: suite 길이로 자른 `00..1f` 패턴, 0 바이트 32 개, 그리고 NIST 의 키.
- **어디까지 검사되나.** `python3 scripts/check-vectors.py` (`cryptography` 50.0.2 와 표준
  라이브러리의 HMAC) 는 모든 NIST 벡터를 primitive 로 다시 계산하고, 모든 봉투를 열어 기대 결과와
  맞추고, 유효한 봉투를 다시 봉인해 같은 바이트가 나오는지 보고, 결정적 nonce 를 다시 유도한다.
  문서들이 이름으로 가리키는 벡터가 있고 각각이 그 이름이 말하는 경우여야 하며, 모든 suite, 결과,
  평문 분류에 대해 적어도 하나의 벡터를 요구한다. 그리고 `spec/envelope.md` 의 예시를 각 예시가
  가리키는 벡터와 대조한다 — 12 자리 이상의 hex 문자열은 그 벡터의 멤버 하나 전체여야 하고, 필드
  표의 행은 해당 오프셋의 필드 전체여야 하며, suite 표와 결과 표는 행이 다 있어야 한다.
  `--self-test` 는 파일과 명세를 메모리에서 35 가지 방법으로 망가뜨리고 하나라도 잡히지 않으면
  실패한다. 이는 그 손상들을 잡는다는 것을 보일 뿐 가능한 모든 손상을 잡는다는 뜻은 아니다. lint
  워크플로가 둘 다 실행한다. 한계가 셋 있다. 프로젝트의 벡터는 이 검사 스크립트 자신의 함수로
  *생성*했으므로, 스크립트가 벡터와 일치한다는 것은 독립적인 증거가 아니다. 독립적인 것은 이렇다.
  스파이크 코어의 임시 사본에 O13 과 O16 의 두 변경을 넣고 EVP 를 직접 호출하게 했더니 (OpenSSL
  3.6.4), AAD 가 없는 AES-256 벡터 16 개를 정확히 같은 바이트로 봉인하고 열었으며 그중 `bad_tag` 9
  개를 거부했다. 그리고 암호 리뷰가 77 개 중 76 개를 — 나중에 추가한 `det-256-300-byte-aad` 를 뺀
  전부이고, 그 벡터의 nonce 는 `openssl` 명령으로 다시 유도했다 — 그 목적으로 작성한 AES-GCM 과 HMAC
  으로 다시 계산했다. 그 코어 사본은 저장소에 없다: **Phase 2 까지는 커밋된 C 코드가 벡터를 하나도
  돌리지 않는다** (이슈 #19). 그리고 명세 검사가 보는 것은 hex 문자열과 표의 행이지 산문이 아니다.
- **열 때의 검사 순서** (명세 §1.7) 를 고정했고 전용 벡터가 있다: suite 를 가리키지 않는 키 길이,
  봉투의 길이와 version 바이트, suite 에 대한 키 길이, tag 순이다. 스파이크의 glue 가 이미 따르는
  순서다. opener 는 결정적 nonce 를 다시 계산하지 않는다 (벡터 `det-256-nonce-not-derived`). 다시
  계산하면 부하 게이트가 재는 경로인 `gcm_decrypt` 마다 HMAC 두 번이 드는데, 그것으로 막는 상대는
  키를 가진 사람이다.
- **벡터 스키마가 바뀌었다.** `docs.md` 에 처음 적은 것과 다르다. `nist` 벡터는 봉투 대신 ciphertext
  와 tag 를 갖는다. `expect` 에 `bad_key_length` 가 추가됐다. 유효한 벡터는 `plaintext_class`
  (`text`, `not_utf8`, `contains_nul`) 를 가지며, SQL 계층은 이것을 보고 텍스트를 기대할지 `22021`
  을 기대할지 안다. 실패하는 벡터는 `derived_from` 으로 원본 벡터를 가리킨다. `nonce_derived: false`
  는 sealer 가 재현할 수 없는 결정적 벡터 하나를 표시한다.

### 미확인

번호는 다시 쓰지 않는다. O2~O13 과 O16 은 위에서 답했고, 그중 O7, O13, O16 은 Phase 1 에서 답했다. O14
와 O15 는 Phase S 리뷰에서 나왔고 Phase 2 의 몫이다.

| # | 질문 | 확인 방법 |
|---|---|---|
| O1 | 19 는 언제 지원 메이저에 들어가나? 15~18 은 정해졌다. 19 는 beta 4 이고, RC1 은 2026-10-15, 출시는 2026-10-29 로 공지됐다 (pgsql-hackers, 2026-09-28). 스파이크는 이미 `19beta4` 에서 빌드되고 통과한다 | 릴리스 이미지가 나오면 `docker/versions.json` 에서 `prerelease` 를 `supported` 로 옮긴다 |
| O14 | `FindDefaultConversionProc` 는 `search_path` 를 통해 찾는다. UTF-8 이 아닌 DB 에서는 평문이 먼저 발견되는 기본 변환에 넘어가며, 서버 자신의 클라이언트 인코딩 변환도 그렇다. 이를 받아들일 것인가, 아니면 `pg_catalog` 에서만 변환을 찾을 것인가? | Phase 2, 인코딩 코드와 함께: 누가 기본 변환을 만들 수 있는지 확인한 뒤 결정한다 |

| O15 | `EVP_MAC` 는 fetch 한 digest 를 받지 않으므로, 결정적 호출은 `EVP_MAC_init` 안에서 SHA-256 을 이름으로 찾는다. 키 없는 `EVP_MAC_CTX` 를 한 번 만들어 호출마다 복제하면 이를 피할 수 있고, 여기서 3.0.22, 3.5.7, 3.6.4 로 통과했다. 그러나 업스트림 `hmac_prov.c` 를 보면 3.0.0 에서는 키 없는 HMAC 컨텍스트의 `EVP_MAC_CTX_dup` 이 실패하고 그때마다 digest 참조를 하나씩 잃는다 (3.0.1 과 3.0.4 에서 수정; 소스를 읽은 것이고 실행하지는 않았다). 그래서 스파이크는 호출마다 찾는 형태를 유지한다. 하한을 3.0.1 로 올리고 실행 시점에 버전을 검사할 것인가, 아니면 그대로 둘 것인가? | Phase 2, 결정적 변형의 측정된 비용과 견주어 |

## 9. 참고 자료

- PostgreSQL 18 문서, F.26 pgcrypto: https://www.postgresql.org/docs/18/pgcrypto.html
- PostgreSQL 18 문서, pgcrypto 보안 제약: https://www.postgresql.org/docs/18/pgcrypto.html#PGCRYPTO-SECURITY-LIMITATIONS
- PostgreSQL 18 문서, `CREATE FUNCTION` (`STRICT`, 기본값): https://www.postgresql.org/docs/18/sql-createfunction.html
- PostgreSQL 18 문서, C 언어 함수와 `fmgr`: https://www.postgresql.org/docs/18/xfunc-c.html
- PostgreSQL 18 문서, 관련 객체를 extension 으로 묶기: https://www.postgresql.org/docs/18/extend-extensions.html
- PostgreSQL 18 문서, extension 빌드 인프라 (PGXS): https://www.postgresql.org/docs/18/extend-pgxs.html
- PostgreSQL 18 문서, 사용자 정의 옵션: https://www.postgresql.org/docs/18/runtime-config-custom.html
- PostgreSQL 버전 정책: https://www.postgresql.org/support/versioning/
- OpenSSL 매뉴얼, `OPENSSL_malloc(3)` (`CRYPTO_set_mem_functions`) 과 `EVP_EncryptInit(3)`
- NIST SP 800-38D: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- Oracle `DBMS_CRYPTO` (19c 와 23ai/26ai), SQL Server Always Encrypted 암호화 — §1.1 에서만 사용
