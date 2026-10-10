# PostgreSQL GCM 암호화 함수 (extension) — 설계와 절차

[English](design.md) | 한국어

> 이 문서는 `docs/design.md` 의 번역이다. 두 문서가 다르면 영어 문서가 맞고, 이 번역을 고친다.

상태: **Phase 0, 기획** (2026-10-10). 여기 적힌 것은 아직 하나도 구현되지 않았다. 설계가 기대는
PostgreSQL 동작에 관한 주장은 모두 §9 에 출처가 있거나, 근거와 함께 §8 "확인됨" 에 기록되어 있거나,
Phase S 에서 확인할 §8 "미확인" 목록에 있다. 이 계획은 2026-10-10 에 PostgreSQL 15~18 소스, 공식
이미지, mysql-gcm 과 대조했고, 거기서 확인된 것을 §8 에 적었다.

## 0. 목표와 범위

[mysql-gcm](https://github.com/devgyurak/mysql-gcm) 이 MySQL 에 주는 것을 PostgreSQL 에도 준다.
서버 안의 SQL 함수로 인증 암호화 AES-GCM 을 제공하고, 복호화한 값을 서버 자신의 `LIKE` 로 쓸 수
있게 하며, **봉투 바이트를 똑같이** 맞춰 한 애플리케이션이 두 데이터베이스 사이에서 암호화 컬럼을
옮기거나 함께 쓸 수 있게 한다.

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
`contrib/pgcrypto/openssl.c` 암호 표 (§8). MySQL 과 MariaDB 에도 GCM 이 없다 (mysql-gcm 설계 §1.1,
실측). SQL Server 의 Always Encrypted 는 AEAD_AES_256_CBC_HMAC_SHA_256 을 쓰고 클라이언트 드라이버에서
복호화하며, secure enclave (SQL Server 2019 이상) 를 쓰면 enclave 안에서 패턴 매칭을 한다. Oracle 은
23ai 에서 `DBMS_CRYPTO` 에 `CHAIN_GCM` 을 추가했고, 19c 에는 없다.

규제 산업 — 이 프로젝트의 경우 헬스케어 — 은 저장된 개인정보에 인증 암호화를 점점 더 요구하고, 보통의
답은 AES-GCM 이다. 데이터베이스에 그것이 없으면 애플리케이션이 직접 암복호화한다.

### 1.2 애플리케이션에서 암호화하면 서버 쪽 검색을 잃는다

복호화 경로를 애플리케이션만 갖고 있으면, 암호화 컬럼에 대한 `WHERE name LIKE '%길%'` 은 SQL 로
불가능하다. 후보 행을 전부 애플리케이션으로 가져와 복호화하고 걸러야 한다. mysql-gcm 은 그 검색을
서버 안에 두려고 만들었고, 이 프로젝트도 마찬가지다. 복호화 결과가 DB 인코딩의 `text` 로 돌아오면
PostgreSQL 의 평범한 `LIKE`, `ILIKE`, 정규식, collation 이 새로 배울 것 없이 그대로 동작한다.

### 1.3 상호 운용이 두 번째 이유다

MySQL 과 PostgreSQL 을 함께 운영하는 조직은 암호화 컬럼 형식이 하나이기를 원한다. mysql-gcm 의 봉투를
공유하면 바이트 복사만으로 컬럼을 두 DB 사이에서 옮길 수 있고, 키와 AAD 가 같으면 결정적 값이 두 DB
사이에서 조인되며, 테스트 벡터 한 벌이 두 프로젝트를 함께 지킨다.

### 1.4 기존 extension 은 이 빈자리를 채우지 못한다

2026-10-10 에 확인했다 (저장소 메타데이터와 PGXN; 검색으로 "다른 것은 없다"를 증명할 수는 없다).

| 프로젝트 | 주는 것 | 답이 아닌 이유 |
|---|---|---|
| [pgsodium](https://github.com/michelp/pgsodium) | SQL 에서 쓰는 libsodium AEAD: ChaCha20-Poly1305-IETF, 결정적 XChaCha20-SIV, `crypto_secretbox`. PostgreSQL License, v3.1.11 (2026-06-10) | AES-GCM 이 없어 "AES-GCM 을 쓰라"는 요구를 채우지 못하고, 형식도 mysql-gcm 의 봉투가 아니다. Supabase 문서는 폐기 예정이라며 사용을 권하지 않는다 |
| [pgcrypsi](https://github.com/telkomdev/pgcrypsi) | 키를 인자로 받는 `pgcrypsi_aes_{128,192,256}_gcm_{encrypt,decrypt}`. MIT | mysql-gcm 설계 §1.3 이 물리친 UDF 의 PostgreSQL 판이고 이유도 같다: 마지막 push 가 2023-09-11, OpenSSL 1.1.1 과 `postgresql-server-dev-10` 기준이며, mysql-gcm 의 봉투가 아니다 |
| pg_tde (Percona), pg_vault_tde | 저장 계층(table access method)의 암호화 | 저장 데이터의 투명 암호화다. SQL 함수가 없고, 다른 DB 가 열 수 있는 봉투도 없다 |

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

- 함수 이름은 mysql-gcm 과 같아서 SQL 을 그대로 옮길 수 있다. extension 이름은 생태계의 `pg_` 관례를
  따라 `pg_gcm` 이고, GUC 는 라이브러리가 예약하는 `pg_gcm.` 접두사를 쓴다 (§5.6).
- **키 길이가 suite 를 고른다**: 32 → AES-256-GCM, 24 → AES-192-GCM, 16 → AES-128-GCM. 그 밖의
  길이는 오류이며, `key` 가 상수일 필요가 없으므로 호출마다 검사한다.
- **NULL 처리는 mysql-gcm 과 같다** (`spec/envelope.md` §4 규칙 3): 어느 인자든 SQL NULL 이면 암호
  연산 없이 SQL NULL 이다. 그래서 모든 함수를 `STRICT` 로 선언하고, 서버가 함수를 부르지 않고 NULL 을
  돌려준다.
- **AAD 는 `DEFAULT NULL` 이 아니라 오버로드로 생략한다.** `aad` 를 생략한 호출은 암호화하고, 명시한
  NULL 은 전파되게 하려는 것이다. **NULL 기본값으로는 둘을 함께 얻을 수 없다.** `STRICT` 아래에서 기본값 NULL 은
  2 인자 호출이 아무것도 암호화하지 않고 NULL 을 돌려주게 만든다 (15~18 에서 재현, §8). 그렇다고 NULL
  을 "AAD 없음"으로 읽으려고 `STRICT` 를 빼면, 명시한 NULL — NULL 을 허용하는 컬럼, 바인딩하지 않은
  파라미터 — 이 조용히 AAD *없이* 봉인된다. 결정적 키 하나에서 같은 평문을 "AAD 있음"과 "AAD 없음"으로
  섞어 쓰는 것이고 `spec/envelope.md` §3 이 금지하는 nonce 재사용 조건이며, mysql-gcm 의 NULL 규칙도
  아니게 된다. 오버로드 둘이면 2 인자 형태가 "AAD 없음"이고, 3 인자 형태의 NULL `aad` 는 MySQL
  에서처럼 NULL 을 주며, 빈 `aad` (`''`) 는 2 인자 형태와 똑같이 봉인한다.
  NULL 이 아닌 기본값으로도 둘을 함께 얻을 수 있다. `STRICT` 와 함께 쓴 `aad bytea DEFAULT ''` 는
  인자를 생략하면 빈 AAD 로 실행되고, 명시한 NULL 에는 여전히 NULL 을 돌려준다 (§8). 오버로드는 고른
  방식이지 유일하게 옳은 방식이 아니다. 표면을 mysql-gcm 의 선택 인자가 읽히는 방식대로 인자 개수 둘로
  두고, 설명해야 할 기본값 표현식을 남기지 않는다.
- `STRICT` 의 귀결 하나를 함수를 문서화하는 모든 곳에 적는다. **키가 빠지면 오류가 아니라 NULL 이다.**
  평문이 NULL 일 수 없는 암호화 컬럼에는 `NOT NULL` 을 선언해, 바인딩하지 않은 키 파라미터가 NULL 을
  저장하는 대신 문장을 실패시키게 한다 (§6, 11 번).
- 함수마다 `COST` 를 명시하고, 값은 Phase S 에서 잰 호출당 비용으로 정한다. C 함수의 기본 비용은 1 이고
  플래너는 한 스캔의 조건을 비용 순으로 배열하므로, 명시하지 않으면 `gcm_decrypt(...) LIKE ...` 가
  §6 4 번이 기대는 값싼 조건들 뒤에 놓이지 않는다.
- 이진 평문(`bytea` 입력, `bytea` 출력)은 0.1 에 일부러 넣지 않는다. 첫 인자에서 `text` 와 `bytea` 를
  오버로드하면 타입 없는 리터럴이 모호해진다. 필요하면 개정을 거쳐 별도 이름(`gcm_encrypt_bytes`,
  `gcm_decrypt_bytes`)으로 넣는다.

### 2.2 봉투

mysql-gcm 의 `spec/envelope.md` 를 그대로 채택한다 — version 바이트, 12 바이트 nonce, 암호문,
16 바이트 tag, version `0x02`~`0x07` (`AGENTS.md` §2). Phase 1 에서 spec 과 벡터를 복사하고, 그
사본이 고정한 mysql-gcm 커밋과 같은지 CI 에서 검사한다. 봉투 변경은 mysql-gcm 에서 먼저, 또는 두
프로젝트에서 동시에 일어나며, 여기서만 바뀌는 일은 없다.

mysql-gcm 의 spec 은 아직 공유 부분과 서버 바인딩으로 나뉘어 있지 않다. §1 과 §4 는 `utf8mb4`,
GLOBAL 변수, `UDF_INIT` 을 말한다. 이 프로젝트가 공유하는 바이트 계약은 그 §2 (레이아웃), §3 (유도),
§5 (예시), 그리고 §6 의 벡터 스키마이고, CI 검사는 그것들을 비교한다. PostgreSQL 바인딩 — SQLSTATE,
인코딩 규칙, 아래의 예외 — 은 명확히 표시한 별도 부분이다. 상위 파일을 같은 식으로 나누는 것은
mysql-gcm 의 후속 과제이지 선행 조건이 아니다.

봉투 안의 평문은 **UTF-8** 이다. `gcm_encrypt` 는 봉인 전에 인자를 DB 인코딩에서 UTF-8 로 변환하고,
`gcm_decrypt` 는 열린 바이트가 올바른 UTF-8 인지 확인한 뒤 DB 인코딩으로 변환한다 (어떻게 하는지,
그리고 왜 뻔한 서버 함수를 쓰지 않는지는 §5.7). UTF-8 DB(흔한 경우)에서는 변환이 일어나지 않는다.
이것이 mysql-gcm 이 결과에 `utf8mb4` 를 태깅하는 것의 PostgreSQL 대응이고, 봉투가 이식 가능한 이유다.

**이식 가능에는 예외가 셋 있다.** 셋 다 인증은 통과한 뒤에 실패하며, `pg_gcm.strict` 가 가리지 않는
오류다.

1. U+0000 이 들어 있는 평문. MySQL 의 `utf8mb4` 는 담지만 PostgreSQL `text` 는 담지 못하고, UTF-8
   검증은 지원하는 모든 메이저에서 0 바이트를 거부한다 (§8).
2. MySQL 이 UTF-8 이 아닌 `binary` 인자로 봉인한 봉투 (mysql-gcm spec §2.3 은
   `gcm_encrypt(UNHEX('ff'), key)` 가 `FF` 를 봉인한다고 적는다). MySQL 은 ill-formed 문자열을
   돌려주고, PostgreSQL 은 오류를 올린다.
3. UTF-8 이 아닌 DB 에서, DB 인코딩이 담을 수 없는 문자.

mysql-gcm 의 레거시 AES-256-CBC dual-read 봉투인 `0x01` (`0x01 || iv(16) || CBC 암호문`, mysql-gcm
개정 A3) 은 §8 O6 으로 남는다. 결과는 둘 중 하나이고, Phase S 가 호환성과 보안 정책이라는 두 근거로
고른다. `pgcrypto` 에서 32 바이트 키로 만든 `'\x01' || iv || encrypt_iv(data, key, iv, 'aes-cbc')` 가
제대로 열리면 mysql-gcm 처럼 구현하고, 그러면 기존 pgcrypto 컬럼에 재암호화 없는 이관 경로가 생긴다.
아니면 구현하지 않는데, spec 의 실패 표가 이미 허용하는 길이다 ("할당됐지만 구현하지 않은 version
바이트" → `bad_envelope`). 후자를 고르면 `legacy` 벡터 둘의 기대값이 여기서만 달라지고, MySQL 에서
복사한 `0x01` 행이 열리지 않는다.

구현한다면 두 조건이 따라오고, `0x01` 을 드러내는 모든 곳에 적는다.

- **앞에 붙이기만 하는 이관은 기존 평문이 이미 UTF-8 일 때만 성립한다** (mysql-gcm spec §2.3).
  `encrypt_iv` 는 `bytea` 를 받고 아무것도 변환하지 않으므로, LATIN1 바이트로 암호화한 컬럼 —
  `Müller` 가 `4D FC 6C 6C 65 72` — 은 열린 뒤 UTF-8 검증에서 실패한다. MySQL 이 ill-formed 문자열을
  돌려주는 자리에서 PostgreSQL 은 시끄럽게 실패하지만, 행마다 실패한다. 순수 ASCII 값은 통과하고
  나머지는 통과하지 못한다. 다른 인코딩의 데이터는 기존 방식으로 복호화하고, 변환한 뒤,
  `gcm_encrypt` 로 다시 봉인한다.
- **`0x01` 은 인증 보장의 예외다.** CBC 에는 tag 가 없다. IV 나 암호문 블록이 바뀌면 바뀐 평문이
  그대로 열리고, `pg_gcm.strict = on` 은 그것을 탐지하지 못하며, 틀린 키가 오류 대신 쓰레기를 돌려줄
  수 있다. 그래서 `0x01` 을 채택한다는 것은 이관이 끝난 뒤 그것을 어떻게 거부할지도 정한다는 뜻이다.
  mysql-gcm 은 그것을 애플리케이션에 맡긴다 (제약 8). extension 안에 스위치를 두려면 새 GUC 와 두
  프로젝트의 개정이 필요하다.

### 2.3 설정

```
# postgresql.conf — 정책만, 키 재료는 절대 넣지 않는다 (§5.4)
shared_preload_libraries = 'pg_gcm'   # 선택; 넣으면 아래 두 설정이 시작 때 검증된다
pg_gcm.strict = on
pg_gcm.min_key_bytes = 32
```

`pg_gcm.strict` 는 `PGC_USERSET` 이다. 어느 세션이든 자기 세션에 한해 완화할 수 있으며, mysql-gcm 이
9.0+ 에서 허용하는 것과 같다. `pg_gcm.min_key_bytes` 는 `PGC_SUSET` 이다. 낮추는 것은 관리자의
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

## 3. mysql-gcm 과의 관계

| 관심사 | mysql-gcm | postgres-gcm |
|---|---|---|
| 패키징 | Component, `udf_registration` 서비스 | Extension, version-1 fmgr 함수, PGXS |
| 평문 문자셋 | 인자를 `utf8mb4` 로 변환, 결과에 `utf8mb4` 태깅 | 봉인 시 UTF-8 로 변환, 열 때 UTF-8 검증 후 되돌려 변환 |
| NULL 인자 | 어느 인자든 NULL 이면 NULL | 같다 (`STRICT` 로) |
| ill-formed 평문 | ill-formed 문자열로 반환 | 오류 (§2.2) |
| strict 범위 | 8.x 는 GLOBAL, 9.0+ 는 SESSION | 지원하는 모든 메이저에서 `PGC_USERSET` |
| 키 길이 하한 | `gcm.min_key_bytes`, GLOBAL | `pg_gcm.min_key_bytes`, `PGC_SUSET` |
| 수명 | component / `UDF_INIT` / operation | 라이브러리 로드(backend) / `FmgrInfo` (`fn_extra`) / operation |
| 오류 | `mysql_runtime_error` | 실패 종류별 SQLSTATE 를 붙인 `ereport(ERROR, errcode(...))` |
| 동시성 | 한 프로세스 안의 스레드 | backend 마다 프로세스 하나; 병렬 워커도 별도 프로세스 |
| 서버 테스트 | MTR + SQL 시나리오 | `pg_regress` (`make installcheck`) |
| 부하 기준선 | `AES_DECRYPT` (CBC) | `pgcrypto` `decrypt()` (CBC) 와 `pgp_sym_decrypt()` |

그대로 공유하는 것: 봉투, 벡터, 결정적 nonce 구성과 그 라벨, strict 의미, NULL 규칙, 그리고 mysql-gcm
개정 A8 "키와 nonce 에 대한 운영 책임" 과 개정 A12 의 운영 책임(사용 예산, 교체, 결정적 키마다 고정
AAD, 복구).

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

### Phase 1 — spec

고정한 커밋의 mysql-gcm 에서 `spec/envelope.md` 와 `spec/test-vectors.json` 을 복사한다. PostgreSQL
바인딩을 별도 부분으로 더한다 (§2.2): 실패 종류별 SQLSTATE, 인코딩 규칙과 그 예외 셋, Phase S 에서
정한 `0x01` 결정, 그리고 평문이 UTF-8 이 아닌 벡터에 대해 SQL 계층이 기대하는 것. mysql-gcm
`2fe2da9` 에서 그런 벡터는 2,304 개 중 1,345 개다 (NIST 1,344 개와 결정적 1 개). 코어는 그것들을 열고
단위 테스트가 바이트를 비교한다. SQL 로는 `gcm_decrypt` 가 `text` 를 돌려주므로 기대 결과가 "인증은
통과하고, 그다음 잘못된 UTF-8 오류" 다.

### Phase 2 — 구현과 테스트

코어(`gcm.c`, `envelope.c`, `nonce.c`)는 mysql-gcm 의 C++ 코어를 같은 경계로 C11 에 옮긴다. glue
(`fn_*.c`)는 인자, 인코딩, GUC, 오류를 다룬다. 단위 테스트는 서버 없이 모든 벡터로 코어를 돌리고,
`pg_regress` 가 SQL 동작을 덮는다. 호출 지점 단위의 키 스케줄 캐시(mysql-gcm 개정 A11)는 기준선을 잰
뒤에 이 문서의 개정을 거쳐 넣으며, `flinfo->fn_extra` 와 키 사본을 지우는 메모리 컨텍스트 리셋
콜백을 쓴다. 그 개정은 A11 의 수명 한계를 빌려 올 수 없다. `UDF_INIT` 은 한 문장의 한 번 실행이지만
`FmgrInfo` 는 더 오래 살 수 있다 — PL/pgSQL 은 단순 표현식의 상태를 트랜잭션이 끝날 때까지 유지한다
(`pl_exec.c`, `shared_simple_eval_estate`).

### Phase 3 — SQL E2E

primary, 스트리밍 replica, mysql-gcm 서버, Python 러너로 된 compose 파일: 왕복, 한국어 `LIKE`, 복제
(replica 가 자신이 암호화하지 않은 암호문을 읽는다), MySQL 이 봉인한 봉투를 PostgreSQL 이 열고 그
반대도 하는 시나리오, 그리고 NULL 인자가 양쪽에서 NULL 을 주는 것.

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
비밀을 지운 뒤에 오류를 올린다. mysql-gcm 이 코어와 어댑터 사이에 긋는 경계와 같고, 오류 모델 때문에
필수가 된다. (`pgcrypto` 는 같은 문제를 ResourceOwner 콜백으로 푸는데, 그 API 가 15~16 과 17+ 에서
다르다. 오류를 올리는 호출을 그 구간 밖에 두는 쪽은 버전별 코드가 필요 없다.)

**지우기 규칙은 extension 이 만든 사본을, 그리고 그것만을 덮는다**: detoast 된 인자, 변환 버퍼, 작업
공간, 결과가 되기 전의 열린 평문.

- detoast 가 필요 없었던 인자는 executor 자신의 저장소다 — 캐시된 플랜의 상수, portal 의 파라미터 값,
  shared buffer 페이지의 튜플. **거기에는 절대 쓰지 않는다.** 제자리에서 지우면 캐시된 플랜의 키가
  0 이 되거나 테이블 페이지가 망가진다. 사본인지는 `PG_FREE_IF_COPY` 가 쓰는 방법
  (`PG_GETARG_POINTER` 와 포인터가 다른지)으로 판별한다.
- 결과 `text`, 호출자의 datum, 그리고 플래너가 `STABLE` 호출을 평가하며 만드는 사본 (§5.3) 은
  extension 의 손이 닿지 않는다. 지우기는 우리 버퍼에 대한 심층 방어이지, backend 메모리에 키 사본이
  남지 않는다는 보장이 아니다.
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

mysql-gcm 개정 A1 과 같다. `postgresql.conf`, GUC, 테이블, 환경 변수에 키를 두지 않는다. 그 대가 —
문장이 있는 곳 어디서나 키가 보인다 — 는 운영 제약(§6)이며, 완화책은 extension 의 코드가 아니라 바인드
파라미터다.

서버 안에서 암호화하면 extension 이 옮길 수 없는 신뢰 경계가 그어진다. `pgcrypto` 가 스스로에 대해
문서화한 것과 같은 경계다 ("Security Limitations", §9). 키와 평문은 클라이언트 연결을 건너고, 관리자가
통제하는 서버의 메모리에 존재한다. 이 설계가 지키는 것은 저장된 컬럼, 백업, 그리고 암호문만 가진
replica 다. 보호되지 않은 연결, DB superuser, 서버의 OS 관리자로부터는 지키지 못한다 (§6, 12 번).

### 5.5 tag 불일치는 기본값에서 NULL 로 내려가지 않는다

mysql-gcm 과 같다. strict 가 on 이면 오류, off 면 NULL 이다. 잘못된 봉투, 틀린 키 길이, 열기에 성공한
뒤의 잘못된 UTF-8 은 strict 와 상관없이 오류다.

### 5.6 GUC 접두사는 `pg_gcm.`

사용자 정의 GUC 의 접두사는 그것을 정의하는 라이브러리여야 `MarkGUCPrefixReserved("pg_gcm")` 가
적용된다. 그것으로 얻는 것은 들리는 것보다 좁다 (§2.3, §8). 라이브러리가 backend 에 로드된 뒤에는
`SET pg_gcm.strcit` 이 오류다. 그 전에는, 그리고 `postgresql.conf` 에서는, 오타가 placeholder 로
받아들여졌다가 로드 때 WARNING 과 함께 제거된다. 예약 접두사는 라이브러리 자신의 것이어야 하므로
mysql-gcm 의 `gcm.` 접두사를 다시 쓰지 않는다.

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
  (메시지에 데이터는 없다). 비밀 사본이 생기기 전에 실행한다.

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
   넘으면 평문을 임시 파일에 쓴다 (언제 그런지는 Phase S 에서 잰다). `temp_tablespaces` 가 있는
   볼륨을 암호화한다.
4. **함수는 플래너에게 불투명하다.** `WHERE gcm_decrypt(col, $1) LIKE ...` 는 후보 집합을 스캔한다.
   선택도는 다른 조건에서 나와야 한다. 복호화한 값에 대한 인덱스는 설계상 없다 (§5.3).
5. **`gcm_encrypt_det` 는 같음을 드러내고 무작위 변형보다 비싸다** — mysql-gcm 제약 6 과 같으며,
   결정적 키마다 AAD 규칙 하나(제약 7)도 포함한다.
6. **자체 운영 PostgreSQL 만.** 관리형 서비스는 이 extension 을 올리지 않는다.
7. **복호화하는 모든 노드에 설치한다.** 스트리밍 replica 는 extension 의 카탈로그 항목을 WAL 로 받지만
   공유 라이브러리는 디스크에 따로 설치해야 한다. 논리 복제 구독자는 둘 다 필요하다.
8. **`pg_gcm.min_key_bytes` 가 잘린 키를 막는다** — mysql-gcm 제약 16 과 같다.
9. **사용 예산, 교체, 복구는 운영자의 책임이다** — mysql-gcm 제약 11~13 과 같고, 바뀌지 않는다.
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

- **mysql-gcm 처럼 GPLv2 가 아닌 이유.** mysql-gcm 이 GPLv2 인 것은 component 가 GPLv2 인 MySQL 헤더를
  링크하기 때문이다. PostgreSQL 헤더는 PostgreSQL License 이고 그런 요구가 없으므로, 그 이유가 여기에
  이어지지 않는다.
- **PostgreSQL License 를 고른 이유.** PostgreSQL 자체와 대부분의 contrib 모듈의 라이선스라서, 배포판이
  패키징하고 PGXN 에 올리고 커뮤니티가 읽는 데 라이선스 문제가 생기지 않는다. 짧은 허용 라이선스이고,
  OpenSSL 3 의 Apache-2.0 과 호환된다.
- **Apache-2.0 이 아닌 이유.** 특허 허여가 실질적인 장점이지만, 이 프로젝트는 공개되고 특허 부담이 없는
  구성(AES-GCM, HMAC-SHA256)을 구현하고 특허를 갖고 있지 않으며, 호스트 프로젝트에 맞추는 쪽이 더
  중요했다.
- **mysql-gcm 에서 옮겨 오기.** 코어는 mysql-gcm 에서 옮겨 오며, 그 `src/` 와 `spec/` 은 이 프로젝트와
  같은 한 명의 저자가 썼다 (2026-10-10 `git log` 로 확인). 그 저자는 mysql-gcm 을 GPLv2 로 둔 채
  여기로 옮긴 코드를 PostgreSQL License 로 낼 수 있다. 다른 사람이 mysql-gcm 에 기여한 코드는 그
  기여자의 서면 허락 없이 옮겨 오지 **않는다**.

## 8. 확인된 사실 / 미확인 질문

### 확인됨 (출처 포함)

따로 적지 않으면 "소스"는 2026-10-10 시점 각 stable 브랜치 끝의 PostgreSQL 트리 (15.19, 16.15, 17.11,
18.6; 줄 번호는 `REL_17_STABLE`) 이고, "실행"은 같은 날 linux/arm64 에서 공식 `postgres:15`~`18`
이미지에 `psql` 로 돌린 것이다.

- 라이선스: PostgreSQL License (§7, `LICENSE`).
- `pgcrypto` 원시 암호화는 `bf` 와 `aes` 를 `cbc`, `ecb` 로, 18 부터는 `cfb` 로도 지원한다 (커밋
  9ad1b3d01). 15~18, 19beta4, master 어디에도 GCM 이나 AEAD 모드는 없다. PGP 함수는 SHA-1 MDC 를
  붙인다. (소스: `contrib/pgcrypto/openssl.c` 의 암호 표, `pgcrypto.sgml`, 18 릴리스 노트.)
- MySQL 과 MariaDB 의 `block_encryption_mode` 에는 GCM 이 없다. (mysql-gcm 설계 §1.1, 실측.)
- **mysql-gcm 은 어느 인자든 NULL 이면 NULL 을 돌려준다.** (`spec/envelope.md` §4 규칙 3,
  `src/udf_glue.cc` 의 `any_arg_is_null`, `2fe2da9` 기준.)
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
  는 거짓 양성을 낸다 (`pg_config_manual.h`). 공식 이미지는 그렇게 빌드되어 있지 않다. 게이트는 단위
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
  `pg_regress` 가 만드는 DB 에만 적용된다. (소스: `pg_regress.c`, `psql/command.c`; 실행하지는
  않았다.)

### 미확인 (Phase S 에서 답한다)

번호는 다시 쓰지 않는다. O2, O3, O5, O8, O9, O10 은 위의 "확인됨"으로 옮겼다.

| # | 질문 | 확인 방법 |
|---|---|---|
| O1 | 19 는 언제 지원 메이저에 들어가나? 15~18 은 정해졌다. 19 는 beta 4 이고, RC1 은 2026-10-15, 출시는 2026-10-29 로 공지됐다 (pgsql-hackers, 2026-09-28) | 릴리스 이미지가 나오면 `docker/versions.json` 에 추가; 그때까지는 `19beta4` 로 스파이크를 빌드 |
| O4 | postmaster 에서 fetch 한 `EVP_MAC` 핸들이 fork 된 backend 에서 동작하나? `EVP_CIPHER` 는 선례가 있다 — postmaster 의 `SSL_CTX` 가 fork 전에 cipher 를 fetch 한다 — 하지만 어느 쪽도 문서화되어 있지 않다 | Phase S 5 단계: preload 한 뒤 두 backend 에서 HMAC known-answer |
| O6 | `0x01`(AES-256-CBC, PKCS#7, IV 앞붙임)을 구현하나, 한다면 어떤 조건으로 (§2.2)? 호환성: 32 바이트 키를 쓴 `pgcrypto` 의 `encrypt_iv(..., 'aes-cbc')` 와 맞나? 보안 정책: 인증이 없고 `pg_gcm.strict` 가 변조를 볼 수 없으므로, 채택한다는 것은 그 예외를 명시하고 이관 뒤 `0x01` 을 어떻게 거부할지 정한다는 뜻이다 | pgcrypto 로 암호화하고 스파이크로 열기; 그다음 호환성만이 아니라 두 부분을 함께 결정 |
| O7 | 실패 종류(틀린 키 길이, 잘못된 봉투, 잘못된 tag, 잘못된 UTF-8, 변환할 수 없는 문자, OpenSSL 실패)마다 어떤 SQLSTATE 가 맞나? 다른 곳에서 쓰이는 후보: `22023`, `XX001`, `22021`, `22P05`. `pgcrypto` 는 전부 `39000` 으로 올린다 | `errcodes.txt`; 사용자 정의보다 기존 분류 우선, 그리고 클라이언트가 위조된 tag 와 틀린 키 길이를 구분할 수 있게 실패마다 분류 하나 |
| O11 | amd64 이미지가 O2 에서 확인한 arm64 이미지와 같은 OpenSSL 을 링크하나? | amd64 에서 `ldd` 와 `openssl version` |
| O12 | 호출마다 `PG_TRY` 블록을 두면 30만 행에서 얼마가 들고, 부하 게이트가 달라지나? | Phase S 7 단계, 블록이 있을 때와 없을 때 |

## 9. 참고 자료

- PostgreSQL 18 문서, F.26 pgcrypto: https://www.postgresql.org/docs/18/pgcrypto.html
- PostgreSQL 18 문서, pgcrypto 보안 제약: https://www.postgresql.org/docs/18/pgcrypto.html#PGCRYPTO-SECURITY-LIMITATIONS
- PostgreSQL 18 문서, `CREATE FUNCTION` (`STRICT`, 기본값): https://www.postgresql.org/docs/18/sql-createfunction.html
- PostgreSQL 18 문서, C 언어 함수와 `fmgr`: https://www.postgresql.org/docs/18/xfunc-c.html
- PostgreSQL 18 문서, 관련 객체를 extension 으로 묶기: https://www.postgresql.org/docs/18/extend-extensions.html
- PostgreSQL 18 문서, extension 빌드 인프라 (PGXS): https://www.postgresql.org/docs/18/extend-pgxs.html
- PostgreSQL 18 문서, 사용자 정의 옵션: https://www.postgresql.org/docs/18/runtime-config-custom.html
- PostgreSQL 버전 정책: https://www.postgresql.org/support/versioning/
- mysql-gcm `docs/design.md` (개정 A1, A2, A3, A5, A8 "키와 nonce 에 대한 운영 책임", A10, A11, A12)
  와 `spec/envelope.md`
- OpenSSL 매뉴얼, `OPENSSL_malloc(3)` (`CRYPTO_set_mem_functions`) 과 `EVP_EncryptInit(3)`
- NIST SP 800-38D: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- Oracle `DBMS_CRYPTO` (19c 와 23ai/26ai), SQL Server Always Encrypted 암호화 — §1.1 에서만 사용
