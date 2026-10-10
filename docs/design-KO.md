# PostgreSQL GCM 암호화 함수 (extension) — 설계와 절차

[English](design.md) | 한국어

> 이 문서는 `docs/design.md` 의 번역이다. 두 문서가 다르면 영어 문서가 맞고, 이 번역을 고친다.

상태: **Phase 0, 기획** (2026-10-10). 여기 적힌 것은 아직 하나도 구현되지 않았다. 설계가 기대는
PostgreSQL 동작에 관한 주장은 모두 §9 에 출처가 있거나, Phase S 에서 확인할 §8 "미확인" 목록에 있다.

## 0. 목표와 범위

[mysql-gcm](https://github.com/devgyurak/mysql-gcm) 이 MySQL 에 주는 것을 PostgreSQL 에도 준다.
서버 안의 SQL 함수로 인증 암호화 AES-GCM 을 제공하고, 복호화한 값을 서버 자신의 `LIKE` 로 쓸 수
있게 하며, **봉투 바이트를 똑같이** 맞춰 한 애플리케이션이 두 데이터베이스 사이에서 암호화 컬럼을
옮기거나 함께 쓸 수 있게 한다.

범위 안: 자체 운영 PostgreSQL 15 이상을 위한 C extension (`pg_gcm`) — 정확한 메이저 버전은 Phase S
에서 정한다 — 과 그 SQL API, GUC, 테스트, 릴리스 파이프라인, 문서.

범위 밖: 서드파티 C extension 을 올릴 수 없는 관리형 서비스, 키 관리·KMS·keyring 연동, 어떤 언어로든
암호화 SDK, 쿼리를 다시 쓰는 투명 암호화나 컬럼 단위 암호화, 암호문 검색용 인덱스.

## 1. 왜 필요한가

### 1.1 PostgreSQL 의 SQL 에는 GCM 이 없다

대부분의 배포에 이미 있는 contrib 모듈 `pgcrypto` 가 주는 것은 다음과 같다.

- `encrypt()` / `decrypt()` — `aes` 를 `cbc`, `cfb`, `ecb` 모드로. 인증이 전혀 없다.
- `pgp_sym_encrypt()` — SHA-1 변조 검출 코드(MDC)가 붙는 OpenPGP 대칭 암호화. OpenPGP 의 의미로는
  인증이 되지만 GCM 은 아니고, "AES-GCM 을 쓰라"는 요구가 뜻하는 것도 아니다.

출처: PostgreSQL 18 `pgcrypto` 문서의 "Raw Encryption Functions" (§9). MySQL 과 MariaDB 에도 GCM 이
없다 (mysql-gcm 설계 §1.1, 실측). SQL Server 의 Always Encrypted 는 AEAD_AES_256_CBC_HMAC_SHA_256 을
쓰고 클라이언트 드라이버에서 복호화한다. Oracle 은 23ai 에서 `DBMS_CRYPTO` 에 `CHAIN_GCM` 을
추가했고, 19c 에는 없다.

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

## 2. 무엇을 만드는가

### 2.1 함수 표면

```sql
gcm_encrypt(plaintext text, key bytea, aad bytea DEFAULT NULL)      RETURNS bytea  VOLATILE PARALLEL SAFE
gcm_encrypt_det(plaintext text, key bytea, aad bytea DEFAULT NULL)  RETURNS bytea  STABLE   PARALLEL SAFE
gcm_decrypt(ciphertext bytea, key bytea, aad bytea DEFAULT NULL)    RETURNS text   STABLE   PARALLEL SAFE
```

- 함수 이름은 mysql-gcm 과 같아서 SQL 을 그대로 옮길 수 있다. extension 이름은 생태계의 `pg_` 관례를
  따라 `pg_gcm` 이고, GUC 는 라이브러리가 예약하는 `pg_gcm.` 접두사를 쓴다 (§5.6).
- **키 길이가 suite 를 고른다**: 32 → AES-256-GCM, 24 → AES-192-GCM, 16 → AES-128-GCM. 그 밖의
  길이는 오류이며, `key` 가 상수일 필요가 없으므로 호출마다 검사한다.
- **NULL 처리**는 mysql-gcm 의 실패 표를 Phase 1 에서 맞춰 따른다. 평문이나 암호문이 NULL 이면 NULL,
  키가 NULL 이면 오류다. 그래서 함수를 `STRICT` 로 선언하지 않는다. `STRICT` 이면 `aad` 가 NULL 일
  때도 결과가 NULL 이 되기 때문이다.
- 이진 평문(`bytea` 입력, `bytea` 출력)은 0.1 에 일부러 넣지 않는다. 첫 인자에서 `text` 와 `bytea` 를
  오버로드하면 타입 없는 리터럴이 모호해진다. 필요하면 개정을 거쳐 별도 이름(`gcm_encrypt_bytes`,
  `gcm_decrypt_bytes`)으로 넣는다.

### 2.2 봉투

mysql-gcm 의 `spec/envelope.md` 를 그대로 채택한다 — version 바이트, 12 바이트 nonce, 암호문,
16 바이트 tag, version `0x02`~`0x07` (`AGENTS.md` §2). Phase 1 에서 spec 과 벡터를 복사하고, 그
사본이 고정한 mysql-gcm 커밋과 같은지 CI 에서 검사한다. 봉투 변경은 mysql-gcm 에서 먼저, 또는 두
프로젝트에서 동시에 일어나며, 여기서만 바뀌는 일은 없다.

봉투 안의 평문은 **UTF-8** 이다. `gcm_encrypt` 는 봉인 전에 인자를 DB 인코딩에서 UTF-8 로 변환하고,
`gcm_decrypt` 는 열린 바이트가 올바른 UTF-8 인지 확인한 뒤 DB 인코딩으로 변환한다. UTF-8 DB(흔한
경우)에서는 변환이 일어나지 않는다. 이것이 mysql-gcm 이 결과에 `utf8mb4` 를 태깅하는 것의 PostgreSQL
대응이고, 봉투가 이식 가능한 이유다.

mysql-gcm 의 레거시 AES-256-CBC dual-read 봉투인 `0x01` 은 §8 의 미확인 질문이다. 그 레이아웃이
`pgcrypto` 의 `encrypt_iv(data, key, iv, 'aes-cbc')` 출력과 충분히 맞아서, 기존 pgcrypto 컬럼에도 같은
이관 경로를 줄 수 있는지 확인해야 한다.

### 2.3 설정

```
# postgresql.conf — 정책만, 키 재료는 절대 넣지 않는다 (§5.4)
shared_preload_libraries = 'pg_gcm'   # 선택; fork 와 RAND 상태는 §8 참고
pg_gcm.strict = on
pg_gcm.min_key_bytes = 32
```

`pg_gcm.strict` 는 `PGC_USERSET` 이다. 어느 세션이든 자기 세션에 한해 완화할 수 있으며, mysql-gcm 이
9.0+ 에서 허용하는 것과 같다. `pg_gcm.min_key_bytes` 는 `PGC_SUSET` 이다. 낮추는 것은 관리자의
결정이고, PostgreSQL 15+ 에서는 `GRANT SET ON PARAMETER` 로 위임할 수 있다. 둘 다 호출마다 C 변수로
읽으며, PostgreSQL 이 backend 에 대해 그 값을 최신으로 유지한다. backend 는 단일 스레드 프로세스이므로
스레드 간 동기화 문제는 생기지 않는다.

## 3. mysql-gcm 과의 관계

| 관심사 | mysql-gcm | postgres-gcm |
|---|---|---|
| 패키징 | Component, `udf_registration` 서비스 | Extension, version-1 fmgr 함수, PGXS |
| 평문 문자셋 | 인자를 `utf8mb4` 로 변환, 결과에 `utf8mb4` 태깅 | 봉인 시 UTF-8 로 변환, 열 때 UTF-8 검증 후 되돌려 변환 |
| strict 범위 | 8.x 는 GLOBAL, 9.0+ 는 SESSION | 지원하는 모든 메이저에서 `PGC_USERSET` |
| 키 길이 하한 | `gcm.min_key_bytes`, GLOBAL | `pg_gcm.min_key_bytes`, `PGC_SUSET` |
| 수명 | component / `UDF_INIT` / operation | 라이브러리 로드(backend) / `FmgrInfo` (`fn_extra`) / operation |
| 오류 | `mysql_runtime_error` | 실패 종류별 SQLSTATE 를 붙인 `ereport(ERROR, errcode(...))` |
| 동시성 | 한 프로세스 안의 스레드 | backend 마다 프로세스 하나; 병렬 워커도 별도 프로세스 |
| 서버 테스트 | MTR + SQL 시나리오 | `pg_regress` (`make installcheck`) |
| 부하 기준선 | `AES_DECRYPT` (CBC) | `pgcrypto` `decrypt()` (CBC) 와 `pgp_sym_decrypt()` |

그대로 공유하는 것: 봉투, 벡터, 결정적 nonce 구성과 그 라벨, strict 의미, 그리고 mysql-gcm 개정 A8 과
A12 의 운영 책임(사용 예산, 교체, 결정적 키마다 고정 AAD, 복구).

## 4. 절차

### Phase S — 스파이크 (spec 전)

§8 의 미확인 질문에 답하는 가장 작은 extension 을 후보 메이저마다 만든다.

1. `postgres:<major>` 에 `postgresql-server-dev-<major>` 를 더한 환경에서 PGXS 로 빌드해
   `CREATE EXTENSION pg_gcm`.
2. AES-256 만, 무작위 nonce, AAD 없이 `gcm_encrypt`/`gcm_decrypt` — 측정하기에 충분한 만큼.
3. 길이가 틀린 키는 오류이고, `SET pg_gcm.strict = off` 이면 위조된 tag 가 NULL 이 된다.
4. `SELECT gcm_decrypt(gcm_encrypt('홍길동', k), k) LIKE '%길%'` 가 UTF-8 DB 에서도, `EUC_KR` DB 에서도
   참이다.
5. `shared_preload_libraries` 가 있을 때와 없을 때 모두 backend 안에서 `EVP_CIPHER_fetch` 가 성공한다.
6. 호출 중간에 오류가 나도 `EVP_CIPHER_CTX` 가 새지 않는다 — 할당 횟수를 세거나 valgrind 로 돌린다.
7. 30만 행에 대한 복호화 + LIKE 의 `EXPLAIN ANALYZE`, 그리고 정렬이나 해시가 복호화된 텍스트를 임시
   파일로 흘리는지.

모든 답을 그것을 만든 명령과 함께 §8 에 기록한다.

### Phase 1 — spec

고정한 커밋의 mysql-gcm 에서 `spec/envelope.md` 와 `spec/test-vectors.json` 을 복사한다. 그리고
PostgreSQL 절을 더한다: 실패 종류별 SQLSTATE, NULL 처리, 인코딩 규칙, Phase S 에서 정한 `0x01` 결정.

### Phase 2 — 구현과 테스트

코어(`gcm.c`, `envelope.c`, `nonce.c`)는 mysql-gcm 의 C++ 코어를 같은 경계로 C11 에 옮긴다. glue
(`fn_*.c`)는 인자, 인코딩, GUC, 오류를 다룬다. 단위 테스트는 서버 없이 모든 벡터로 코어를 돌리고,
`pg_regress` 가 SQL 동작을 덮는다. 호출 지점 단위의 키 스케줄 캐시(mysql-gcm 개정 A11)는 기준선을 잰
뒤에 이 문서의 개정을 거쳐 넣으며, `flinfo->fn_extra` 와 키 사본을 지우는 메모리 컨텍스트 리셋
콜백을 쓴다.

### Phase 3 — SQL E2E

primary, 스트리밍 replica, mysql-gcm 서버, Python 러너로 된 compose 파일: 왕복, 한국어 `LIKE`, 복제
(replica 가 자신이 암호화하지 않은 암호문을 읽는다), 그리고 MySQL 이 봉인한 봉투를 PostgreSQL 이 열고
그 반대도 하는 시나리오.

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

### 5.2 코어는 `ereport` 를 부르지 않는다

`ereport(ERROR)` 는 `longjmp` 로 빠져나가며 돌아오지 않는다. OpenSSL 이 할당한 `EVP_CIPHER_CTX` 는
PostgreSQL 메모리 컨텍스트가 추적하지 않으므로, 그것이 살아 있는 동안 오류가 나면 새고, 그 안의 키
사본은 지워지지 않는다. 그래서 코어는 오류 코드를 돌려주고, glue 가 모든 OpenSSL 자원을 해제하고 모든
비밀을 지운 뒤에 오류를 올린다. mysql-gcm 이 코어와 어댑터 사이에 긋는 경계와 같고, 오류 모델 때문에
필수가 된다.

### 5.3 어떤 함수도 `IMMUTABLE` 이 아니다

`gcm_encrypt_det` 는 입력에 대해 결정적이므로 `IMMUTABLE` 이 자연스러워 보인다. 거부하는 이유는,
immutable 함수는 인덱스 표현식이나 생성 컬럼에 쓸 수 있고, 그러면 키가 카탈로그(`pg_index`,
`pg_attrdef`)에 리터럴로 남아 `pg_get_indexdef` 로 읽히고 `pg_dump` 에 찍히기 때문이다.
`gcm_decrypt(...)` 에 대한 표현식 인덱스는 평문을 인덱스에 저장하기도 한다. 게다가 `STABLE` 이 그냥
맞는 선언이다. 결과가 `pg_gcm.min_key_bytes` 와 `pg_gcm.strict` 에 따라 달라지기 때문이다.

### 5.4 키는 SQL 인자이고, 설정이 아니다

mysql-gcm 개정 A1 과 같다. `postgresql.conf`, GUC, 테이블, 환경 변수에 키를 두지 않는다. 그 대가 —
문장이 있는 곳 어디서나 키가 보인다 — 는 운영 제약(§6)이며, 완화책은 extension 의 코드가 아니라 바인드
파라미터다.

### 5.5 tag 불일치는 기본값에서 NULL 로 내려가지 않는다

mysql-gcm 과 같다. strict 가 on 이면 오류, off 면 NULL 이다. 잘못된 봉투, 틀린 키 길이, 열기에 성공한
뒤의 잘못된 UTF-8 은 strict 와 상관없이 오류다.

### 5.6 GUC 접두사는 `pg_gcm.`

사용자 정의 GUC 의 접두사는 그것을 정의하는 라이브러리여야 한다. 그래야
`MarkGUCPrefixReserved("pg_gcm")` 가 `pg_gcm.strcit` 같은 오타를 조용히 placeholder 로 만들지 않고
거부할 수 있다. 같은 이유로 mysql-gcm 의 `gcm.` 접두사를 다시 쓰지 않는다.

## 6. 운영 제약 (초안 — Phase 4 에서 `docs/ops-constraints.md` 와 README 로 옮긴다)

1. **키와 평문이 로그와 통계에 나올 수 있다.** `log_statement`, `auto_explain`,
   `pg_stat_activity.query`, 그리고 — `log_min_error_statement` 의 기본값이 `error` 이므로 — 실패한
   모든 문장의 로그 줄, 위조된 tag 오류도 포함해서. 키는 **바인드 파라미터**로 보낸다. 그러면 문장
   텍스트에는 `$1` 만 남고, `log_parameter_max_length_on_error` 를 올리지 않는 한 오류 때 파라미터가
   로그에 남지 않는다. `LIKE` 패턴도 평문 조각이다.
2. **DDL 에 키 리터럴을 절대 넣지 않는다.** 뷰, 컬럼 기본값, 규칙, 트리거, 함수 본문, 정책은
   카탈로그에 저장되고 `pg_dump` 에 찍힌다.
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

- 라이선스: PostgreSQL License (§7, `LICENSE`).
- `pgcrypto` 원시 암호화는 `bf` 와 `aes` 를 `cbc`, `cfb`, `ecb` 로 지원하고, GCM 이나 AEAD 모드는
  없다. PGP 함수는 SHA-1 MDC 를 붙인다. (PostgreSQL 18 문서, §9.)
- MySQL 과 MariaDB 의 `block_encryption_mode` 에는 GCM 이 없다. (mysql-gcm 설계 §1.1, 실측.)

### 미확인 (Phase S 에서 답한다)

| # | 질문 | 확인 방법 |
|---|---|---|
| O1 | 어느 메이저를 지원하나: 15~18, 그리고 나왔다면 19? | postgresql.org 의 현재 지원 정책; 각 메이저에서 스파이크를 빌드하고 실행 |
| O2 | 각 `postgres:<major>` 이미지의 서버가 링크하는 OpenSSL 이 모든 아키텍처에서 3.x 여서 `EVP_CIPHER_fetch` 를 쓸 수 있나? | 각 이미지에서 서버 바이너리를 `ldd`; `openssl version` |
| O3 | `shared_preload_libraries` 를 쓰면 `_PG_init` 이 postmaster 에서 돌고 backend 는 거기서 fork 된다. 물려받은 RAND 상태가 자식마다 다시 시드되나? | OpenSSL 의 fork 감지와 PostgreSQL 의 fork 후 `pg_strong_random_init`; 두 backend 의 첫 nonce 를 비교 |
| O4 | fetch 한 `EVP_CIPHER` 핸들이 fork 를 안전하게 넘나, 아니면 backend 마다 따로 fetch 해야 하나? | OpenSSL 3 의 library context 와 fork 문서; 두 방식 모두 스파이크 |
| O5 | DB 인코딩이 담을 수 없는 UTF-8 문자를 `pg_any_to_server` 가 치환 없이 오류로 거부하나? | `EUC_KR` 과 `LATIN1` DB 에서 스파이크 |
| O6 | `0x01`(AES-256-CBC, PKCS#7, IV 앞붙임)이 32 바이트 키를 쓴 `pgcrypto` 의 `encrypt_iv(..., 'aes-cbc')` 와 맞나? | pgcrypto 로 암호화하고 스파이크로 열기 |
| O7 | 실패 종류(틀린 키 길이, 잘못된 봉투, 잘못된 tag, 잘못된 UTF-8)마다 어떤 SQLSTATE 가 맞나? | `errcodes.txt`; 사용자 정의보다 기존 분류 우선 |
| O8 | CI 에서 `ereport` 경로의 누수 게이트로 valgrind 와 할당 카운터 중 무엇이 나은가? | 스파이크에서 둘 다 시도 |
| O9 | 사용자 정의 GUC 값이 병렬 워커로 직렬화되어, 워커가 리더의 `pg_gcm.strict` 를 보나? | `SET pg_gcm.strict = off` 후 위조된 tag 로 병렬 스캔을 강제 |
| O10 | Debian 의 `postgresql-server-dev-<major>` 패키지가 복제 테스트용 `TAP_TESTS=1` 을 지원하나, 아니면 복제는 compose E2E 에만 두나? | TAP 테스트로 `make installcheck` 시도 |

## 9. 참고 자료

- PostgreSQL 18 문서, F.26 pgcrypto: https://www.postgresql.org/docs/current/pgcrypto.html
- PostgreSQL 문서, C 언어 함수와 `fmgr`: https://www.postgresql.org/docs/current/xfunc-c.html
- PostgreSQL 문서, 관련 객체를 extension 으로 묶기: https://www.postgresql.org/docs/current/extend-extensions.html
- PostgreSQL 문서, extension 빌드 인프라 (PGXS): https://www.postgresql.org/docs/current/extend-pgxs.html
- mysql-gcm `docs/design.md` (개정 A1, A2, A5, A8, A10, A11, A12) 와 `spec/envelope.md`
- NIST SP 800-38D: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- Oracle `DBMS_CRYPTO` (19c 와 23ai/26ai), SQL Server Always Encrypted 암호화 — §1.1 에서만 사용
