# PostgreSQL GCM 암호화 함수 (extension) — 설계와 절차

[English](design.md) | 한국어

> 이 문서는 `docs/design.md` 의 번역이다. 두 문서가 다르면 영어 문서가 맞고, 이 번역을 고친다.

상태: **Phase 4 를 마쳤고 Phase 5 의 패키징을 갖췄다** (2026-10-14).
확장이 명세 — `spec/envelope.md` 와 `spec/test-vectors.json` — 를
구현한다. 세 가지 키 길이, AAD 가 있는 형태와 없는 형태, `pg_gcm.strict` 와 `pg_gcm.min_key_bytes` 까지다.
코어는 단위 테스트에서 모든 벡터를, SQL 함수는 회귀 테스트에서 모든 봉투 벡터를 실행하고, E2E 스위트는
primary 와, primary 가 봉인한 것을 재생만 한 스트리밍 replica 에서 그 함수들을 실행한다. PostgreSQL
15~18 에서다 (§4, §8). 부하 게이트는 복호화 + `LIKE` 스캔을 `pgcrypto` 와 비교해 감시하고, 코어
마이크로 벤치마크는 봉인과 열기를 bare OpenSSL EVP 와 비교해 감시한다 ([`docs/perf.md`](perf.md)).
**두 게이트는 기본 브랜치 `main` 에서 세 번씩 돌았고, 상한은 그 실행들에서 정했다** (§8, O17 답함).
운영 제약은 별도 문서 [`docs/ops-constraints.md`](ops-constraints.md) 에 있고, 릴리스 파이프라인이
tarball 과 그 체크섬, SBOM, 그리고 extension 을 미리 설치한 `postgres:<major>` 이미지를 만든다.
PGXN 메타데이터와 소스 배포 파이프라인도 갖춰져 있다 (§4, Phase 5). 이것 역시 연습만 되고 끝에서
끝까지 관찰되지는 않았다: 아무것도 업로드되지 않았다. **릴리스된 것은 없고
아직 쓸 수 있는 단계가 아니다**: tag 를 자르지 않았고 0.1.0 까지 형식이 바뀔 수 있다. 설계가 기대는
PostgreSQL 동작에 관한 주장은 모두 §9 에 출처가 있거나, 근거와 함께 §8 에
기록되어 있거나, §8 "미확인" 목록에 있다. 이 계획은 2026-10-10 에 PostgreSQL 15~18 소스, 공식 이미지와
대조했고, 스파이크 실행, 명세 작성, 구현을 명세에 맞추는 일은 2026-10-12 에, E2E 스위트 실행과 배포는
2026-10-13 에 했고 두 성능 게이트는 2026-10-14 에 `main` 에서 기록했으며, 각각에서 확인된 것을 §8 에
적었다.

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
  저장하는 대신 문장을 실패시키게 한다 (docs/ops-constraints.md 11 번).
- 함수마다 `COST` 를 명시한다: `gcm_decrypt` 50, `gcm_encrypt` 100, `gcm_encrypt_det` 200 으로, Phase S
  측정에서 나온 둥근 값이다 (§8). C 함수의 기본 비용은 1 이고 플래너는 한 스캔의 조건을 비용 순으로
  배열하므로, 명시하지 않으면 `gcm_decrypt(...) LIKE ...` 가 docs/ops-constraints.md 4 번이 기대는 값싼 조건들 뒤에 놓이지
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

Phase 2 는 스파이크를 명세에 맞췄다 (이슈 #19). version 바이트를 associated data 에 넣었고, 결정적
nonce 도 associated data 에서 유도하며, 코어에 AAD 인자와 24 바이트, 16 바이트 suite 를, glue 에
`pg_gcm.min_key_bytes` 를 더했고, 스파이크 테스트의 인라인 known answer 를 단위 테스트와 회귀 테스트가
읽는 `spec/test-vectors.json` 으로 바꿨다. 관찰한 것은 §8 "Phase 2 에서 확인된 것" 에 있다.

코어(`gcm.c`, `envelope.c`, `nonce.c`)는 C11 이고 PostgreSQL 헤더를 포함하지 않는다. glue
(`fn_*.c`)는 인자, 인코딩, GUC, 오류를 다룬다. 단위 테스트는 서버 없이 모든 벡터로 코어를 돌리고,
`pg_regress` 가 SQL 동작을 덮는다. 호출 지점 단위의 키 스케줄 캐시는 기준선을 잰
뒤에 이 문서의 개정을 거쳐 넣으며, `flinfo->fn_extra` 와 키 사본을 지우는 메모리 컨텍스트 리셋
콜백을 쓴다. 그 개정은 수명 한계를 스스로 정해야 한다. `FmgrInfo` 는 한 문장보다
오래 살 수 있다 — PL/pgSQL 은 단순 표현식의 상태를 트랜잭션이 끝날 때까지 유지한다
(`pl_exec.c`, `shared_simple_eval_estate`).

### Phase 3 — SQL E2E

primary, 스트리밍 replica, Python 러너로 된 compose 파일: 왕복, 한국어 `LIKE`, 복제 (replica 가 자신이
암호화하지 않은 암호문을 읽는다), 그리고 NULL 인자가 NULL 을 주는 것. `tests/e2e` 가 그것이고
`scripts/e2e.sh <major>` 로 실행한다. 거기서 본 것은 §8 "Phase 3 에서 확인된 것" 에 있다.

### Phase 4 — 배포

메이저 × 아키텍처 빌드 매트릭스는 `build.yml` 이다 (§4, Phase 2). 이 phase 는 패키징, 배포 이미지,
그리고 두 성능 게이트를 더한다. `scripts/package.sh` 가 `pg_gcm-<version>-pg<major>-<arch>.tar.gz` 와
그 체크섬을, `scripts/sbom.py` 가 CycloneDX SBOM 을 쓰고, `release.yml` 이 tag (SemVer, `main` 위,
`pg_gcm.control` 과 일치, CHANGELOG 에 `## <version>` 절) 를 검사한 뒤 tarball, `SHA256SUMS`, 그
keyless 서명, SBOM 을 게시한다. `workflow_dispatch` 실행은 dry run 이다. `docker/server.Dockerfile`
은 빌드한 extension 을 `postgres:<major>` 위에 얹고 init 스크립트에서 `CREATE EXTENSION pg_gcm` 을
실행한다. `scripts/server-image.sh` 가 그것을 만들고 `scripts/smoke-image.sh` 가 이미지 자체의 init 에
대해 한국어 `LIKE` 왕복을 푸시 전에 확인한다. 운영 제약은 `docs/ops-constraints.md` 이고, 부하 기준선과
두 성능 게이트는 `docs/perf.md` 다. 게이트와 이미지가 실제로 무엇을 하는지는 §8 "Phase 4 에서 확인된
것" (2026-10-13) 과 "Phase 4 에서 확인된 것 (2026-10-14)" 에 있고, 게이트의 상한은 뒤의 세 번
`main` 실행에서 나왔다.

### Phase 5 — 생태계

PGXN, 그다음 수요가 있으면 배포판 패키징. `META.json` 은 배포본의 메타데이터다 (PGXN Meta Spec
1.0.0). `scripts/check-pgxn.py` 는 그것을 그 명세 — 필수 필드, 그 값에 대한 규칙, 그리고 맵이 자기
키나 사용자 정의 `x_` 키만 담아야 한다는 규칙 — 에 대해 검증하고, 명세가 할 수 없는 교차 검사를
더한다: 버전이 `pg_gcm.control` 과 일치하는지, 제공하는 `file` 과 `docfile` 이 존재하는지,
extension 버전이 배포본 버전과 같은지, PostgreSQL 하한이 지원 범위인지. `scripts/pgxn-dist.sh`
는 소스 아카이브 `pg_gcm-<version>.zip` 을 `git archive HEAD` 로 쓴다 — 최상위 디렉터리 하나가
`pg_gcm-<version>/` 인, PGXN Manager 가 기대하는 배치다 — 그리고 `dist/` 바깥의 디렉터리에 쓰므로
체크섬이 붙는 릴리스 산출물에 끼지 않는다. `release.yml` 의 `publish` job 은 메타데이터를 검증하고
아카이브를 만든 뒤, tag 일 때만 HTTP Basic 인증으로 PGXN Manager 에 업로드한다. `workflow_dispatch`
는 아카이브를 검증·생성만 하고 업로드하지 않는다. 배포본은 0.1.0 이 pre-release 인 동안
`release_status` 가 "testing" 이다: 봉투 형식이 아직 바뀔 수 있고 프로젝트가 아직 쓸 수 있는 단계가
아니므로, PGXN 이 그것을 stable 설치로 제공해서는 안 된다. 배포판 패키징 (Debian, RPM) 은 수요를
기다리며 만들지 않는다. 검사기와 아카이브가 실제로 무엇을 하는지, 무엇이 아직 기록되지 않았는지는
§8 "Phase 5 에서 확인된 것" 에 있다.

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
  함수로 감싼 사용자는 그것에 인덱스를 걸 수 있다. 이것은 운영 제약 (docs/ops-constraints.md 2 번) 이고 extension 이 막을
  수 있는 일이 아니다.

### 5.4 키는 SQL 인자이고, 설정이 아니다

`postgresql.conf`, GUC, 테이블, 환경 변수에 키를 두지 않는다. 그 대가 —
문장이 있는 곳 어디서나 키가 보인다 — 는 운영 제약(docs/ops-constraints.md)이며, 완화책은 extension 의 코드가 아니라 바인드
파라미터다.

서버 안에서 암호화하면 extension 이 옮길 수 없는 신뢰 경계가 그어진다. `pgcrypto` 가 스스로에 대해
문서화한 것과 같은 경계다 ("Security Limitations", §9). 키와 평문은 클라이언트 연결을 건너고, 관리자가
통제하는 서버의 메모리에 존재한다. 이 설계가 지키는 것은 저장된 컬럼, 백업, 그리고 암호문만 가진
replica 다. 보호되지 않은 연결, DB superuser, 서버의 OS 관리자로부터는 지키지 못한다 (docs/ops-constraints.md 12 번).

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
  봉인할 때는 앞서는 검증이 없으므로 — 확장은 인자를 DB 인코딩에 대해 검증하지 않는다 — 변환을 멈춘
  원인이 무엇이든 짧은 개수는 변환할 수 없는 문자로 보고한다 (명세 §2.4). 변환된 텍스트의 길이는 `strlen` 으로
  구한다. 서버 자신의 `convert` 함수들처럼 glue 도 변환 프로시저가 출력을 NUL 로 끝낸다는 데
  기댄다. 조회가 `pg_catalog` 로 한정되어 있으므로, 이를 깰 수 있는 것은 superuser 가 거기에 넣은
  프로시저뿐이다.
- 변환 프로시저는 `FindDefaultConversion(PG_CATALOG_NAMESPACE, …)` 로 얻는다. 카탈로그 조회이고, 변환이
  없으면 glue 가 두 인코딩의 이름을 담아 `42883` 을 올린다. 비밀 사본이 생기기 전에 실행한다.
  `pg_catalog` 에서만 찾고 `search_path` 를 따라가지 않는다 (§8 O14).

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

## 6. 운영 제약

운영자가 지켜야 할 제약은 여기서 확정되어 [`docs/ops-constraints.md`](ops-constraints.md) 에
유지된다. 그 모두는 [`README.md`](../README.md) 첫 화면에도 있다. 그것은 이 코드가 아니라 배포에
속한다. extension 이 보호할 수 있는 것과 없는 것은 §5.4 의 신뢰 경계로 정해져 있고, `postgresql.conf`
의 어떤 설정도 그것을 옮기지 못한다. 배포 전에 그 문서를 읽고, 정확하게 유지한다 — SQL 함수만큼이나
이 프로젝트의 결과물이다.

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
  `FindDefaultConversionProc` 는 `search_path` 를 따라간다 (O14, Phase 2 에서 결정). `-Wextra` 는 서버 자신의
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
  nonce 봉투는 여전히 두 번째 봉투가 된다. 결정적 컬럼이 이에 대해 할 일은 docs/ops-constraints.md 5 번에 있다. 이 phase
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

### Phase 2 에서 확인된 것 (2026-10-12)

- **코드가 명세를 구현한다.** 코어는 여섯 version 바이트 모두를 `A = version || aad` 로 봉인하고 열며,
  결정적 nonce 를 `be64(len(A)) || A || P` 에서 유도한다. glue 는 인자 세 개짜리 형태와
  `pg_gcm.min_key_bytes` 를 더한다. 단위 테스트는 `spec/test-vectors.json` 을 읽고, 77 개 벡터 중 어느
  스위트도 소비하지 않는 것이 있으면 실패하는 테스트가 있다. NIST 벡터 15 개는 테스트 seam 을 통해
  프리미티브에서, 모든 봉투 벡터는 open 으로, 유효한 벡터는 자기 nonce 로 seal 해서 (결정적 벡터는
  스스로 유도하고, `gcm_nonce_derive` 만 따로 불러 유도된 nonce 각각과도 비교한다) 실행하고, 실패하는 벡터는 출력 버퍼가 0 으로 지워졌는지까지 본다. 회귀 테스트도 같은
  파일을 읽는다. 봉투 벡터 62 개가 `pg_gcm.strict` on 과 off 에서 `gcm_decrypt` 를 거치고, nonce 가
  유도되는 결정적 벡터 11 개는 바이트 단위로 같은 봉투로 봉인된다. 이제 테스트에 직접 적힌 known
  answer 는 없다. PostgreSQL 15.19, 16.15, 17.11, 18.6 (OpenSSL 3.5.7), 17.11 (OpenSSL 3.0.22),
  19beta4 에서 관찰했다: 단위 테스트 302 개, 회귀 파일 18 개, 그리고 라이브러리를 지연 로드한 경우와
  preload 한 경우의 `scripts/verify.sql`.
- **nonce 충돌 테스트.** 한 키와 한 AAD 로 서로 다른 평문 100 만 개를 결정적으로 봉인하면 서로 다른
  nonce 100 만 개가 나온다 (PR 에서는 10 만 개). 이는 유도 과정이 제대로 연결됐는지 보는 점검이다 —
  너무 적은 바이트로 잘리거나 입력이 상수면 실패한다 — 96 비트 nonce 의 birthday bound 에 대해서는
  아무것도 말해 주지 않으며, 어떤 테스트도 거기에 닿을 수 없다. docs/ops-constraints.md 의 9 번 항목이 그대로 규칙이다.
- **O14 — 변환은 `pg_catalog` 에서만 찾는다.** `FindDefaultConversion(PG_CATALOG_NAMESPACE, …)` 를 쓴다.
  17.11 에서 관찰한 것: superuser 가 아니어도 스키마에 `CREATE` 권한이 있는 role 은 거기에 기본 변환을
  만들 수 있고, `search_path` 를 따라가면 내장 변환보다 먼저 발견된다. 다만 이미 있는 함수만 묶을 수
  있다. `CREATE CONVERSION` 은 내장 함수를 그 함수가 대상으로 하지 않는 인코딩 쌍에 묶는 것을
  거부했고, 그 role 은 C 함수도 internal 함수도 만들 수 없었다. 따라서 노출은 superuser 가 설치한 변환
  함수가 호출자의 `search_path` 에 따라 선택되는 경우였다. `pg_catalog` 에서 찾으면 결과가
  `search_path` 와 무관해진다. 대가는, 사이트가 DB 인코딩에 대해 따로 둔 기본 변환을 이 함수들이 쓰지
  않는다는 것이다. 회귀 테스트 `conversion_lookup` 이 15~18 과 19beta4 에서 그 차이를 보인다. 내장
  변환의 기본 표시를 지운 일회용 EUC_KR DB 에서 모든 함수가 `42883` 을 내고, `search_path` 의
  스키마에 기본 변환을 두어 서버 자신의 `SET client_encoding` 이 그것을 찾게 된 뒤에도 계속 `42883`
  을 낸다. `scripts/check-architecture.py` 도 `src/` 의 `FindDefaultConversionProc` 를 거부한다. 기본
  상태의 서버에서 `42883` 은 거의 도달할 수 없다. 17.11 에서 UTF-8 로의 변환이 없는 서버 인코딩은
  MULE_INTERNAL 하나였고, 19beta4 에는 그 인코딩이 없다.
- **O15 — 호출마다 찾는 형태를 유지하고, 하한도 3.0.0 그대로다.** 17.11, OpenSSL 3.5.7 (arm64 노트북 한
  대, 두 번 실행, 잘해야 2 배 이내의 정밀도) 에서 `gcm_encrypt_det` 는 호출당 약 1.1 µs,
  `gcm_encrypt` 는 0.6 µs, `LIKE` 를 붙인 `gcm_decrypt` 는 0.3 µs 다. 앞의 둘 사이 0.5 µs 에는 digest 를
  이름으로 찾는 비용뿐 아니라 HMAC-SHA256 두 번도 들어 있으므로, 미리 준비한 컨텍스트로 아낄 수 있는
  양의 상한이다. 절감분 자체는 따로 재지 않았다. 그 반대편에는 3.0.0 에서 실패하는 컨텍스트가 있다.
  결정적 변형은 조인 키와 정확 일치 조회용이지 대량 텍스트용이 아니므로, 이것 때문에 하한을 올리지
  않는다. bench 게이트가 무작위 봉인에 대한 결정적 봉인을 기록한다 — 2026-10-14 의 세 번 `main` 실행에서
  16 바이트 1.22~1.68 부터 65536 바이트 3.34~4.06 까지 (`docs/perf.md`) — 그리고 다시 열 자리는 그
  기록된 비율이다; load 게이트는 `gcm_encrypt_det` 를 부르지 않는다.
- **`pg_gcm.min_key_bytes` 와 placeholder**, 15~18 과 19beta4 (회귀 테스트 `min_key_bytes`). 라이브러리가
  로드되기 전에 superuser 가 설정한 값은 로드될 때 유지된다. 16, 24, 32 가 아닌 값은 경고와 함께
  버려지고 기본값이 적용된다. 이 파라미터를 설정할 수 없는 role 이 설정한 값은 라이브러리가 로드될 때
  "permission denied to set parameter" 와 함께 버려지므로, placeholder 는 `PGC_SUSET` 을 우회하는
  길이 아니다. `GRANT SET ON PARAMETER` 로 위임한다. 설정보다 짧은 키는 `22023` 과 전용 메시지로
  거부되고, 어떤 suite 에도 해당하지 않는 길이는 설정과 무관하게 키 길이 메시지를 유지한다.
- **라이브러리는 SQL 함수만 내보낸다.** PGXS 는 PostgreSQL 16 부터만 `-fvisibility=hidden` 으로
  컴파일한다. 15 용 빌드의 `nm -D` 에는 테스트 seam 둘을 포함한 코어 함수 전부가 나왔고, 각각 동적
  링커를 통해 호출할 수 있으며 먼저 로드된 라이브러리가 가로챌 수 있었다. SQL 에서 닿는 것은 없었다.
  이제 프로젝트 헤더가 SQL 에서 호출하는 함수 외의 모든 것을 hidden visibility 로 선언하고,
  `scripts/build-in-docker.sh` 는 동적 심볼이 정확히 그 함수들, 그 fmgr 레코드, `_PG_init`,
  `Pg_magic_func` 가 아니면 실패한다. pragma 를 뺀 빌드에서 실제로 실패하는 것을 확인했다.
- **CI.** `unit.yml` 은 libcrypto 마다 빌드 이미지 하나 (가장 새로운 지원 메이저, 그리고 OpenSSL 하한)
  에서 sanitizer 를 켜고 단위 테스트를 실행한다. `build.yml` 은 `docker/versions.json` 의 모든 이미지를
  amd64 와 arm64 에서 `-Werror` 로 빌드하고, `pg_gcm.so` 가 서버 자신의 `libcrypto.so.3` 로 해석되지
  않으면 실패한다. `regress.yml` 은 모든 이미지에서 `make installcheck` 와 `scripts/verify.sql` 을
  실행한다. 셋 다 이미지 목록을 그 파일을 읽는 `scripts/ci-matrix.py` 에서 받는다.
  `continue-on-error` 인 job 은 없다. 그 설정에서는 실패해도 실행이 실패하지 않아 놓치기 쉽기 때문이다.
  프리릴리스 이미지는 눈에 보이게 실패하고, 그 job 만 required check 로 삼지 않는다 (O1). GitHub 는
  schedule 을 기본 브랜치에서만 실행하므로, nightly 실행은 이 파일들이 `main` 에 들어갈 때 시작된다.
  그때까지 100 만 평문 실행은 `develop` 에 push 할 때마다 일어난다.
- **Phase 전체 리뷰 이후 (2026-10-13).** `gcm_decrypt` 는 결과를 평문 길이에 맞춰 할당하므로, 코어는
  항상 정확히 암호문 길이만큼의 버퍼를 받는다 — 빈 텍스트면 버퍼가 없다 — 그리고 단위 테스트는 모든
  봉투 벡터를 그렇게, 버퍼 뒤에 가드 바이트를 두고 연다. EVP 가 그 이상 쓰지 않는다고 약속하는 것은
  블록 크기가 1 인 cipher 뿐이고 AES-GCM 이 그렇다. `gcm_init` 은 fetch 한 cipher 마다 이를 요구하고,
  cipher 가 보고하는 키 길이가 그 이름이 뜻하는 길이일 것도 요구한다. EVP 가 키에서 그만큼의 바이트를
  읽기 때문이다. 다르게 보고하는 cipher 는 없는 것으로 취급한다. 저장소 안에 그 거부에 닿는 테스트는
  없다. 다른 블록 크기나 키 길이를 보고하는 프로바이더가 있어야 하기 때문이다. 벡터 파일에는 78 번째 벡터 `tag-last-bit-flipped-empty` — 빈
  텍스트의 29 바이트 봉투에서의 tag 실패 — 가 추가되어, 단위 테스트는 78 개, 회귀 테스트는 63 개를
  실행한다. `54000` 테스트는 길이를 집합 반환 함수로 넘긴다. 상수였을 때는 플래너가 `repeat()` 를
  접어 사본을 하나 더 들고 있었고, 백엔드 피크가 285 MB 가 아니라 547 MB 였다.
- **어떤 테스트도 다루지 않는 것.** `54000` 은 변환 버퍼가 한계인 경우 — EUC_KR DB 에서 256 MB 텍스트를
  봉인할 때 — 만 테스트하고, 1 GB 근처의 한계와 여는 쪽은 테스트하지 않는다. tag 불일치나 거부된
  할당이 아닌 EVP 호출 실패 (O8, 변함없음). 백엔드 밖에서는 관찰할 수 없는 `PG_FINALLY` 의 cleanse.
  UTF-8 이 아닌 DB 에서는 호출마다 카탈로그에서 변환을 찾고 함수 관리자를 통해 호출하는데, 그 비용은
  Phase 4 의 부하 게이트 전에는 측정하지 않는다. 스위트는 CI 에서는 amd64 로, 개발 장비에서는 arm64 로
  실행된다. arm64 에서 CI 는 컴파일만 하고 실행하지 않는다.

### Phase 3 에서 확인된 것 (2026-10-13)

- **스위트.** `tests/e2e/compose.yml` 은 공식 이미지로 primary 와 replica 를 띄우고 — 빌드는 각 컨테이너가
  시작할 때 그 안에 설치된다 — SQL 만 보내며 키를 bind 파라미터로 넘기는 러너 (Python, `psycopg`) 를
  띄운다. replica 는 primary 의 `pg_basebackup` 이고 primary 로부터 스트리밍한다. 시나리오는 21 개이고,
  PostgreSQL 15.19, 16.15, 17.11, 18.6 (OpenSSL 3.5.7), 17.11 (OpenSSL 3.0.22), 19beta4 에서 관찰했다.
  셋은 두 번째 노드가 말한 그대로의 것임을 확인한다. recovery 중이고 WAL receiver 가 primary 로부터
  스트리밍하고 있으며, 쓰기를 거부하고, `CREATE EXTENSION` 을 primary 에서만 실행했는데도 확장의
  카탈로그 항목이 있다. 아홉은 각 노드에서 실행한다. 모든 이름이 돌아온다. 인자 두 개짜리 형태로
  봉인한 메모는 그 형태로 열린다. 복호화한 값에 대한
  `LIKE '%길%'` 이 그 글자가 든 두 이름을 찾는다. primary 에서 결정적으로 봉인한 값은 어느 노드에서든
  거기서 다시 봉인해 찾을 수 있다. 같은 값이라도 AAD 가 다르면 찾지 못한다. 두 테이블이 쿼리에 키가
  전혀 없이 결정적 봉투로 조인된다. 위조된 tag 는 `pg_gcm.strict` on 에서 `XX001`, off 에서 NULL 이다.
  열다섯 인자 위치 각각의 NULL 은 NULL 을 준다. 러너는 첫 시나리오 전에 replica 가 primary 의 마지막
  WAL 위치까지 재생하기를 기다리고, 30 초 안에 되지 않으면 실패한다. 종료 상태가 0 인 것은 unittest 가
  실행한 모든 시나리오가 통과로 기록되고, 하나 이상 실행됐고, 두 노드가 같은 공유 시나리오를 실행했을
  때뿐이다. lint 워크플로의 `run.py --self-test` 는 이 게이트가 실패, 오류, skip, 실패한 subtest,
  예상된 실패, 예상 밖의 성공, 빈 실행을 거부하는지, 그리고 시나리오가 서로 다르거나 하나도 없는 두
  클래스를 거부하는지 확인한다. 첫 시나리오 전의 대기는 WAL receiver 의 상태도 포함하므로,
  `streaming` 을 단정하는 시나리오가 막 연결된 receiver 를 만나지 않는다.
- **docs/ops-constraints.md 의 7 번 항목을 관찰했다.** replica 의 디스크에서 라이브러리를 뺀 경우 (17.11 에서 21 개
  시나리오를 손으로 실행), 카탈로그 항목은 그대로 있었고 봉투에 대한 조인도 그대로 동작했으며, 거기서
  함수를 호출하는 일곱 시나리오는 `could not access file "$libdir/pg_gcm"` 로 실패했다. 21 개 중 14 개가
  통과했고 게이트는 닫혔다. NULL 시나리오는 거기서도 통과했다.
  `STRICT` 함수는 NULL 인자에 대해 호출되지 않으므로 라이브러리가 로드되지도 않는다.
- **보여 주지 않는 것.** 스위트의 네트워크는 러너와 서버 사이에서 키와 평문을 암호화 없이 나른다.
  공개된 테스트 키를 쓰는 테스트용 네트워크이지 배포 형태가 아니다 (docs/ops-constraints.md 의 12 번 항목). 논리 복제
  구독자, 승격된 replica, 나중에 복원한 base backup, 서로 다른 메이저 사이나 확장의 서로 다른 빌드
  사이의 복제는 테스트하지 않는다. CI 에서는 amd64 로, 개발 장비에서는 arm64 로 실행된다.
- **CI.** `e2e.yml` 은 `main` 이나 `develop` 으로의 push 때, 그리고 확장이나 스위트나 그것을 빌드하는 것을 바꾸는 PR 에서
  `docker/versions.json` 의 모든 이미지로 스위트를 실행한다. required check 가 아니다. 그것은
  `regress.yml` 에 있다.

### Phase 4 에서 확인된 것 (2026-10-13)

여기서 "실행" 은 개발 장비에서 이 저장소의 스크립트를 돌린 것과, 게이트를 받아 갈 워크플로를
뜻한다. tag 는 자르지 않았고 아무것도 릴리스하지 않았다.

- **부하 게이트.** `tests/load/run.py` 는 한국어 이름 N 행을 한 테이블에 두 번 봉인한다 —
  `gcm_encrypt` 와 `pgcrypto` `encrypt_iv(..., 'aes-cbc')`, 같은 키로. 그리고 `sessions` 에
  걸쳐 교차로, 어느 쿼리도 기계를 독점하지 않게, `gcm_decrypt(...) LIKE '%김%'` 스캔과 CBC 스캔을
  시간 재어 각각의 p95 와 그 비율을 보고한다. Phase S 와 같이 JIT 와 병렬 워커를 끄어 두 플랜의
  모양을 같게 하고, 테이블을 `VACUUM (ANALYZE, FREEZE)` 하며, 쿼리별 워밍업 한 번을 버리고, 각
  셀이 쿼리당 `samples` 번의 스캔을 모아 한 세션에서도 p95 가 백분위수가 되게 한다. 게이트는
  `tests/load/baseline.json` 에 대한 게이트 대상 셀 — baseline 의 `gated_sessions`, 즉 낮은 동시성
  셀 — 의 최악의 비율이고 밀리초가 아니라서 이식 가능하다. 10k 행의 높은 세션 셀은 암호가 아니라
  스케줄링에 묶여 기록만 하고 게이트하지 않는다. `run.py --self-test` 는 답이 알려진 케이스에 대해
  판정과 게이트 대상 규칙, 비율의 방향을 확인하고 lint 워크플로에서 실행된다. Phase S 의 네 번의
  실행이 기대값이고 (GCM 쿼리가 CBC 쿼리의 0.49~0.63 을 차지했다, 위 step 7), 상한은 1.0 — GCM 이 더
  느리지 않다는 설계의 요구다.
- **마이크로 벤치마크.** `tests/bench/benchmark.cc` (Google Benchmark) 는 코어의 `gcm_seal` (무작위와
  결정적) 과 `gcm_open` 을 같은 모양의 직접 짠 EVP AES-256-GCM 과 16, 256, 4096, 65536 바이트에서
  재고, `tests/bench/baseline.json` 의 같은 것끼리의 세 비율을 게이트로 삼는다 — bare EVP 에 대한
  무작위 봉인과 열기, 그리고 같은 두 번의 HMAC-SHA256 과 같은 AES-GCM 을 치르는 bare 결정적 봉인에
  대한 결정적 봉인. 각 벤치마크는 무작위 순서로 다섯 번 돌고 게이트는 중앙값을 읽어, 시끄러운 한 번의
  반복이 비율을 움직이지 못한다. 기준선의 nonce 는 코어의 무작위 봉인과 같이 무작위라, 봉인 비율이
  한쪽만 내는 비용이 아니라 코어 자체의 봉투와 점검을 재게 되고, 상한은 크기별이다 — 코어의 고정된 호출
  비용은 작은 메시지에서 더 큰 몫이다. 무작위 봉인에 대한 결정적 봉인은 기록만 하고 게이트하지 않는다:
  O17 프로브가 그것이 이식 가능하지 않음을 찾았다 (아래 bullet). 바이너리의 `--self-test` 가 판정과 비율의
  방향, 고정 측정값에 대한 게이트를 확인한다. 서버도 PostgreSQL 헤더도 관여하지 않는다.
- **배포 이미지.** `docker/server.Dockerfile` 은 공식 `postgres:<major>` (base 는 digest 로 고정) 이고,
  빌드한 `pg_gcm.so`, `pg_gcm.control`, SQL 을 그 이미지 자체의 `pg_config` 가 이르는 디렉터리에
  설치하며, `docker/initdb.d/00-pg_gcm.sql` 이 `/docker-entrypoint-initdb.d` 에 있어 처음 init 때
  `CREATE EXTENSION pg_gcm` 이 실행된다. `scripts/smoke-image.sh` 가 이미지를 띄워 `HEALTHCHECK` 를
  기다리고 — 스스로 `CREATE EXTENSION` 을 하지 않고 — `홍길동` 을 봉인·개방하고 `LIKE '%길%'` 을
  확인한다: 실패나 extension 부재는 0 이 아닌 종료다.
- **릴리스 파이프라인.** `scripts/package.sh` 는 빌드를 `pg_gcm-<version>/…` 로 펼쳐
  `pg_gcm-<version>-pg<major>-<arch>.tar.gz` 와 그 체크섬을 쓴다. `scripts/release-guard.py` 는
  `vMAJOR.MINOR.PATCH` 가 아닌 tag, `pg_gcm.control` 의 `default_version` 과 다른 tag, `main` 의
  조상이 아닌 tag, `## <version>` CHANGELOG 절이 없는 tag 를 거부한다. `scripts/sbom.py` 는
  extension, 그 PostgreSQL 과 libcrypto 의존성, 모든 산출물의 SHA-256 을 담은 CycloneDX 1.5 문서를
  쓴다 — extension 은 `metadata.component` 에만 두어 `bom-ref` 가 중복되지 않는다. `release.yml` 은
  지원 major 를 amd64 와 arm64 로 패키징하고, `scripts/smoke-tarball.sh` 가 각 tarball 을 공식
  이미지에 얹어 라운드 트립을 실행하므로 배포되는 바이트가 모든 아키텍처에서 로드된다. `server` job 은
  배포 이미지를 빌드·smoke 한 뒤에야 모든 tarball 이 통과했고 tag 일 때만 keyless cosign 으로 서명해
  푸시한다. `publish` job 은 SBOM 과 `SHA256SUMS` (SBOM 파일 자체 포함) 를 쓰고, 체크섬을 서명하고
  GitHub release 를 만든다. `workflow_dispatch` 실행은 푸시·서명·릴리스만 빼고 모든 것을 연습한다. 두
  헬퍼 스크립트의 `--self-test` 는 lint 워크플로에서 실행된다.
- **그 시점에 아직 기록되지 않은 것, 그리고 O17 프로브가 찾은 것.** bench 게이트는 `develop` 에서 돌아 본 적이
  있었다 (2026-10-13, 런 `38380818627`, 통과; 2026-10-14, 런 `38496259310`, 실패). load 게이트는 일회성
  프로브 전까지 CI 러너에서 돌아 본 적이 없었다. `tests/load/baseline.json` 과
  `tests/bench/baseline.json` 의 상한은 Phase S 의 기대값이고 당시 O17 이 들고 있던 placeholder 이지 러너의
  측정이 아니었다. 그 프로브 (2026-10-14, `ci/perf-probe`; bench 런 `38497426020`, `38497735934`,
  `38497746227`, load 런 `38497426196`, `38498234824`, `38498245407`; O17 의 세 번에는 포함되지 않는다) 가 GitHub
  러너에서 둘 다 돌려 게이트 하나를 바꿨다. load 게이트는 매 실행 통과했다 — 최악 gated 비율 0.84~0.88 로
  설계가 요구하는 1.0 아래였고, 약 4분이 걸렸다. bench 게이트는 어떤 러너에서는 통과하고 어떤 러너에서는
  실패했다: `seal` 과 `open` 은 어디서나 약 1.0 이었지만, 무작위 봉인에 대한 결정적 봉인의 비율은 약
  1.2~9.6 이었다 (65536 바이트에서 약 3.3~9.6). 그 비율은 SHA-256 에 묶인 봉인을 AES 에 묶인 봉인과
  비교하는데, 두 연산은 러너 CPU 와 libcrypto 에 따라 다르게 확장된다: 가장 빠른 65536 바이트 AES-GCM
  셀 (AMD EPYC 9V45, Intel Xeon 8573C — 둘 다 AVX-512, OpenSSL 3.5.7) 은 가장 느린 셀 (AMD EPYC 7763,
  EPYC 9V74, OpenSSL 3.0.22 포함) 의 약 5배였다. 따라서 그 비율은 이 코드의 속성이 아니며 게이트가 될 수
  없다. 그래서 O17 은 `det` 게이트를 같은 것끼리 비교하도록 — 같은 모양의 bare 결정적 봉인에 대한 결정적
  봉인 — 재정의하고 그 비율을 게이트하지 않고 기록하는 것으로 답했다. tag 를
  자른 적이 없고 릴리스도 게시하지 않았으므로 파이프라인은 연습만 되고 끝에서 끝까지 관찰되지는 않았으며,
  배포 이미지는 smoke 테스트만 됐다.

### Phase 4 에서 확인된 것 (2026-10-14) — O17 을 답했다: 두 게이트를 `main` 에서 기록

워크플로마다 기본 브랜치에서 세 번씩, 매번 `docker/versions.json` 의 두 이미지를 돌렸고, 상한은 관측된
최악값에서 정했다. 여기서는 `main` 에서 돈 실행만 센다: GitHub 은 schedule 과 dispatch 를 기본
브랜치에서 읽고, 게이트는 조용한 머신을 원한다. 러너 모델은 AMD EPYC 7763, AMD EPYC 9V45, AMD EPYC
9V74, Intel Xeon Platinum 8573C 네 가지이고 모두 4 vCPU 였다.

- **load 게이트.** 런 `38518507148`, `38518993036`, `38519339009` (셋 다 2026-10-14 에 `main` 에서
  디스패치) 가 두 이미지의 9셀 매트릭스에서 gated 셀을 모두 통과했다. 여섯 job 중 최악 gated 비율은
  **0.860** 이었다 (100k 행 × 8 세션, `38519339009` 의 `18` 이미지). 곱하기 1.2 는 1.032 이고 소수 첫째
  자리로 올림하면 1.1 이며 설계 요구값에서 잘리므로, `tests/load/baseline.json` 의 `max_ratio` 는
  **1.0** 그대로다; 기록만 하는 32 세션 셀은 0.75~0.91 이었고, 10k 행만 보면 0.86~0.91 이다. 런별 러너
  CPU 는 `docs/perf.md` 의 표에 있다.
- **마이크로 벤치마크.** 런 `38518367089` (브랜치를 승격한 push), `38518733427`, `38518740737` 이
  같은 모델들에서 통과했다. 크기별 최악 관측값은 16, 256, 4096, 65536 바이트에서 봉인 1.048, 1.090,
  1.024, 1.011; 열기 1.052, 1.036, 1.019, 1.005; det 1.027, 1.027, 1.012, 1.005 였다. 곱하기 1.2 하고
  소수 첫째 자리로 올리되 대체한 placeholder 보다 높이지 않으면 `tests/bench/baseline.json` 의 상한이
  된다: 256 바이트 봉인의 1.4 를 빼고 모두 1.3 이다. 무작위 봉인에 대한 결정적 봉인은 기록만 하고
  게이트하지 않는데, 크기별로 1.22~1.68, 1.26~1.74, 2.12~2.57, 3.34~4.06 이었고, O15 에서 호출당
  digest 조회를 다시 열 조건도 그 기록에서 읽는다. `docs/perf.md` 에 크기별 최악값과 거기서 나온
  상한이 있다.

### Phase 5 에서 확인된 것 (2026-10-13)

여기서 "실행" 은 개발 장비에서 이 저장소의 스크립트를 돌린 것이다. 아무것도 업로드하지 않았고 tag 도
자르지 않았으므로, PGXN 경로는 연습만 되고 끝에서 끝까지 관찰되지는 않았다.

- **`META.json`.** 배포본 메타데이터는 PGXN Meta Spec 1.0.0 이다: `name` 은 `pg_gcm`, SemVer
  `version` 은 `pg_gcm.control` 과 일치하고, `license` 는 `postgresql`, `provides` 는 extension 을
  지목하며 그 `file` 은 버전이 붙은 SQL 스크립트, `docfile` 은 `README.md` 다.
  `prereqs.runtime.requires.PostgreSQL` 하한은 15.0.0 이고, 저장소·버그 트래커·홈페이지는
  `resources` 에, `tags` 는 검색을 위해 있다. `release_status` 는 `testing` 이다: 0.1.0 은
  pre-release 이고 — 봉투 형식이 아직 바뀔 수 있으며 아직 쓸 수 있는 단계가 아니므로 — PGXN 이
  그것을 stable 설치로 제공해서는 안 된다. `no_index` 는 에이전트 설정, CI 파일, 개발 스크립트를
  PGXN 문서 색인에서 제외한다.
- **검사기.** `scripts/check-pgxn.py` 는 그 명세의 규칙 — 필수 필드, 값에 대한 규칙, 사용자 정의
  `x_` 예외를 둔 미지의 키 규칙, prereq phase·relation·버전 범위 — 을 구현하고, 명세가 할 수 없는
  교차 검사를 더한다: 제어 파일에 대한 버전, 작업 트리에 대한 제공 `file`·`docfile`, 배포본 이름과
  extension 버전을 `pg_gcm` 과 배포 스크립트가 만드는 아카이브에 대고, 15.0.0 이상을 요구하는
  PostgreSQL 하한. `--self-test` 는 41 가지 판정을 낸다 — 한 번에 한 가지씩 깨뜨린 37 개 문서, 검사기가
  받아들여야 하는 세 문서, 유효한 문서 자신 — 그리고 각각이 기대대로이기를 요구한다. 관측: 41 가지
  모두. lint 워크플로가 검사기, 그 `--self-test`, 그리고 아카이브 배치에 대한
  `scripts/pgxn-dist.sh` 를 실행한다.
- **아카이브.** `scripts/pgxn-dist.sh` 는 검사기를 통해 버전을 읽고, 더러운 작업 트리를 거부하며,
  출력 디렉터리를 절대 경로로 바꾸고 — 다른 디렉터리에서 준 상대 경로가 아카이브와 배치 검사에서
  같은 곳을 가리키게 — `git archive HEAD` 와 접두사 `pg_gcm-<version>/` 로
  `pg_gcm-<version>.zip` 을 쓴다. 그런 다음 아카이브를 열어 접두사 아래에 `META.json`, `Makefile`,
  `pg_gcm.control` 이 있는지, 최상위 디렉터리가 정확히 하나인지, 아카이브 자체의 `META.json` 버전이
  이름과 맞는지 요구한다. 관측: HEAD 의 아카이브는 그 모두를 통과했고, 커밋되지 않은 변경이 있는
  작업 트리는 거부됐으며, pgxn 클라이언트 (1.3.2) 가 그 아카이브를 PostgreSQL 17 빌드 이미지에서
  빌드·설치했고 거기서 `CREATE EXTENSION pg_gcm` 과 한국어 `LIKE '%길%'` 왕복이 통과했다.
- **릴리스 단계.** `release.yml` 의 `publish` job 은 아카이브를 `dist/` 바깥에 만들어 체크섬이 붙는
  산출물에 끼지 않게 한다; 그 빌드는 릴리스보다 앞서므로 업로드가 거부할 메타데이터는 거기서
  실패한다. GitHub release 를 만든 뒤 `manager.pgxn.org/upload` 로는 마지막에 업로드한다 — 되돌릴 수
  있는 단계를 되돌릴 수 없는 단계보다 앞에 — 그리고 릴리스와 업로드는 멱등하므로 재실행이 이미 된
  일에서 실패하지 않고 부분 릴리스를 마무리한다: `gh release view` 는 이미 있는 release 를
  건너뛰고, 이미 게시된 버전 (`api.pgxn.org/dist/pg_gcm/<version>/META.json`) 은 PGXN 이 두 번 받지
  않으므로 그대로 둔다. 업로드는 `curl` 에 HTTP Basic 인증, multipart 필드 `archive`, 그리고
  `X-Requested-With: XMLHttpRequest` — 성공은 `200`, 거부된 배포본은 `409` 다. `PGXN_USER` 와
  `PGXN_PASSWORD` 는 required reviewer 가 있는 `release` environment 의 secret 이다.
  `workflow_dispatch` 실행은 아카이브를 검증·생성만 하고 아무것도 업로드하지 않는다.
- **보여주지 않는 것.** 업로드는 실행된 적이 없고, 위의 아카이브 빌드와 왕복은 CI 가 아니라 한 메이저
  에서 손으로 했다: 아카이브의 소스는 `build` 와 `regress` 워크플로가 컴파일하는 바로 그 추적
  파일들이므로 거기서 커버되고, 업로드는 첫 tag 를 위해 남겨 둔다. 메타데이터는 아직 PGXN Manager
  자체 검증기를 거친 적이 없다. 배포판 패키징 (Debian, RPM) 은 만들지 않는다 (Phase 5 는 수요를 위해
  남겨 둔다). Phase 5 는 O17 이 열린 채로 했다: PGXN 경로는 두 성능 게이트를 지나지 않으므로,
  그 게이트가 기다리는 기록은 이 작업의 전제가 아니었다.

### 미확인

번호는 다시 쓰지 않는다. O2~O17 은 위에서 답했다. O7, O13, O16 은 Phase 1 에서, O14 와 O15 는 Phase 2
에서, O17 은 Phase 4 에서 답했다.

| # | 질문 | 확인 방법 |
|---|---|---|
| O1 | 19 는 언제 지원 메이저에 들어가나? 15~18 은 정해졌다. 19 는 beta 4 이고, RC1 은 2026-10-15, 출시는 2026-10-29 로 공지됐다 (pgsql-hackers, 2026-09-28). 확장은 `19beta4` 에서 빌드되고 모든 스위트를 통과하며, 그 CI job 은 pre-release 라고 표시되고 required check 로 삼지 않는다 | 릴리스 이미지가 나오면 `docker/versions.json` 에서 `prerelease` 를 `supported` 로 옮긴다 |

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
