# deploy 스키마 — DDL

배포 스키마는 공유 MySQL 클러스터의 네 번째 스키마이며 배포 경로의 지속적 사실의
원천이다: 배포 윈도우 락, 재생 방어 ledger, mode, history가 모두 여기 살기에 부작용을
여는 일 — 요청 예약, mode 버전 확인, 락 획득 — 이 하나의 데이터베이스에 대한 하나의
트랜잭션이 된다(ADR-022 §2.1, ADR-027 §2.2).

파일을 순서대로 적재한다:

1. `00_schema.sql` — `deploy` 스키마를 생성한다(DT-9).
2. `01_tables.sql` — 단일 행 락 테이블과 세 개의 append-only 테이블(history, request
   ledger, mode)(DT-9, DT-12).
3. `02_procedures.sql` — 일곱 개의 락 전이(DT-12, ADR-024 §2.4).
4. `03_grants.sql` — 두 계정과 그 최소 grant(DT-10, DT-11, DT-12).

## DDL이 정본을 어떻게 반영하는가

**락에는 자유롭게 갱신되는 행이 없다(DT-12 ⑶).** 어떤 계정도 `deploy_window_lock`에 raw
DML을 갖지 않는다; 그것은 일곱 개의 프로시저를 통해서만 바뀐다. fencing-token 증가,
holder 조건, lease 검사, 그리고 모든 전이 가드는 프로시저 내부에 살기에, 전이를
`EXECUTE`할 수 있는 계정조차 owner, token, lease를 위조할 수 없다. `SELECT` + `EXECUTE`가
락에 대한 각 계정 권한의 전부다.

**일곱 개의 전이와 그 호출자는 분리된다(DT-12 ⑴).** acquire, renew, release는
deploy-agent와 cutoff 계정 둘 다 호출할 수 있다(하나의 행에 대한 양방향 경합).
record-preempt와 override-acquire는 deploy-agent 전용이다. safety-boundary-ack와
resolve-open-debt는 cutoff 전용이다. 이 분리는 관례가 아니라 프로시저별 `EXECUTE`
grant로 강제된다.

**§2.4 핸드셰이크는 "정지 후 인계"이며, 단일 UPDATE가 아니다.**
`sp_lock_override_acquire`는 preempt가 기록되었고 *그리고* holder가 정지를 ack했거나 그
lease가 만료된 뒤에만 성공한다 — 그래서 선점된 스케줄러가 아직 쓰고 있는 동안에는(그것은
RL-4 버전 스큐를 재도입할 것이다) 롤백이 절대 시작되지 않는다. 인계가 ack 없이 lease
만료를 통한 것이면 스케줄러가 "열림"을 적재하기 전에 죽은 것이므로, 프로시저는
`open_debt`를 설정한다; 다음 cutoff 실행은 `sp_lock_resolve_open_debt`가 그것을 지우기
전까지 그 영업일을 마감할 수 없다.

**Append-only는 실재한다(DT-12 ⑵).** ledger, mode, history 테이블은 `INSERT` + `SELECT`만
받는다 — `UPDATE`/`DELETE` grant 없음 — 이므로 재생 ledger와 history를 그것들을 쓰는
계정이 다시 쓸 수 없다. request ledger의 `PRIMARY KEY (request_id)`와 `UNIQUE (jti)`는
재생을 재실행 대신 `INSERT` 시점에 실패시키며(ADR-027 DO-10), writer의 선의와 무관하다.

**deploy-agent는 money 데이터에 접근이 전혀 없다(DT-10 ⑵).** `deploy` 스키마만
부여받는다; core, settlement, ledger는 읽기를 포함해 단 한 셀도 받지 못한다(ADR-022 R7은
무관용).

## [구현 검증] CDV-19 / ADR-022 R8

MySQL이 실제로 이 최소 형태를 표현하는지는 구현 시점에 검증된다: `SQL SECURITY DEFINER`가
`EXECUTE` 전용이고 테이블 권한이 없는 계정이 전이를 실행하게 하는지; append-only가 grant
만으로 성립하는지(아니면 trigger/`REVOKE` 조합이 필요한지); 그리고 어떤 기본값/`PUBLIC`/
역할 상속 경로도 더 넓은 권한을 누설하지 않는지. Testcontainers 통합 스위트
(`internal/store`)가 이 검사들의 실행 가능한 형태를 소유한다(test-strategy L1: 트랜잭션
경계와 원자성은 인메모리 대체물이 아니라 오직 실제 MySQL에 대해서만 검증된다).
