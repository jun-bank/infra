# PR #2 — 레이아웃과 배포 스키마 DDL: 기록의 계약부터

이 문서는 infra의 첫 코드가 왜 Go 파일이 아니라 DDL이었는지를 다룬다. 이 PR 직전까지 배포 오케스트레이션의 결정(ADR-027 v0.3, ADR-022 DT-9~12)은 전부 문서 안에만 있었다 — 결정은 다 났는데 실행되는 것이 하나도 없는 상태에서, 가장 먼저 세운 것은 "배포 기록을 어디에 어떤 계약으로 남기나"였다.

## 문제와 원인 — "없다"가 "금지"로 읽히고 있었다

이 스키마가 존재하게 된 경위 자체가 흥미로운 사건이다. 원래 운영 문서에는 "agent에게 DB 계정을 주지 않는다"는 규칙이 있었고, 그 근거는 ADR-022 권한 매트릭스에 배포 주체 계정이 **없다**는 것이었다. 그런데 재검에서 이것이 오독으로 판정됐다 — "이 표가 그 계정을 갖고 있지 않다"는 사실이지 "가지면 안 된다"는 판정이 아니었는데, 사실이 판정처럼 쓰이고 있었다.

그 오독이 만든 실제 문제가 둘 있었다. 락 조작의 제공자가 코어라서 코어가 응답하지 않으면 락을 잡을 수 없고 배포도 롤백도 불가능한데, 롤백이 필요한 순간이 바로 그 순간이다(제공자 순환). 그리고 락은 코어 스키마의 DB 행이고 배포 이력은 agent 로컬 파일이라 "락을 잡은 시각과 배포 이력이 맞나"를 한 곳에서 판정할 수 없었다(대조 불가). 해법이 배포 전용 스키마(deploy)다 — 새 서버 제품이 아니라 이미 있는 MySQL의 스키마 하나이므로 도구 최소주의(C-08)와도 충돌하지 않는다.

## 채택 — 권한 단위는 테이블이 아니라 "정의된 연산"

핵심 결정은 DT-12다: 배포 스키마의 어느 계정도 raw DML을 갖지 않는다. 락 행은 일곱 가지 전이(획득·lease 갱신·PREEMPT 기록·안전 경계 ACK·override 획득·채무 해소·해제) 각각의 저장 프로시저로만 바뀌고, 이력 테이블은 append-only(INSERT만)다. 그래서 배포 스키마에 "자유롭게 갱신되는 행"은 하나도 없다.

같은 규칙을 코드 계층에서도 강제했다 — `internal/store`는 일반 Exec/Query 메서드를 아예 노출하지 않는다. GRANT에서 금지된 것이 코드에서도 도달 불가능하도록, **동일한 규칙을 두 계층에서** 강제한다는 것이 커밋 메시지에 적힌 원리다.

```sql
-- deploy/schema/01_tables.sql:59-71 (발췌) — 재전송 방어를 UNIQUE 제약에 맡긴다
-- Append-only. requestId와 jti는 어떤 부작용이 있기 전에 예약된다; UNIQUE 제약은
-- 재생(동일 requestId, 또는 재사용된 OIDC jti)을 재실행 대신 INSERT 시점에 요란하게
-- 실패시킨다. 예약은 삭제할 수 없으므로(append-only, DT-12 ⑵) 재생 방어는 writer의
-- 선의에 의존하지 않는다.
CREATE TABLE IF NOT EXISTS `deploy_request_ledger` (
  `request_id`  VARCHAR(255) NOT NULL,
  `jti`         VARCHAR(255) NULL,
  `body_digest` VARCHAR(128) NOT NULL,
  PRIMARY KEY (`request_id`),
  UNIQUE KEY `uq_jti` (`jti`)
) ENGINE=InnoDB;
```

```sql
-- deploy/schema/03_grants.sql:50-51 — GRANT를 안 쓴 것이 결정이다
-- 다른 어떤 스키마에도 GRANT 없음. 그 부재가 곧 강제다(DT-10 ⑵): deploy-agent는
-- core/settlement/ledger에 접근이 전혀 없다 — 읽기 포함(R7).
```

fencing token의 단조성("절대 감소하지 않는다")도 주석이 아니라 프로시저가 소유한다 — 모든 획득마다 증가하고 리셋되지 않으며, 낡은 보유자는 다음 재확인 시 토큰 불일치로 감지된다.

```go
// internal/store/store.go:239-254 (발췌) — 컴파일 타임 단언과 "없는 메서드"
// SQLStore가 모든 store 인터페이스를 만족한다는 컴파일 타임 단언.
var (
    _ LockStore    = (*SQLStore)(nil)
    _ LedgerStore  = (*SQLStore)(nil)   // Reserve(INSERT)만 노출 — 삭제 메서드가 없다
    _ ModeStore    = (*SQLStore)(nil)
    _ HistoryStore = (*SQLStore)(nil)
)
```

## 검증

이 PR에는 듀얼 리뷰 기록이 없다 — 대신 계약 스모크 6종이 있었다. 실제 MySQL 8 컨테이너에 DDL을 적재하고, agent 계정의 raw UPDATE가 거부되는지, 핸드셰이크 ACK 전 override가 거절되는지, fencing이 단조 증가하는지, requestId 재전송이 UNIQUE로 거부되는지, EXECUTE 전용 계정이 테이블 권한 없이 프로시저로 변경에 성공하는지(SQL SECURITY DEFINER 성립)를 확인했다. 시크릿 스캔이 코드를 바꾼 기록도 있다 — 하드코딩된 포트가 발견돼 env 조회로 바꾸고 해당 커밋을 재작성했다.

## 다음으로의 연결

이 PR이 만든 구조 하나는 곧바로 뒤집혔다 — 별도 프로세스로 세운 `cmd/dispatcher`는 다음 PR(#7)에서 삭제된다. 토폴로지 재판정(단일 바이너리 + ROLE 모드)이 그 사이에 있었기 때문이다. 그리고 이 스키마는 나중에 실제로 뚫린다 — S2-1(PR #16)에서 실행 있는 리뷰가 반대 계정의 락 해제, 0초 lease, 유령 락 3건을 실 MySQL에서 실증했고, 수정은 역할별 wrapper 프로시저로 갔다. "스키마를 세웠다"와 "스키마가 안전하다" 사이의 거리를 보여주는 대목이며, 그 이야기는 PR #16 문서에서 이어진다.
