# PR #16 — 배포 창 락: 획득·fencing 재확인·해제

이 문서는 배포 창 락의 Go 배선과, 이 프로젝트에서 가장 극적인 리뷰 사건을 다룬다. 같은 락 코드를 두고 한 리뷰어는 "프로덕션 코드 clean"으로, 다른 리뷰어는 "실 MySQL 익스플로잇으로 High 3건 실증"으로 — 정반대 판정이 나온 자리다.

## 문제와 원인

작업 자체는 공백 메우기였다 — DB에는 락 전이 프로시저(S0에서 세운 일곱 전이)가 있는데 Go에서 부르는 코드가 없었다. 락의 계약은 "조회가 아니라 획득"이다: 점유자가 없거나 lease가 만료됐을 때만 내 식별자·새 fencing token·새 lease로 바꾸는 조건부 UPDATE 하나, 영향 행 1 = 획득, 0 = 거절. 배선의 기술적 난점은 MySQL OUT 파라미터였다 — 세션 변수로 받아야 하는데 세션 변수는 커넥션 로컬이라, 커넥션 풀 위에서 CALL과 SELECT가 다른 커넥션으로 흩어지면 값이 조용히 어긋난다. `callProc` 헬퍼가 두 문장을 하나의 고정 커넥션에 묶는다.

## 리뷰 라운드 1 — 논증과 실행이 갈린 자리

Opus는 6개 렌즈로 정독한 뒤 프로덕션 코드를 clean으로 판정했다(테스트 갭만 지적). codex는 실제 MySQL에 스키마를 올리고 익스플로잇을 시도해 High 3건을 실증했다:

1. **반대 계정이 남의 락을 해제할 수 있다** — 두 계정이 kind를 인자로 받는 공유 프로시저에 EXECUTE를 가지므로, 커트오프 계정이 AGENT 락을 release해 성공한다.
2. **0초·음수 lease가 무보호 락을 만든다** — 즉시 만료된 락이 "획득 성공"으로 돌아온다.
3. **미지 kind·NONE kind로 유령 락이 생긴다.**

정반대 판정이 갈린 이유는 방법의 차이였다 — Opus는 SQL 의미를 논증해 clean으로 읽었고, codex는 그 논증이 실제 MySQL에서 성립하지 않는 지점을 실행으로 뚫었다. 이날의 결론이 이 프로젝트의 검증 문화를 만들었다: "리뷰어를 늘리는 것"만으로는 부족했고 "실제로 실행해 보는 것"이 있어야 잡혔다.

## 수정 — kind를 리터럴로 결박한 wrapper

수정 방침은 역할별 wrapper 프로시저 + 무권한 impl 분리다. 로직은 kind를 인자로 받는 impl에 두되 어느 계정에도 impl EXECUTE를 주지 않고, 각 계정은 kind가 리터럴로 박힌 자기 wrapper만 실행한다 — 상대 kind로는 애초에 호출할 수 있는 프로시저가 없다. 이 방침은 착수 시 load-bearing 가정 하나를 달고 있었다("DEFINER 하에서 wrapper의 중첩 CALL이 impl EXECUTE 없이 성립한다") — 착수 직후 통합 스모크로 실증됐다.

```sql
-- deploy/schema/02_procedures.sql:72-96 (발췌) — 세 방어선을 한 IF에
IF p_holder_kind IS NULL OR p_lease_seconds IS NULL
   OR p_holder_kind NOT IN ('AGENT', 'BATCH_CUTOFF') OR p_lease_seconds < 1 THEN
  -- NULL 입력 · 미지 kind(유령 락) · 최소 미만 lease(무보호 락) = fail-closed 거절.
  SET p_ok = 0;
ELSE
  UPDATE `deploy_window_lock`
     SET ... `fencing_token` = `fencing_token` + 1, ...
   WHERE `lock_id` = 1
     AND (`holder_kind` = 'NONE' OR `lease_expires_at` < NOW(6));
  IF ROW_COUNT() = 1 THEN
```

재점검(라운드 2)이 두 겹을 더했다 — 이미 프로비저닝된 DB에 구 취약 프로시저가 남아 있으면 새 wrapper를 배선해도 구판으로 구멍이 계속 열려 있으므로 DROP 정리(MySQL은 DROP 시 EXECUTE 권한도 함께 제거), 그리고 NULL 입력이 `NOT IN` 검사를 UNKNOWN으로 우회해 만료 없는 무보호 락을 만드는 fail-open 차단이다.

검증은 red-first의 교과서적 사례다 — 미수정 스키마에서 프로브 테스트로 세 결함을 재현 통과시켜(RED 증거) 결함의 실재를 먼저 증명하고, 수정 후 정식 회귀 테스트(교차 계정 거부·lease 하한·kind 거절·24-goroutine 동시 획득)로 바꿨다.

## 다음으로의 연결

오케스트레이션에 노출된 프리미티브는 셋이다 — 획득(`AcquireWindow`), 불가역 단계 직전 보유 재확인(`Confirm`), 해제. 그런데 `Confirm`은 이 PR에서 노출만 되고 실제로 호출되지 않았다 — 그 갭은 다음 PR(#18)의 리뷰가 잡는다. 긴급 롤백 인계(override 핸드셰이크)는 인터페이스만 확정하고 스텁으로 남았다. 그리고 이 락이 "실행을 지키는" 이야기 — lease가 dispatch 전체를 덮는가 — 는 PR #22에서 이어진다.
