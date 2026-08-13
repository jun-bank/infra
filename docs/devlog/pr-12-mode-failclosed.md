# PR #12 — 모드 조회: 모르면 실행하지 않는다

이 문서는 배포 모드(dev 자동 / 운영 승인)를 읽는 코드가 왜 "모르면 dev"가 아니라 "모르면 승인"인지를 다룬다. S1 마일스톤의 마지막 조각이고, 이 프로젝트에서 fail-open이 실제 사고 형태로 확인된 첫 자리 중 하나다.

## 문제와 원인

두 가지 문제가 있었다. 첫째, **승인 게이트가 장애로 열릴 수 있다** — "모드를 모르면 dev"는 저장 장애가 곧 승인 우회가 되는 형태다. 그래서 저장 접근 실패·모드 부재·미지의 모드 문자열 전부를 operational(승인 필요)로 닫는다. 둘째, **토글과 요청이 경쟁한다** — 모드 토글은 배포 요청이 아니라서(락을 잡지 않는다) 배포 진행 중에도 일어날 수 있고, 수락 시점과 적용 시점 사이에 모드가 바뀌면 승격 전 모드로 실행된다. 그 창은 mode version을 수락 시 읽고 적용 직전에 재검증하는 것으로 닫는다.

배경에는 "dev는 환경이 아니라 모드다"라는 결정이 있다(ADR-024 — 스테이징 없음). dev에서도 락·서명·이력·적용 순서는 그대로고, 자동이 되는 것은 방아쇠 하나뿐이다. 그래서 모드 판정은 게이트가 아니라 오케스트레이션의 소유다 — 대상(target)은 검증된 manifest에서 오고, 원자 검증은 락 획득과 같은 자리에서 서야 하기 때문이다.

## 채택 — 장애로 닫힌 것과 원래 운영인 것을 구별한다

```go
// internal/deploy/mode.go:47-70 (발췌) — fail-closed 3분기
// 저장 접근 실패·mode 부재(ErrNoMode)·미지의 mode 문자열(손상)은 전부
// operational(승인 필요)로 닫는다 — fail-closed(DO-17 ⑷). "모드를 모르면 dev"가 아니다:
// 승인 게이트가 장애로 열리면 승인 없이 배포가 나가므로, 모르면 승인 쪽으로 닫는다.
func DecideMode(ctx context.Context, r ModeReader, target string) ModeDecision {
    mode, version, err := r.Current(ctx, target)
    if err != nil {
        return ModeDecision{Mode: ModeOperational, ApprovalRequired: true, FailClosed: true}
    }
    ...
}
```

`FailClosed` 플래그가 따로 있는 이유가 이 설계의 요체다 — "운영이라 승인 필요"와 "장애라 안전하게 닫음"이 사후에 구별돼야 한다. 기록이 없으면 "승인 없이 배포된 것"과 "승인이 필요 없는 대상이었던 것"이 구별되지 않는다는 원 결정(DO-5)과 같은 논리다. store는 행이 없으면 기본값을 지어내지 않고 `ErrNoMode`를 올린다 — fail-closed 판정 자리를 한 곳(호출자)으로 유지하기 위해서다.

## 리뷰가 만든 코드 — 단조 version의 fail-open

codex 리뷰가 High 2건을 냈고, 첫째가 이 PR의 가장 뼈아픈 발견이다. `UNIQUE(target, mode_version)` 제약은 **중복만 막고 더 작은 새 version의 삽입을 허용**한다 — dev/v2가 있는 상태에서 operational/v1을 넣어도 성공하고, "현재"는 최댓값 행이므로 계속 dev/v2다. 성공한 운영 토글이 반영되지 않는 fail-open이다. 수정은 version 결정권을 호출자에게서 빼앗는 것이었다:

```sql
-- deploy/schema/02_procedures.sql:351-363 (발췌) — 프로시저가 max+1을 원자 계산
CREATE PROCEDURE `sp_mode_append`(...)
BEGIN
  INSERT INTO `deploy_mode` (`target`, `mode`, `mode_version`, `actor`)
  SELECT p_target, p_mode, COALESCE(MAX(`mode_version`), 0) + 1, p_actor
    FROM `deploy_mode`
   WHERE `target` = p_target;
END $$
```

Go 쪽에서는 version 파라미터 자체가 사라졌다 — 임의 version을 넘길 자리가 없으니 낮은 version이 들어갈 길이 원천 차단되고, 동시 호출이 같은 max를 노리면 UNIQUE가 한쪽을 거부한다. 단조성이 프로시저 계산과 DB 제약 두 계층에서 강제된다.

둘째 High는 TOCTOU다 — `VerifyModeUnchanged`가 독립 SELECT 후 version만 비교하므로, 검증 직후·락 획득 전에 토글이 나면 이미 반환된 OK로 자동 배포가 이어진다. 이번 수정은 재조회한 mode의 유효성 검사까지였고, 창을 진짜로 닫는 락·모드 단일 트랜잭션 원자성은 S2(#14)로 명시 이월됐다 — 코드 주석에 그 창이 `[구현 검증]`으로 남아 있다.

## 검증

거절·안전 경로 우선의 단위 8건(-race 포함)과 Testcontainers 통합 — 최신 행 선택, ErrNoMode, 대상 격리, 단조 강제, 그리고 agent 계정의 모드 행 UPDATE/DELETE가 GRANT 차원에서 거부되는지(append-only)까지다. fix 커밋은 "낮은 version 무효화" 통합 테스트를 red-first로 추가했다.

## 다음으로의 연결

S1 마일스톤이 여기서 닫혔다. 이 시점의 회고 기록이 남긴 집계가 인상적이다 — 듀얼 리뷰가 잡은 실결함 셋(빈 requestId·malformed nbf·단조 version) 모두 codex가 Opus의 누락을 보완했고, 전부 fail-open 방향이었다. 이월된 TOCTOU는 이슈 #14(HTTP→오케스트레이션 배선)로, 모드 대상 ENUM은 나중에 gateway가 4번째 배포 대상이 되며 마이그레이션으로 확장된다.
