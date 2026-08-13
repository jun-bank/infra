# PR #18 — HTTP→오케스트레이션 배선

이 문서는 501 스텁이던 종단 수신을 실제 배포 시퀀스로 이은 과정을 다룬다. 각 단계의 실패가 "락을 풀고 끝낼 실패"인지 "락을 쥔 채 사람을 부를 실패"인지를 가르는 것이 이 PR의 실제 설계 노동이었고, 그 판단 대부분이 리뷰로 다듬어졌다 — fix 커밋 9개가 전부 리뷰 산물이다.

## 문제와 원인

이 PR은 두 일을 한 브랜치에서 했다. 하나는 배선 자체 — 파싱 → 모드 판정 → 락 획득 → mode version 재검증 → manifest 검증 → fencing 재확인 → dispatch(스텁) → 해제. 다른 하나는 이슈 #9(예약 후 재실행 갭)를 함께 닫으려는 시도였다.

#9를 파는 도중 안전 결함이 나왔다. jti 재사용도 재전송으로 분류되는데, 미예약 새 requestId로 재개하면 예약-우선 불변식이 깨진다 — 재사용된 토큰의 새 requestId가 예약 없이 부작용을 여는 셈이다. 그래서 재개는 "재전송이니까"가 아니라 **이력이 양성으로 예약을 증명할 때만** 하도록 좁혔다.

그리고 이 PR의 가장 정직한 부분은 #9를 닫지 못한다고 판정한 것이다. 재전송 분류의 default 분기("이력 없음 = 미예약")와 호출 문맥의 전제("ErrReplay = 예약 확정")가 어긋나는데, 예약과 이력 append가 별개 쓰기라 이력이 유실되면 미완 배포가 stranded되는 창이 남는다. 원자성(예약+락+mode version+이력 단일 트랜잭션)은 실 dispatch를 소유하는 S2-3의 몫이라, 이 PR은 `Closes #14`만 달고 #9는 열어 뒀다.

## 채택 — CD-4의 비대칭을 코드 분기로

핵심 설계는 실패의 종류를 다른 Outcome으로 가르는 것이다. 락 경합은 기록할 거절(`LOCK_CONTENDED`), 저장·검증 불가는 fail-closed. 그리고 CD-4의 규칙 — 전환 전 실패는 락을 풀고, 전환 이후의 부분 실패는 락을 쥔 채 사람을 부른다 — 를 그대로 옮겨, UNKNOWN만 락을 유지한다.

```go
// internal/deploy/coordinator.go:217-226 (발췌) — dispatch 직전 fencing 재확인
// lease가 만료돼 다른 점유자가 진입했거나(held=false) 판정 불가(err)면 dispatch를
// 시작하지 않는다 — 만료·탈취된 락으로 특권 실행을 여는 것을 막는다(좀비 차단).
if held2, cerr := hold.Confirm(ctx); cerr != nil {
    return Result{Outcome: OutcomeFailClosed, State: StateUnexecuted, Detail: "fencing 재확인 오류 — dispatch 미시작"}
} else if !held2 {
    return Result{Outcome: OutcomeFailClosed, State: StateUnexecuted, Detail: "fencing 상실(lease 만료·탈취) — dispatch 미시작"}
}
```

이 `Confirm` 호출이 PR #16이 만들어 두고도 부르지 않았던 프리미티브를 처음 실제로 쓰는 자리다. 락 해제는 요청 ctx와 분리한다 — 요청이 취소됐어도 락은 반드시 놓아야 하는데, 취소된 ctx를 재사용하면 해제가 즉시 실패해 lease 만료까지 누수되기 때문이다.

## 리뷰가 바꾼 것 — fix 9개 전부

Opus가 예약-우선 불변식이 정확히 구현됐음을 확인(반증 시도가 통과로 끝남)한 한편, 실패 처리 곳곳에서 결함이 나왔다. 두 High가 특히 중요하다.

하나는 오류 검사 순서 — `derr != nil`을 `switch state`보다 앞에 둬서, dispatch가 `(UNKNOWN, err)`를 내면 UNKNOWN 분기(락 유지)에 못 가고 fail-closed로 접혀 **락이 풀렸다**. 다른 하나는 durable 기록 유실 — `recordDispatch`가 이력 append 오류를 `_ =`로 버려, UNKNOWN/COMPLETED가 durable하지 못한 채 통과해 재전송이 재실행할 수 있었다. 나머지 med 7건은 `Confirm` 미호출, digest 형식 검증(64자 hex 강제), defer 해제의 ctx 재사용, 죽은 필드와 거짓말하는 주석 제거 등이었다. 라운드 2는 정의 밖 dispatch 상태가 default로 락을 푸는 fail-open과 `History=nil`이면 완료를 증명할 근거 없이 COMPLETED가 되는 것을 잡아, 후자를 기동 시 panic(fail-closed)으로 바꿨다.

브랜치 위생 사고도 하나 기록됐다 — 이전 브랜치가 rebase로 SHA가 바뀐 옛 커밋을 중복 포함해 충돌 상태였는데, force-push 대신 오케스트레이션 커밋만 현재 main 위로 cherry-pick한 clean 브랜치로 교체했다(force 금지 정책 준수).

## 다음으로의 연결

dispatch는 여전히 스텁이라 정상 요청은 501을 받는다 — "조용한 성공 위장 금지"가 명시적 설계였다. 실행은 PR #22가 채우고, 그때 실 dispatch의 durable 기록이 서면서 이슈 #9의 완료 조건이 충족된다(좁은 창은 코드 주석에 남은 채). 락과 mode version을 한 트랜잭션으로 묶는 원자성은 여전히 `[구현 검증]` 이연으로 남았다.
