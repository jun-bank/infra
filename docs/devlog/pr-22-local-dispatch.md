# PR #22 — 로컬 dispatch: pull·up·헬스

이 문서는 처음으로 부작용이 있는 코드 — 실제로 이미지를 받고 컨테이너를 띄우는 실행 층 — 이 들어온 과정을 다룬다. 그래서 이 PR의 핵심 질문은 "어떻게 실행하나"가 아니라 "실행 결과를 무엇으로 부를 것인가"였고, 리뷰 3루프가 잡은 결함은 거의 전부 그린 위장(silent COMPLETED)과 락 밖 실행이었다.

## 문제와 원인 — 실행 결과를 세 상태 중 무엇으로 부르나

스텁을 실 dispatcher로 바꾸는 일이지만, 부작용이 생기는 순간 판정 문제가 커진다. pull 실패는 compose를 건드리지 않았으니 부작용 0(UNEXECUTED), up·헬스 실패 후 정리 성공은 미전환(UNEXECUTED), 정리 실패는 green이 남았을 수 있으니 UNKNOWN, green이 뜨고 digest 대조·헬스를 통과하면 COMPLETED다. 변이 명령은 각 1회만 — 자체 재시도 루프를 두지 않는다(UNKNOWN에 단순 재시도 금지).

특히 헬스체크의 그린 위장이 반복 주제다 — "프로세스가 떴다"만 보는 헬스체크는 DB 권한 오설정·스키마 불일치를 통과시킨다. 그래서 헬스 앞에 digest 대조를 둔다: 헬스는 "떴는가"만 보지 "무엇이 떴는가"는 못 본다.

## 채택 — 열거 명령만, argv 슬라이스만

특권 실행은 열거된 명령만 argv 슬라이스로 실행한다 — 셸 해석을 거치지 않으므로 raw shell 금지가 코드 형태로 강제된다. 열거 밖의 Action은 argv를 아예 만들지 않는다.

```go
// internal/deploy/dispatcher.go:261-292 (발췌) — 4단계와 DO-16 매핑
// 1. 이미지 pull. 실패 = 부작용 0(compose 미접촉) = UNEXECUTED.
if err := exec.Pull(phaseCtx, imageRef); err != nil {
    return StateUnexecuted, ...
}
// 2. green 기동. down 성공=미전환(UNEXECUTED), down 실패=green 잔존 가능(UNKNOWN).
if err := exec.Up(phaseCtx, imageRef); err != nil {
    return cleanupAfterFailure(ctx, exec, "compose up 실패", err)
}
// 3. 이미지 무결성 대조. env 없이 :latest·오타 이미지가 헬스만 통과하면 위장한다.
if err := exec.VerifyImageDigest(phaseCtx, imageRef); err != nil {
    return cleanupAfterFailure(ctx, exec, "이미지 무결성 대조 실패", err)
}
// 4. CD-1 헬스. 실패 → green 종료·blue 유지 = 미전환(롤백 아님).
if err := health.Check(ctx); err != nil {
    return cleanupAfterFailure(ctx, exec, "CD-1 헬스 실패", err)
}
return StateCompleted, nil
```

dispatch 전체를 lease 안에 예산으로 가둔 것도 이 PR의 결정이다 — lease 갱신 goroutine을 두지 않는(무갱신) 모델을 택하는 대신, 기동 시 `lease ≥ 단계예산 + 헬스deadline + 정리 + 전환 + slack`을 검증해 미달이면 기동을 거부한다.

## 리뷰 3루프가 잡은 것 — 그린 위장의 카탈로그

이 PR은 stakes 높음의 첫 사례로, codex ∥ Opus에 blind 테스트 워커까지 붙어 3루프를 돌았다. 루프별로 잡힌 것이 그린 위장의 목록에 가깝다:

- **루프 1**: up 후 digest 미대조(엉뚱 이미지가 헬스만 통과) · 그린위장 방어선이 컨테이너명 미설정 시 통째로 생략 · baseline을 첫 표본에서 잡아 첫 프로브 중 재시작을 놓침 · 실행 중 락 상실.
- **루프 2**: `ps -q`가 종료된 컨테이너를 은닉해 부분기동인데 COMPLETED · unbounded pull이 lease 보증을 깸 · fencing 없는 cleanup이 다른 배포가 올린 green을 철거.
- **루프 3(최종 게이트)**: lease 하한식이 digest 대조를 빼먹어 조건부로만 성립 · 거대 duration이 int64 overflow로 음수가 돼 작은 lease가 검증을 통과하는 fail-open · orphan이 pinned digest면 현재 app이 오타여도 가려짐.

그린 위장 방어선을 예외 없이 항상 켜는 것과 baseline을 대기 시작 전 1회 고정하는 것이 이 루프들의 결론이다 — 대상 컨테이너를 설정이 아니라 compose 프로젝트에서 파생하고, 확정하지 못하거나 재시작을 읽지 못하면 fail-closed(판정 불가 = 실패). orphan 완전 방어는 "어느 compose 서비스가 app인지"를 결박해야 하는데, 그것은 호스트 compose 매핑과 얽혀 별도 이슈(#21)로 분리하고 코드에 명시 마커를 남겼다("무음 이연 아님").

검증은 이 개발 머신에서 무해한 테스트 이미지(임의 GET에 200을 돌려주는 이미지)로 실제 리허설 — pull→up→헬스→COMPLETED, pull과 up의 digest 일치 실증, down 후 이미지 보존(롤백 성립), 부분기동 검출까지 밟았다.

## 다음으로의 연결

이 PR의 "이연(후속 이슈)" 목록이 그대로 다음 마일스톤의 backlog가 됐다 — #19(compose revision 결박), #20(실행 실패 Outcome 분리), #21(사후조건 identity 결박), 그리고 블루-그린 전환(#26). 그런데 이 PR이 만든 실행 경로가 실서버에서 처음 도는 순간이 곧 다음 사건이다 — 첫 실배포에서 "배포는 됐는데 배포가 실패했다"는 모순 상태(false-UNKNOWN)가 터진다. 그 이야기는 PR #25 문서에 있다.
