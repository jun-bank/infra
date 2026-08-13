# PR #7 — HTTP 골격: 아직 아무것도 실행하지 않는 서버

이 문서는 deploy-agent의 HTTP 진입점이 선 과정과, 그 과정에서 직전 PR의 구조가 곧바로 갈아엎어진 사건을 다룬다. 이 PR이 만든 것은 판정 로직이 아니라 "서명·검증·멱등을 끼울 자리"다 — 그리고 그 자리의 배치(미들웨어 체인의 순서)가 이후 모든 게이트의 뼈대가 됐다.

## 문제와 원인 — 하루 만에 낡은 구조

문제는 두 겹이었다. 첫째, 진입점이 없었다 — 설계는 "엣지 → agent"까지 그렸지만 agent 쪽에 요청을 받을 표면이 없었다. 둘째, PR #2가 세운 3-프로세스 구조(agent·dispatcher·watchdog)가 이미 낡아 있었다. 그 사이에 사용자 토폴로지 결정이 있었기 때문이다: 각 호스트가 자기 서버를 배포하고, 인프라 도구는 docker를 제어해야 하므로 컨테이너로 못 띄우며, 전송이 SSH에서 "호스트별 로컬 agent에 서명 RPC"로 바뀌었다. SSH forced-command의 대상이던 별도 dispatcher 바이너리는 존재 이유가 사라졌다.

검토된 대안들이 기록에 남아 있다. 역할을 프로세스 둘로 나누는 안은 "모드의 단순함을 해친다"로 기각됐고(단일 바이너리 + `ROLE` env — DO-21), watchdog만은 모드 통합이 기각됐다(agent가 죽어도 감시해야 하므로 같은 프로세스면 안 된다). 전송은 gRPC도 SSH 유지도 아닌 HTTP+JSON+HMAC — 외부 진입과 같은 프로토콜 하나로 최소화하고, 3서버 공통 SSH 키라는 위험 축을 없앴다.

## 채택 — 역할이 모호하면 기동하지 않는다

```go
// cmd/agent/main.go:160-171 — fail-closed 기동
// resolveRole은 ROLE 원시 값을 검증한다. 빈 값·미지원 값은 오류다(fail-closed —
// 역할이 정해지지 않은 채로 기동하지 않는다, DO-21).
func resolveRole(raw string) (role, error) {
    switch role(raw) {
    case roleMain, roleAgent:
        return role(raw), nil
    case "":
        return "", errors.New("ROLE 미설정 (.env에 ROLE=main 또는 ROLE=agent 를 둔다)")
    default:
        return "", fmt.Errorf("ROLE 미지원: %q (main|agent 중 하나여야 한다)", raw)
    }
}
```

"역할이 모호한 채로 특권 프로세스를 띄우지 않는다"는 문장이 이 PR의 태도를 요약한다. 같은 태도가 종단 핸들러에도 있다 — 인증이 아직 통과 스텁인 상태에서 종단을 202(성공)로 두면 조용한 성공 위장이 되므로, 일부러 501로 두어 "아직 아무것도 하지 않는다"를 요란하게 드러냈다.

체인의 구조는 순서 자체가 계약이다:

```go
// internal/httpentry/httpentry.go:154-181 (발췌) — 엔드포인트 하나, 순서가 계약
mux.Handle("POST /deploy", chain(
    deployReceiver(deps),
    withBodyLimit(cfg.MaxBodyBytes), // 전송 제한(DO-15 ⑵) — 바깥에서 body를 캡
    withAuth(deps),                  // 게이트 1 — HMAC + 신선도
    withOIDC(deps),                  // 게이트 2 — OIDC claim 행렬 · HMAC과 AND
    withValidate(deps),              // repo↔target 결박
    withIdempotency(deps),           // requestId·jti 멱등 선점
))
```

이 PR 시점에는 뒤 네 고리가 전부 통과 스텁이었다 — 자리를 먼저 만들고 판정을 나중에 채우는 방식이다. 엔드포인트가 하나뿐인 것도 결정의 산물이다(DO-1): 엣지는 인증하지 않고 전달만 한다. 엣지에서도 서명을 보면 판정 주체가 둘이 되고, 둘이 갈리는 순간 "거절은 어디 기록되나"가 흐려지기 때문이다.

층 분리도 여기서 고정됐다 — HTTP 진입 미들웨어(선형 체인)와 상태를 가진 오케스트레이션(락·트랜잭션)을 나눠, 미들웨어의 선형성이 트랜잭션 경계를 가리지 않게 한다(ADR-029 IA-4). 이 분리는 나중에 "결박을 어디에 두나"(PR #29) 같은 논쟁의 기준선이 된다.

## 검증

리뷰 지적 기록은 없다. 검증은 단위 테스트(타 메서드 405, 상한 초과 413, 상한 안 POST 501 도달, 설정 fail-closed)와 기동 스모크였다 — ROLE 미설정/미지원/주소 없음 전부 exit 1, 정상 기동 후 curl 5종, SIGTERM graceful shutdown. body 상한 기본값(64KiB)은 `[구현 검증]` 표식과 함께 상수 옆에 남겼다 — 실측 값은 엣지 제한과 함께 정해진다는 이연 선언이다.

## 다음으로의 연결

`withAuth`·`withIdempotency` 스텁은 PR #8이, `withOIDC`는 PR #10이 채운다. `withValidate` 스텁은 특이하게 5일을 비어 있다가 repo별 allowlist(PR #29)에서야 채워졌다 — "검증 자리는 있으나 아무것도 검증하지 않는" 기간이 있었다는 뜻이다. DO-15의 나머지 항목(타임아웃 정교화·출발지 제한·forwarded 불신)은 지금도 TODO로 남아 있다.
