# PR #24 — JWKS 실 공개키 페치

이 문서는 게이트 2(OIDC)를 "존재하지만 작동하지 않는" 상태에서 실동작으로 바꾼 과정을 다룬다. PR #10에서 게이트 2의 claim 행렬은 세웠지만 서명 검증에 쓸 공개키를 실제로 가져오는 부분은 스캐폴드(전건 거절) 뒤에 있었다. 이 PR이 그 스캐폴드를 실 JWKS 페치로 바꾼다 — 그리고 리허설과 green 테스트를 통과한 코드에서 리뷰가 인증 뿌리의 fail-open 2건을 잡았다.

## 문제와 원인

JWKS 페치 자체는 3단계로 단순하다(발급자 discovery → JWK Set 페치 → kid별 RSA 공개키 조회). 문제는 이 코드가 인증의 뿌리라는 점이다. 리뷰가 잡은 두 fail-open이 그 무게를 보여준다.

첫째, **만료 + throttle 시 stale 키 반환**이다. 캐시가 만료돼 재페치를 부르는데, 요청 폭주 방지 throttle 창 안이면 재페치는 갱신 없이 nil을 낸다. 호출부는 그 nil을 "방금 페치했다"로 오인해 만료된 캐시의 키를 그대로 검증에 쓴다 — 발급자 장애 동안 회전으로 철회됐을 수 있는 키로 무기한 검증하게 된다.

둘째, **리다이렉트 HTTPS 다운그레이드**다. https 강제가 정적 문자열 검사라, `CheckRedirect`가 없으면 https 엔드포인트가 302로 http(또는 공격자 https)로 리다이렉트할 때 그대로 따라간다 — "https를 강제했다"는 검사가 실제 전송 scheme을 보증하지 못한다.

## 채택 — TTL을 staleness 상한으로

새 의존성 없이 JWK를 stdlib로 수동 파싱했고(도구 최소주의), 서명 검증은 kid → 키 조회만 이 파일이 소유하고 alg 방어·claim 행렬은 기존 `oidc.go`가 유지한다. 빈 kid는 페치 없이 즉시 거절한다 — 키를 특정할 수 없는 요청이 발급자를 두드리게 두지 않는다.

fail-open 수정의 핵심은 TTL을 staleness 상한으로 삼는 것이다:

```go
// internal/auth/jwks.go:189-204 (발췌) — 재페치 후 freshness 재확인
// 재페치가 nil을 냈다고 해서 "방금 신선히 페치했다"는 보장은 없다 — storm throttle
// 창 안이면 refetch는 갱신 없이 nil을 낸다. 따라서 keys[kid]를 반환하기 전에 freshness를
// 재확인한다: 캐시가 여전히 만료 상태면 그 키는 stale이므로 거절한다(TTL = staleness 상한).
fresh := ks.clock.Now().Sub(ks.fetchedAt) < ks.ttl
key, ok := ks.keys[kid]
if !fresh {
    return nil, ErrJWKSStale
}
```

리다이렉트는 각 hop의 scheme을 강제하되, 흥미로운 후속이 하나 있었다 — 1차 수정이 주입된 클라이언트의 기존 `CheckRedirect`를 무조건 덮어써, 호출자가 이미 건 정책(리다이렉트 전면 금지 등)을 잃는 또 다른 fail-open을 만들었다. post-fix 재점검이 이를 잡아, https 검사를 먼저 하고 기존 정책이 있으면 이어서 적용하는 정책 합성으로 바꿨다.

## 리뷰가 바꾼 것 — 대가의 문서화까지

듀얼 1패스에서 fix 5건이 나왔다 — stale 키(치명)·다운그레이드·지수 조립 overflow·ctx 취소를 못 보는 single-flight·그리고 문서화 하나다. 마지막이 특이하다: 재페치 throttle 창 동안 발급자가 회전한 새 kid가 잠깐 거절되는데, 이것이 fail-open이 아니라 storm 방지의 가용성 대가임을 **코드 주석으로 명시**했다. 미확인 키를 통과시키는 게 아니라 아직 못 집은 키를 잠깐 거절하는 것이고, GitHub Actions OIDC가 키를 겹쳐 회전하므로 옛 kid와 새 kid가 한동안 공존한다는 근거까지 남겼다.

검증은 httptest 단위 15개 — 유효 kid 통과, 빈 kid 무페치 거절, http jwks_uri 거절, 그리고 리뷰가 만든 케이스들(만료+throttle stale 거절, https 다운그레이드/합성, exponent 분기, ctx 취소)이다.

## 다음으로의 연결

e2e — 유효 GitHub 토큰이 실제로 게이트 2를 통과하는지 — 는 에이전트 배포 후에만 가능하므로 `[구현 검증]`으로 이연됐다. 그것이 실제로 통과한 것은 2026-08-12 첫 실배포이고, 그 배포가 곧 false-UNKNOWN 사건(PR #25)이다. `[구현 검증]` 값(발급자 URL·TTL·timeout·크기 상한)의 중앙 대장 등재는 후속으로 남았다.
