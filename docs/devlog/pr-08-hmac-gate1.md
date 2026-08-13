# PR #8 — 게이트 1: HMAC 서명과 requestId 멱등

이 문서는 배포 요청의 첫 번째 관문이 선 과정을 다룬다. 배포 API는 인터넷에서 도달 가능한 원격 코드 실행이므로(ADR-024 RL-8), 서명이 실패하면 적용하지 않는다는 것이 출발점이다. 그런데 이 PR의 진짜 주제는 서명이 아니라 **재전송**이다 — 그리고 듀얼 리뷰가 처음으로 실결함을 잡아낸 PR이기도 하다.

## 문제와 원인 — HMAC만으로는 재전송을 못 막는다

설계 문서(ADR-027 DO-10)의 근거 문장이 문제를 정확히 잡았다: "HMAC은 진위를 증명할 뿐 freshness를 보장하지 않는다 — 유효 요청 한 건을 탈취하면 같은 배포를 언제든 다시 실행할 수 있고, 프록시·CI의 타임아웃 재시도와 응답 유실도 같은 결과를 만든다." 공격과 사고가 같은 모양이라는 것이 핵심이다.

그리고 이것은 새 규약이 아니었다 — 시스템 채널의 멱등 규약(재수신 = 최초 결과 재반환)과 같은 축이고, 배포 채널의 멱등 키가 requestId인 것뿐이다. 다만 배포는 "실패한 재실행이 조용히 성공으로 보이는" 조작이라 무음 무시 금지가 더 세게 적용된다.

## 채택 — 정규화는 한 곳, 선점은 DB 제약에

서명 범위는 정규화된 method·path·body digest·requestId·issuedAt·expiresAt이고, 그 정규화는 `Canonicalize` 한 곳에서만 정의된다 — CI 서명자와 이 검증자가 반드시 같은 형태를 만들어야 하는 실계약이라, 한쪽만 바꾸면 모든 서명이 조용히 불일치한다는 경고가 주석에 있다. 판정 순서는 진위 먼저(상수 시간 비교), 그 다음 신선도다.

멱등 선점은 부작용 전에 requestId(와 OIDC jti)를 내구적으로 예약하는 것이고, 판정은 UNIQUE 제약에 의해 INSERT 시점에 선다 — writer의 선의에 의존하지 않는다. 중복이 잡히면 저장된 body digest와 대조해 3분기한다:

```go
// internal/store/store.go:459-476 (발췌) — 멱등 3분기
switch {
case errors.Is(qErr, sql.ErrNoRows):
    // requestId는 신규인데 INSERT가 중복으로 실패했다 = jti 재사용(토큰 재전송).
    return ErrReplay
case storedDigest == bodyDigest:
    // 동일 requestId + 동일 digest = 같은 요청의 재전송 → 재실행 금지.
    return ErrReplay
default:
    // 동일 requestId + 다른 digest = 거절·기록해야 하는 충돌.
    return ErrDigestConflict
}
```

## 리뷰가 만든 코드 — 이 PR의 하이라이트

듀얼 리뷰(codex ∥ Opus)는 보안 코어(HMAC·신선도·멱등·fail-closed)에 중대 결함이 없음을 확인했지만, 그 바깥에서 2건을 잡았고 둘 다 코드가 바뀌었다.

첫째는 **빈 requestId** — codex 단독 발견이다. 빈 ID도 올바르게 서명하면 인증과 예약을 통과하는데, 그러면 모든 무-ID 요청이 멱등 키 `""`를 공유해 서로의 예약과 충돌한다(선점 붕괴). 게이트 1에서 거절하도록 고쳤다:

```go
// internal/auth/auth.go:199-206 (발췌)
// 비었거나 공백만 있으면 모든 무-ID 요청이 멱등 키 ""를 공유해 서로의 예약과 충돌한다
// (선점 붕괴·DoS). 예약(Reserve)에 닿기 전 게이트 1에서 거절한다.
if strings.TrimSpace(req.RequestID) == "" {
    return Decision{Accepted: false, Reason: "requestId 비어 있음 (멱등 키 필수)"}, nil
}
```

둘째는 **시계 편차(skew) 0의 무시** — 양 리뷰어 공통 발견이다. 운영자가 `0s`(엄격)를 명시해도 값 타입의 0과 "미설정"이 구별되지 않아 기본값 60초로 조용히 완화됐다. `Config.Skew`를 포인터로 바꿔 "미설정(nil) vs 명시적 0"을 구분했다:

```go
// internal/auth/auth.go:93-101 (발췌)
// 포인터로 두어 "미설정(nil)"과 "명시적 0s(엄격)"를 구분한다 — 값 타입이면 둘 다
// 0이라, 운영자가 명시한 무-skew(엄격)가 기본값(60s)으로 조용히 완화된다.
Skew *time.Duration
```

두 결함 모두 "닫혀야 할 것이 열리는" 방향(fail-open)이었다는 점이 이날의 교훈으로 기록됐다. 검증은 거절 경로 red-first(위조·만료·재전송이 실제로 거절되는지 먼저 실패시켜 확인)와 Testcontainers 실 MySQL 통합이었다.

## 다음으로의 연결

리뷰가 수용하고 이월한 것이 이슈 #9가 됐다 — "예약 이후 종단 수신이 실패하면 같은 요청의 재시도가 재전송으로 단락되어 배포가 영영 미완이 될 수 있다"(Opus 발견). 당시엔 수신부가 501 스텁이라 무해했고, 실행 층이 생기는 S2에서 처리하기로 했다. 이 PR이 만든 `jti` 자리는 비어 있다가 PR #10(OIDC)이 채우고, "운영 승인은 자기 신고"라는 한계 표식(`SelfReport`)도 게이트 2가 붙기 전까지의 상태를 드러내며 남았다.
