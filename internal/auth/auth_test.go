// 게이트 1(HMAC + 신선도)의 단위 테스트. 거절 경로를 우선 밟는다(위조·만료·미래·
// 형식 오류) — DO-2/RL-8은 "서명 실패는 무조건 거절"이며, 조용히 통과하는 것이 이
// 경계의 유일한 치명적 실패이기 때문이다. 시각은 고정 Clock으로 주입해 만료·스큐
// 경계를 결정론적으로 밟는다(DO-10 ⑵).
package auth

import (
	"bytes"
	"testing"
	"time"
)

// fixedClock은 주입된 고정 시각을 반환하는 테스트용 Clock이다.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// testKey는 테스트 전용 HMAC 키다(시크릿 아님 — 테스트 벡터).
var testKey = []byte("test-hmac-key-not-a-secret")

// baseRequest는 서명이 유효하고 신선한 기준 요청을 만든다. 각 테스트는 이걸 변형해
// 정확히 한 가지만 어긋나게 한다.
func baseRequest(now time.Time) Request {
	req := Request{
		Method:     "POST",
		Path:       "/deploy",
		BodyDigest: "sha256:abc123",
		RequestID:  "req-0001",
		IssuedAt:   now.Add(-30 * time.Second).UTC().Format(time.RFC3339),
		ExpiresAt:  now.Add(5 * time.Minute).UTC().Format(time.RFC3339),
	}
	req.Signature = Sign(testKey, req)
	return req
}

// newTestVerifier는 고정 시각·기본 스큐로 verifier를 만든다.
func newTestVerifier(t *testing.T, now time.Time) Verifier {
	t.Helper()
	skew := DefaultClockSkew
	v, err := NewVerifier(Config{Key: testKey, Skew: &skew}, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewVerifier 오류: %v", err)
	}
	return v
}

// TestForgedSignatureRejected는 서명이 위조되면 거절하는지 확인한다(RL-8).
func TestForgedSignatureRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)

	req := baseRequest(now)
	req.Signature = append([]byte(nil), req.Signature...)
	req.Signature[0] ^= 0xFF // 한 바이트 뒤집기 = 위조

	dec, err := v.Verify(req)
	if err != nil {
		t.Fatalf("Verify 오류: %v", err)
	}
	if dec.Accepted {
		t.Fatal("위조된 서명이 수락됐다 (거절 기대 — RL-8)")
	}
	if dec.Reason == "" {
		t.Error("거절인데 Reason이 비었다 (기록 의무 — RL-8)")
	}
}

// TestTamperedFieldRejected는 서명 범위 안의 필드가 서명 후 바뀌면 거절하는지
// 확인한다 — 서명은 body digest·requestId 등을 덮으므로, 그 값만 바꿔치면 HMAC이
// 어긋난다(DO-10 ⑴ "서명 밖의 값은 판정에 쓰지 않는다"의 대우).
func TestTamperedFieldRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)

	for _, tc := range []struct {
		name   string
		mutate func(*Request)
	}{
		{"body digest 변조", func(r *Request) { r.BodyDigest = "sha256:evil" }},
		{"requestId 변조", func(r *Request) { r.RequestID = "req-9999" }},
		{"path 변조", func(r *Request) { r.Path = "/deploy/../admin" }},
		{"method 변조", func(r *Request) { r.Method = "DELETE" }},
		{"expiresAt 연장", func(r *Request) { r.ExpiresAt = now.Add(24 * time.Hour).UTC().Format(time.RFC3339) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := baseRequest(now)
			tc.mutate(&req) // 서명은 재계산하지 않는다 — 변조를 흉내낸다
			dec, err := v.Verify(req)
			if err != nil {
				t.Fatalf("Verify 오류: %v", err)
			}
			if dec.Accepted {
				t.Errorf("%s: 변조된 요청이 수락됐다 (거절 기대)", tc.name)
			}
		})
	}
}

// TestExpiredRejected는 expiresAt가 스큐를 넘어 지났으면 거절하는지 확인한다
// (DO-10 ⑵ — 서명은 맞는데 신선하지 않다).
func TestExpiredRejected(t *testing.T) {
	signedAt := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	req := baseRequest(signedAt) // expiresAt = signedAt+5m

	// 만료 후 스큐를 넘긴 시점에서 검증한다.
	now := signedAt.Add(5*time.Minute + DefaultClockSkew + time.Second)
	v := newTestVerifier(t, now)

	dec, err := v.Verify(req)
	if err != nil {
		t.Fatalf("Verify 오류: %v", err)
	}
	if dec.Accepted {
		t.Fatal("만료된 요청이 수락됐다 (거절 기대 — DO-10 ⑵)")
	}
}

// TestExpiredWithinSkewAccepted는 만료 직후지만 스큐 안이면 수락하는지 확인한다 —
// 스큐가 있어야 정상 요청이 시계 차이로 거절되지 않는다.
func TestExpiredWithinSkewAccepted(t *testing.T) {
	signedAt := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	req := baseRequest(signedAt)

	now := signedAt.Add(5*time.Minute + DefaultClockSkew/2) // 만료를 막 지났지만 스큐 안
	v := newTestVerifier(t, now)

	dec, err := v.Verify(req)
	if err != nil {
		t.Fatalf("Verify 오류: %v", err)
	}
	if !dec.Accepted {
		t.Fatalf("스큐 안 요청이 거절됐다: %s", dec.Reason)
	}
}

// TestFutureRejected는 issuedAt가 스큐를 넘어 미래면 거절하는지 확인한다.
func TestFutureRejected(t *testing.T) {
	signedAt := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	req := baseRequest(signedAt) // issuedAt = signedAt-30s

	// issuedAt보다 스큐 이상 이전 시점 = issuedAt가 미래로 보이는 시점.
	now := signedAt.Add(-30*time.Second - DefaultClockSkew - time.Second)
	v := newTestVerifier(t, now)

	dec, err := v.Verify(req)
	if err != nil {
		t.Fatalf("Verify 오류: %v", err)
	}
	if dec.Accepted {
		t.Fatal("미래 요청이 수락됐다 (거절 기대)")
	}
}

// TestMalformedTimestampsRejected는 issuedAt/expiresAt 형식이 깨졌으면 거절하는지
// 확인한다(서명이 그 문자열을 덮으므로 형식 오류 = 위조/오작성).
func TestMalformedTimestampsRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)

	for _, tc := range []struct {
		name string
		set  func(*Request)
	}{
		{"issuedAt 비형식", func(r *Request) { r.IssuedAt = "not-a-time" }},
		{"expiresAt 비형식", func(r *Request) { r.ExpiresAt = "20260807" }},
		{"창이 비었다", func(r *Request) {
			r.IssuedAt = now.UTC().Format(time.RFC3339)
			r.ExpiresAt = now.UTC().Format(time.RFC3339)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{
				Method: "POST", Path: "/deploy", BodyDigest: "sha256:abc123",
				RequestID: "req-0001",
				IssuedAt:  now.Add(-30 * time.Second).UTC().Format(time.RFC3339),
				ExpiresAt: now.Add(5 * time.Minute).UTC().Format(time.RFC3339),
			}
			tc.set(&req)
			req.Signature = Sign(testKey, req) // 형식 오류지만 서명은 유효 — 신선도 단계에서 걸려야 한다
			dec, err := v.Verify(req)
			if err != nil {
				t.Fatalf("Verify 오류: %v", err)
			}
			if dec.Accepted {
				t.Errorf("%s: 수락됐다 (거절 기대)", tc.name)
			}
		})
	}
}

// TestValidRequestAccepted는 서명이 유효하고 신선한 요청이 수락되는지 확인한다
// (거절 경로만 있으면 fail-open을 잡지 못하므로 통과 경로도 못박는다).
func TestValidRequestAccepted(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)

	dec, err := v.Verify(baseRequest(now))
	if err != nil {
		t.Fatalf("Verify 오류: %v", err)
	}
	if !dec.Accepted {
		t.Fatalf("유효·신선 요청이 거절됐다: %s", dec.Reason)
	}
}

// TestCanonicalMethodNormalized는 method가 대소문자만 다를 때 같은 서명으로 검증되는지
// 확인한다(Canonicalize가 method를 대문자로 정규화 — 다른 표기를 같은 요청으로 취급).
func TestCanonicalMethodNormalized(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)

	req := baseRequest(now) // method "POST"로 서명됨
	req.Method = "post"     // 소문자로 재전송 — 정규화되면 같은 서명이어야 한다

	dec, err := v.Verify(req)
	if err != nil {
		t.Fatalf("Verify 오류: %v", err)
	}
	if !dec.Accepted {
		t.Fatalf("method 정규화 실패 — 대소문자만 다른 요청이 거절됐다: %s", dec.Reason)
	}
}

// TestSignDeterministic는 같은 요청·키에 대해 Sign이 결정론적이고, 키가 다르면
// 서명이 달라지는지 확인한다(서명·검증 단일 출처의 최소 성질).
func TestSignDeterministic(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	req := baseRequest(now)

	if !bytes.Equal(Sign(testKey, req), Sign(testKey, req)) {
		t.Error("같은 입력에 Sign이 다른 값을 냈다 (비결정론)")
	}
	if bytes.Equal(Sign(testKey, req), Sign([]byte("other-key"), req)) {
		t.Error("다른 키가 같은 서명을 냈다")
	}
}

// TestEmptyRequestIDRejected는 검증된 requestId가 비었거나 공백만 있으면 거절하는지
// 확인한다(codex medium). requestId는 서명 범위 안이라 서명은 유효하게 만들 수 있지만,
// 빈 값이면 모든 무-ID 요청이 멱등 키 ""를 공유해 서로의 예약과 충돌한다(선점 붕괴·DoS).
// 그러므로 예약(Reserve)에 닿기 전 게이트 1에서 막아야 한다.
func TestEmptyRequestIDRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)

	for _, tc := range []struct {
		name string
		id   string
	}{
		{"빈 문자열", ""},
		{"공백만", "   "},
		{"탭", "\t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := baseRequest(now)
			req.RequestID = tc.id
			req.Signature = Sign(testKey, req) // 빈 requestId로도 유효하게 서명 — 서명 자체는 통과한다
			dec, err := v.Verify(req)
			if err != nil {
				t.Fatalf("Verify 오류: %v", err)
			}
			if dec.Accepted {
				t.Errorf("%s: 빈 requestId가 수락됐다 (거절 기대 — 멱등 키 필수)", tc.name)
			}
			if dec.Reason == "" {
				t.Errorf("%s: 거절인데 Reason이 비었다 (기록 의무 — RL-8)", tc.name)
			}
		})
	}
}

// TestExplicitZeroSkewRespected는 운영자가 명시한 무-skew(엄격, 0s)가 기본값(60s)으로
// 조용히 완화되지 않는지 확인한다(codex·Opus medium). 만료를 1초 지난 요청은 스큐 0이면
// 거절돼야 한다 — 기본 60s 스큐였다면 통과했을 경계 요청이다.
func TestExplicitZeroSkewRespected(t *testing.T) {
	signedAt := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	req := baseRequest(signedAt) // expiresAt = signedAt+5m

	zero := time.Duration(0)
	now := signedAt.Add(5*time.Minute + time.Second) // 만료를 1초 지남 (60s 스큐 안, 0s 스큐 밖)
	v, err := NewVerifier(Config{Key: testKey, Skew: &zero}, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewVerifier 오류: %v", err)
	}

	dec, err := v.Verify(req)
	if err != nil {
		t.Fatalf("Verify 오류: %v", err)
	}
	if dec.Accepted {
		t.Fatal("명시적 0 스큐인데 만료 요청이 수락됐다 (60s로 완화됨 — 거절 기대)")
	}
}

// TestUnsetSkewDefaults는 Skew가 nil(미설정)이면 DefaultClockSkew로 채워지는지
// 확인한다 — 직접 조립 시의 안전한 기본값(명시적 0과 구분된다).
func TestUnsetSkewDefaults(t *testing.T) {
	signedAt := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	req := baseRequest(signedAt)

	now := signedAt.Add(5*time.Minute + DefaultClockSkew/2) // 만료 직후지만 기본 스큐 안
	v, err := NewVerifier(Config{Key: testKey}, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewVerifier 오류: %v", err)
	}

	dec, err := v.Verify(req)
	if err != nil {
		t.Fatalf("Verify 오류: %v", err)
	}
	if !dec.Accepted {
		t.Fatalf("미설정 스큐(기본 60s 기대) 안 요청이 거절됐다: %s", dec.Reason)
	}
}

// TestNewVerifierRejectsEmptyKey는 키 없이 verifier를 만들 수 없음을 확인한다
// (fail-closed — 검증 못 하는 경계를 세우지 않는다).
func TestNewVerifierRejectsEmptyKey(t *testing.T) {
	if _, err := NewVerifier(Config{Key: nil}, SystemClock{}); err == nil {
		t.Error("빈 키로 NewVerifier가 성공했다 (fail-closed 기대)")
	}
}
