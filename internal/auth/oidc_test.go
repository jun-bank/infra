// 게이트 2(OIDC claim 행렬)의 단위 테스트. 거절 경로를 우선 밟는다(red-first) — 각
// claim이 어긋나면 적용하지 않고 거절해야 하며(DO-11 · RL-8), 조용히 통과하는 것이 이
// 경계의 유일한 치명적 실패이기 때문이다. 서명 검증은 페이크 TokenVerifier로 대체해
// 행렬만 순수하게 밟고, 별도로 실제 golang-jwt 서명 경로도 합성 RSA 키로 못박는다.
//
// ★ sub 대조 안 함(DO-11 각주)도 명시적으로 검증한다: sub를 엉뚱한 값으로 두어도
// 나머지가 맞으면 통과해야 한다 — sub는 판정 대상이 아니다.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeTokenVerifier는 서명 검증을 대체한다 — 미리 정한 claim(또는 오류)을 곧바로
// 돌려줘 행렬 판정만 순수하게 테스트한다.
type fakeTokenVerifier struct {
	claims Claims
	err    error
}

func (f fakeTokenVerifier) VerifyToken(context.Context, string) (Claims, error) {
	return f.claims, f.err
}

// basePolicy는 baseClaims와 정확히 맞는 기대값이다.
func basePolicy() OIDCPolicy {
	return OIDCPolicy{
		Issuer:         "https://token.actions.githubusercontent.com",
		Audience:       "https://deploy.jun-bank.example",
		Repository:     "jun-bank/infra",
		RepositoryID:   "123456",
		OwnerID:        "654321",
		RefAllowlist:   []string{"refs/heads/main"},
		JobWorkflowRef: "jun-bank/infra/.github/workflows/deploy.yml@refs/heads/main",
		Skew:           DefaultClockSkew,
	}
}

// baseClaims는 서명이 검증됐다고 가정한, 정책과 완전히 일치하는 신선한 claim이다. 각
// 테스트는 이걸 변형해 정확히 한 칸만 어긋나게 한다.
func baseClaims(now time.Time) Claims {
	return Claims{
		Issuer:         "https://token.actions.githubusercontent.com",
		Audience:       []string{"https://deploy.jun-bank.example"},
		Subject:        "repo:jun-bank/infra:ref:refs/heads/main", // 판정에 쓰이지 않는다
		Repository:     "jun-bank/infra",
		RepositoryID:   "123456",
		OwnerID:        "654321",
		Ref:            "refs/heads/main",
		JobWorkflowRef: "jun-bank/infra/.github/workflows/deploy.yml@refs/heads/main",
		Environment:    "production",
		JTI:            "jti-0001",
		IssuedAt:       now.Add(-30 * time.Second).Unix(),
		NotBefore:      now.Add(-30 * time.Second).Unix(),
		ExpiresAt:      now.Add(5 * time.Minute).Unix(),
	}
}

func newOIDCVerifier(t *testing.T, claims Claims, now time.Time) *OIDCVerifier {
	t.Helper()
	v, err := NewOIDCVerifier(fakeTokenVerifier{claims: claims}, basePolicy(), fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewOIDCVerifier 오류: %v", err)
	}
	return v
}

// TestClaimMismatchRejected는 각 claim이 어긋나면 거절하고 사유를 담는지 확인한다
// (행렬 전 칸 AND — 한 칸이라도 불일치면 거절 기록, RL-8 무예외).
func TestClaimMismatchRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name   string
		mutate func(*Claims)
	}{
		{"iss 불일치", func(c *Claims) { c.Issuer = "https://evil.example" }},
		{"aud 불일치(플랫폼 기본값)", func(c *Claims) { c.Audience = []string{"https://github.com/jun-bank"} }},
		{"aud 부재", func(c *Claims) { c.Audience = nil }},
		{"repository 불일치", func(c *Claims) { c.Repository = "jun-bank/other" }},
		{"repository_id 불일치(이름 재사용)", func(c *Claims) { c.RepositoryID = "999999" }},
		{"repository_owner_id 불일치", func(c *Claims) { c.OwnerID = "111111" }},
		{"ref 허용목록 밖", func(c *Claims) { c.Ref = "refs/heads/feature-x" }},
		{"태그 ref 허용목록 밖", func(c *Claims) { c.Ref = "refs/tags/v1.0.0" }},
		{"job_workflow_ref 불일치(다른 워크플로)", func(c *Claims) {
			c.JobWorkflowRef = "jun-bank/infra/.github/workflows/test.yml@refs/heads/main"
		}},
		{"jti 부재", func(c *Claims) { c.JTI = "" }},
		{"jti 공백만", func(c *Claims) { c.JTI = "   " }},
		{"exp/iat 부재", func(c *Claims) { c.ExpiresAt = 0; c.IssuedAt = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := baseClaims(now)
			tc.mutate(&claims)
			v := newOIDCVerifier(t, claims, now)

			dec := v.Verify(context.Background(), "raw-token")
			if dec.Accepted {
				t.Errorf("%s: 어긋난 claim이 수락됐다 (거절 기대 — DO-11)", tc.name)
			}
			if dec.Reason == "" {
				t.Errorf("%s: 거절인데 Reason이 비었다 (기록 의무 — RL-8)", tc.name)
			}
		})
	}
}

// TestExpiredTokenRejected는 exp가 스큐를 넘어 지났으면 거절하는지 확인한다.
func TestExpiredTokenRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	claims := baseClaims(now)
	claims.ExpiresAt = now.Add(-DefaultClockSkew - time.Second).Unix() // 스큐 밖으로 만료
	v := newOIDCVerifier(t, claims, now)

	dec := v.Verify(context.Background(), "raw-token")
	if dec.Accepted {
		t.Fatal("만료된 토큰이 수락됐다 (거절 기대)")
	}
}

// TestFutureIatRejected는 iat가 스큐를 넘어 미래면 거절하는지 확인한다.
func TestFutureIatRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	claims := baseClaims(now)
	claims.IssuedAt = now.Add(DefaultClockSkew + time.Second).Unix() // 스큐 밖 미래
	v := newOIDCVerifier(t, claims, now)

	dec := v.Verify(context.Background(), "raw-token")
	if dec.Accepted {
		t.Fatal("미래 발급 토큰이 수락됐다 (거절 기대)")
	}
}

// TestNotBeforeRejected는 nbf가 아직 도래하지 않았으면 거절하는지 확인한다.
func TestNotBeforeRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	claims := baseClaims(now)
	claims.NotBefore = now.Add(DefaultClockSkew + time.Second).Unix() // 스큐 밖 미도래
	v := newOIDCVerifier(t, claims, now)

	dec := v.Verify(context.Background(), "raw-token")
	if dec.Accepted {
		t.Fatal("nbf 미도래 토큰이 수락됐다 (거절 기대)")
	}
}

// TestMultiAudRejected는 우리 audience에 다른 audience가 섞인 다중 aud 토큰을 거절하는지
// 확인한다(정확 일치 — 포함 검사면 이런 토큰이 통과한다). DO-11 "전용" = 단일값 기대.
func TestMultiAudRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	claims := baseClaims(now)
	claims.Audience = []string{"https://deploy.jun-bank.example", "https://evil.example"}
	v := newOIDCVerifier(t, claims, now)

	dec := v.Verify(context.Background(), "raw-token")
	if dec.Accepted {
		t.Fatal("우리값이 섞인 다중 aud 토큰이 수락됐다 (정확히 하나 일치 기대 — DO-11)")
	}
	if dec.Reason == "" {
		t.Error("거절인데 Reason이 비었다 (RL-8)")
	}
}

// TestExactAudAccepted는 정확히 우리 audience 하나면 통과하는지 못박는다(정확 일치가
// 정상 토큰을 막지 않는지 — 거절 경로만 있으면 과잉 거절을 못 잡는다).
func TestExactAudAccepted(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	claims := baseClaims(now)
	claims.Audience = []string{"https://deploy.jun-bank.example"} // 정확히 우리값 하나
	v := newOIDCVerifier(t, claims, now)

	dec := v.Verify(context.Background(), "raw-token")
	if !dec.Accepted {
		t.Fatalf("정확한 단일 aud 토큰이 거절됐다: %s", dec.Reason)
	}
}

// TestSignatureFailureRejected는 서명 검증이 실패하면(TokenVerifier 오류) claim을
// 보기도 전에 거절하는지 확인한다 — payload는 서명이 선 뒤에만 신뢰된다.
func TestSignatureFailureRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	v, err := NewOIDCVerifier(
		fakeTokenVerifier{err: ErrOIDCMalformed},
		basePolicy(), fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewOIDCVerifier 오류: %v", err)
	}

	dec := v.Verify(context.Background(), "garbage")
	if dec.Accepted {
		t.Fatal("서명 실패 토큰이 수락됐다 (거절 기대)")
	}
	if dec.Reason == "" {
		t.Error("거절인데 Reason이 비었다 (RL-8)")
	}
}

// TestSubNotMatched는 sub를 대조하지 않음을 못박는다(DO-11 각주). sub를 엉뚱한 값으로
// 두어도 나머지 칸이 맞으면 통과해야 한다 — sub는 파생값이라 판정 대상이 아니다.
func TestSubNotMatched(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	claims := baseClaims(now)
	claims.Subject = "repo:someone-else/evil-repo:ref:refs/heads/attacker" // 완전히 다른 sub
	v := newOIDCVerifier(t, claims, now)

	dec := v.Verify(context.Background(), "raw-token")
	if !dec.Accepted {
		t.Fatalf("sub가 다르다는 이유로 거절됐다 (sub는 대조 대상이 아니다 — DO-11): %s", dec.Reason)
	}
}

// TestValidTokenAcceptedSelfReport는 전 칸이 맞으면 통과하고, jti를 실어 오며, 운영
// 승인이 자기 신고임을 SelfReport로 드러내는지 확인한다(잔여-5). 거절 경로만 있으면
// fail-open을 잡지 못하므로 통과 경로도 못박는다.
func TestValidTokenAcceptedSelfReport(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	claims := baseClaims(now)
	v := newOIDCVerifier(t, claims, now)

	dec := v.Verify(context.Background(), "raw-token")
	if !dec.Accepted {
		t.Fatalf("유효한 토큰이 거절됐다: %s", dec.Reason)
	}
	if dec.JTI != "jti-0001" {
		t.Errorf("선점할 jti가 실려 오지 않았다: %q", dec.JTI)
	}
	if !dec.SelfReport {
		t.Error("운영 승인이 자기 신고인데 SelfReport가 false다 (잔여-5 — 이력에 남겨야 한다)")
	}
}

// TestOIDCExpiredWithinSkewAccepted는 만료 직후지만 스큐 안이면 수락하는지 확인한다 —
// 스큐가 있어야 정상 토큰이 시계 차이로 거절되지 않는다.
func TestOIDCExpiredWithinSkewAccepted(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	claims := baseClaims(now)
	claims.ExpiresAt = now.Add(-DefaultClockSkew / 2).Unix() // 만료 직후지만 스큐 안
	v := newOIDCVerifier(t, claims, now)

	dec := v.Verify(context.Background(), "raw-token")
	if !dec.Accepted {
		t.Fatalf("스큐 안 토큰이 거절됐다: %s", dec.Reason)
	}
}

// --- 실제 서명 경로(golang-jwt) --------------------------------------------------

// fakeKeySet은 합성 RSA 공개키 하나를 돌려주는 KeySet이다(테스트 키 — 시크릿 아님).
type fakeKeySet struct {
	key *rsa.PublicKey
	err error
}

func (f fakeKeySet) VerificationKey(context.Context, string) (any, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.key, nil
}

// signTestToken은 합성 RSA 키로 RS256 서명한 토큰을 만든다(테스트 벡터).
func signTestToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-kid"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("테스트 토큰 서명 실패: %v", err)
	}
	return s
}

// TestJWKSVerifyRealSignature는 실제 golang-jwt 경로가 올바른 키로 서명된 토큰의
// claim을 디코드하고, 서명이 다른 키면 거절하는지 확인한다.
func TestJWKSVerifyRealSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA 키 생성 실패: %v", err)
	}
	raw := signTestToken(t, key, jwt.MapClaims{
		"iss":           "https://token.actions.githubusercontent.com",
		"repository_id": "123456",
		"jti":           "jti-real",
	})

	// 올바른 공개키 → claim 디코드.
	tv := NewJWKSTokenVerifier(fakeKeySet{key: &key.PublicKey})
	claims, err := tv.VerifyToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("유효 서명 토큰이 거절됐다: %v", err)
	}
	if claims.RepositoryID != "123456" || claims.JTI != "jti-real" {
		t.Errorf("claim 디코드가 어긋났다: %+v", claims)
	}

	// 다른 키 → 서명 불일치 거절.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	tvBad := NewJWKSTokenVerifier(fakeKeySet{key: &other.PublicKey})
	if _, err := tvBad.VerifyToken(context.Background(), raw); err == nil {
		t.Error("다른 키로 서명 검증이 통과했다 (거절 기대)")
	}
}

// validMapClaims는 basePolicy와 정확히 맞는 수치 시간 claim 세트다(실제 서명 경로 테스트용).
// 각 테스트는 한 칸만 형식이 깨지게 변형한다.
func validMapClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":                 "https://token.actions.githubusercontent.com",
		"aud":                 "https://deploy.jun-bank.example",
		"sub":                 "repo:jun-bank/infra:ref:refs/heads/main",
		"repository":          "jun-bank/infra",
		"repository_id":       "123456",
		"repository_owner_id": "654321",
		"ref":                 "refs/heads/main",
		"job_workflow_ref":    "jun-bank/infra/.github/workflows/deploy.yml@refs/heads/main",
		"environment":         "production",
		"jti":                 "jti-time",
		"iat":                 now.Add(-30 * time.Second).Unix(),
		"nbf":                 now.Add(-30 * time.Second).Unix(),
		"exp":                 now.Add(5 * time.Minute).Unix(),
	}
}

// TestMalformedNbfRejected는 서명은 유효하지만 nbf가 존재하는데 수치가 아닌(형식 오류)
// 토큰을 무음 스킵하지 않고 거절하는지 실제 서명 경로로 확인한다 — 이전엔 0으로 무음
// 치환돼 nbf 검증을 통째로 건너뛰었다(반-silent-failure). 대조군(정상 nbf)은 통과해야
// 나머지가 유효함이 증명돼 거절이 nbf 형식 오류로 격리된다.
func TestMalformedNbfRejected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA 키 생성 실패: %v", err)
	}
	tv := NewJWKSTokenVerifier(fakeKeySet{key: &key.PublicKey})
	v, err := NewOIDCVerifier(tv, basePolicy(), fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewOIDCVerifier 오류: %v", err)
	}

	// 대조군 — nbf가 정상 수치면 통과(나머지 전 칸 유효 확인).
	good := signTestToken(t, key, validMapClaims(now))
	if dec := v.Verify(context.Background(), good); !dec.Accepted {
		t.Fatalf("정상 nbf 토큰이 거절됐다: %s (거절이 nbf 형식 오류로 격리되지 않는다)", dec.Reason)
	}

	// nbf가 존재하나 문자열(형식 오류) → 거절.
	mc := validMapClaims(now)
	mc["nbf"] = "invalid"
	bad := signTestToken(t, key, mc)
	dec := v.Verify(context.Background(), bad)
	if dec.Accepted {
		t.Fatal("형식이 깨진 nbf 토큰이 수락됐다 (무음 스킵 — 거절 기대)")
	}
	if !strings.Contains(dec.Reason, "형식 오류") {
		t.Errorf("nbf 형식 오류 거절 사유가 아니다: %q", dec.Reason)
	}
}

// TestJWKSRejectsNonRSA는 RS256이 아닌 알고리즘(예: HS256)을 거절하는지 확인한다 —
// alg 혼동 공격(대칭키·none)을 keyFunc 진입 전에 막는다.
func TestJWKSRejectsNonRSA(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": "x"})
	raw, err := tok.SignedString([]byte("symmetric-secret"))
	if err != nil {
		t.Fatalf("HS256 토큰 서명 실패: %v", err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tv := NewJWKSTokenVerifier(fakeKeySet{key: &key.PublicKey})
	if _, err := tv.VerifyToken(context.Background(), raw); err == nil {
		t.Error("HS256 토큰이 통과했다 (RS256 고정 — 거절 기대)")
	}
}
