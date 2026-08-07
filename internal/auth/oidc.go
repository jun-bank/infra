// 이 파일은 게이트 2다: 게이트 1(HMAC + 신선도)이 "요청이 위조되지 않았고 신선한가"를
// 판정한 뒤, 게이트 2는 "이 요청이 정말 우리 파이프라인에서 왔는가"를 GitHub Actions
// OIDC ID 토큰의 claim 행렬로 판정한다(ADR-027 DO-11). 둘은 AND이며 — 한 칸이라도
// 어긋나면 적용하지 않고 거절을 기록한다(RL-8 무예외).
//
// 계약 출처(정본):
//   - ADR-027 DO-11  (claim 검증 행렬 — iss·aud 전용값·저장소 수치 ID·ref 허용목록·
//     job_workflow_ref·exp/nbf/iat·jti · ★ sub 문자열 대조 금지)
//   - ADR-027 DO-10 ⑶ (jti는 부작용 전에 선점 — requestId와 같은 재생 방어 축)
//   - ADR-027 §7 잔여-5 / IV-37 (운영 승인 결박은 [구현 검증]; 판정 전까지 자기 신고)
//
// 설계 두 조각으로 나눈다:
//
//	⑴ TokenVerifier — 서명 검증(발급자 JWKS 공개키). 실제 JWKS 페치는 이 인터페이스
//	   뒤(KeySet)에 있어 테스트가 합성 토큰·테스트 키로 주입할 수 있다.
//	⑵ OIDCVerifier  — 서명이 검증된 claim에 행렬을 적용한다(checkClaims). 순수 판정이라
//	   암호 없이 red-first로 각 claim 불일치를 못박는다.
//
// ★ sub는 대조하지 않는다(DO-11 각주). sub는 여러 축을 이어 붙인 합성 문자열이라 형식이
// 바뀌면 조용히 통과·조용히 거절이 된다 — 구성 요소(repository_id·ref·job_workflow_ref)를
// 각각 본다. checkClaims는 claims.Subject를 판정에 쓰지 않는다(감사 기록용으로만 담는다).
package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims는 게이트 2가 판정에 쓰는 GitHub Actions OIDC 토큰의 claim들이다. 서명이
// 검증된 뒤의 값이며, checkClaims가 각 칸을 정책과 대조한다. Subject(sub)는 담되
// 판정에 쓰지 않는다(DO-11 — sub는 파생값이라 대조 대상이 아니다).
type Claims struct {
	Issuer         string   // iss — 발급자(하나로 고정)
	Audience       []string // aud — 우리 배포 전용값(플랫폼 기본값 금지)
	Subject        string   // sub — 감사 기록용. ★ 판정에 쓰지 않는다
	Repository     string   // repository — owner/repo 이름
	RepositoryID   string   // repository_id — ★ 수치 ID(이름 재사용 방어)
	OwnerID        string   // repository_owner_id — ★ 수치 ID
	Ref            string   // ref — 실행 ref(허용목록으로 좁힌다)
	JobWorkflowRef string   // job_workflow_ref — 배포 워크플로 하나로 고정
	Environment    string   // environment — 운영 승인 결박(현재는 자기 신고 · 잔여-5)
	JTI            string   // jti — 부작용 전 선점(토큰 재사용 = 재전송)
	IssuedAt       int64    // iat — unix 초
	NotBefore      int64    // nbf — unix 초(0이면 미설정)
	ExpiresAt      int64    // exp — unix 초
}

// OIDCPolicy는 claim 행렬이 대조하는 기대값들이다. 전부 식별자이며 시크릿은 아니지만
// 환경마다 다르므로 코드가 아니라 환경에서 온다(OIDC_* — .env.example 참조).
type OIDCPolicy struct {
	Issuer         string        // 기대 iss(발급자 하나)
	Audience       string        // 기대 aud(우리 전용값)
	Repository     string        // 기대 repository(owner/repo)
	RepositoryID   string        // 기대 repository_id(수치 ID)
	OwnerID        string        // 기대 repository_owner_id(수치 ID)
	RefAllowlist   []string      // 배포 가능 ref 허용목록(기본 = 기본 브랜치)
	JobWorkflowRef string        // 기대 job_workflow_ref(배포 워크플로 하나)
	Skew           time.Duration // exp/nbf/iat 판정 허용 시계 편차([구현 검증])
}

// OIDCDecision은 게이트 2의 결과다. 거절 사유(RL-8 기록 의무)와, 통과 시 선점할 jti,
// 그리고 운영 승인이 자기 신고에 머무는지(SelfReport · 잔여-5)를 담는다.
type OIDCDecision struct {
	Accepted bool
	Reason   string // Accepted=false일 때 영속화할 거절 사유(RL-8)
	JTI      string // 검증된 토큰의 jti — 부작용 전 선점에 쓴다(DO-10 ⑶)
	// SelfReport는 이 요청이 "우리 파이프라인에서 왔다"까지만 기계 증명되고 "운영
	// 승인됐다"는 자기 신고임을 나타낸다(DO-11 ⑵ / 잔여-5 — environment 결박이
	// 플랫폼에서 서는지는 [구현 검증]). 판정 전까지 통과 요청은 이 표식을 이력에 남긴다.
	SelfReport bool
}

// TokenVerifier는 OIDC 토큰의 서명을 검증하고 claim을 디코드한다. 발급자 JWKS 공개키로
// 서명을 확인하는 경계이며 — claim 행렬은 적용하지 않는다(그것은 OIDCVerifier의 몫).
// 실제 JWKS 페치는 이 인터페이스 뒤에 있어, 테스트는 합성 claim을 곧바로 돌려주는
// 페이크로 행렬만 순수하게 밟는다.
type TokenVerifier interface {
	// VerifyToken은 토큰을 파싱하고 서명을 검증한 뒤 claim을 반환한다. 서명이 발급자
	// 키로 검증되지 않거나 토큰 형식이 깨졌으면 오류다 — payload의 어떤 값도 신뢰하기
	// 전에 서명이 먼저 서야 한다.
	VerifyToken(ctx context.Context, rawToken string) (Claims, error)
}

// KeySet은 발급자 JWKS에서 kid에 해당하는 공개키를 준다. 실제 구현은 발급자의 JWKS
// 엔드포인트를 HTTPS로 페치·캐시하며(키 회전 포함), ⚠️ 그 발급자 URL·회전·캐시는
// [구현 검증]이다. 이 경계를 인터페이스로 두어 서명 검증 로직(정평 있는 라이브러리)과
// 네트워크 페치를 분리한다.
type KeySet interface {
	// VerificationKey는 kid에 해당하는 검증 공개키를 반환한다(RSA 공개키). 알 수 없는
	// kid·페치 실패는 오류다 — 키를 얻지 못하면 서명을 검증할 수 없으므로 거절로 이어진다.
	VerificationKey(ctx context.Context, kid string) (any, error)
}

var (
	// ErrOIDCMalformed는 토큰이 JWT 형식이 아니거나 서명 검증에 실패했음을 나타낸다.
	ErrOIDCMalformed = errors.New("auth: OIDC 토큰 형식·서명 검증 실패")
	// ErrNoIssuer 등 — 정책 로딩 시 필수 값 부재.
	ErrOIDCPolicyIncomplete = errors.New("auth: OIDC 정책 필수 값 미설정 (OIDC_*는 .env에서 온다)")
)

// jwksTokenVerifier는 golang-jwt로 RS256 서명을 검증하는 TokenVerifier다. 서명만
// 검증하고 claim 판정은 하지 않는다(WithoutClaimsValidation) — 시간·발급자·저장소 등
// 모든 claim 대조는 checkClaims 한 곳이 소유한다(단일 출처).
type jwksTokenVerifier struct {
	keys KeySet
}

// NewJWKSTokenVerifier는 JWKS 공개키로 서명을 검증하는 TokenVerifier를 만든다.
func NewJWKSTokenVerifier(keys KeySet) TokenVerifier {
	return &jwksTokenVerifier{keys: keys}
}

// VerifyToken은 RS256 서명만 검증하고 claim을 그대로 디코드해 반환한다. alg는
// RS256으로 고정한다 — "alg":"none"·대칭키 혼동 공격을 keyFunc 진입 전에 막는다.
func (t *jwksTokenVerifier) VerifyToken(ctx context.Context, rawToken string) (Claims, error) {
	parsed, err := jwt.Parse(rawToken, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("예상치 못한 서명 알고리즘: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		return t.keys.VerificationKey(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrOIDCMalformed, err)
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return Claims{}, ErrOIDCMalformed
	}
	return claimsFromMap(mc), nil
}

// claimsFromMap은 검증된 payload에서 우리가 쓰는 claim을 뽑는다. GitHub OIDC는
// repository_id·repository_owner_id를 문자열로, 시간 claim을 수치로 싣는다.
func claimsFromMap(mc jwt.MapClaims) Claims {
	return Claims{
		Issuer:         mapString(mc, "iss"),
		Audience:       mapAudience(mc, "aud"),
		Subject:        mapString(mc, "sub"),
		Repository:     mapString(mc, "repository"),
		RepositoryID:   mapString(mc, "repository_id"),
		OwnerID:        mapString(mc, "repository_owner_id"),
		Ref:            mapString(mc, "ref"),
		JobWorkflowRef: mapString(mc, "job_workflow_ref"),
		Environment:    mapString(mc, "environment"),
		JTI:            mapString(mc, "jti"),
		IssuedAt:       mapUnix(mc, "iat"),
		NotBefore:      mapUnix(mc, "nbf"),
		ExpiresAt:      mapUnix(mc, "exp"),
	}
}

func mapString(mc jwt.MapClaims, key string) string {
	if v, ok := mc[key].(string); ok {
		return v
	}
	return ""
}

// mapAudience는 aud를 뽑는다 — JWT의 aud는 문자열 하나 또는 문자열 배열이다.
func mapAudience(mc jwt.MapClaims, key string) []string {
	switch v := mc[key].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// mapUnix는 수치 시간 claim을 unix 초로 뽑는다(JSON 수는 기본 float64로 디코드된다).
func mapUnix(mc jwt.MapClaims, key string) int64 {
	if v, ok := mc[key].(float64); ok {
		return int64(v)
	}
	return 0
}

// OIDCVerifier는 게이트 2다: 서명 검증(TokenVerifier)과 claim 행렬(checkClaims)을 잇는다.
type OIDCVerifier struct {
	tokens TokenVerifier
	policy OIDCPolicy
	clock  Clock
}

// NewOIDCVerifier는 게이트 2를 만든다. tokens가 nil이면 서명을 검증할 수 없으므로
// 오류다(fail-closed — 검증 못 하는 경계를 세우지 않는다). clock이 nil이면 벽시계를
// 쓴다(테스트는 고정 시각을 주입해 exp 경계를 결정론적으로 밟는다).
func NewOIDCVerifier(tokens TokenVerifier, policy OIDCPolicy, clock Clock) (*OIDCVerifier, error) {
	if tokens == nil {
		return nil, errors.New("auth: TokenVerifier가 nil이다 (서명 검증 없이 게이트 2를 세울 수 없다)")
	}
	if clock == nil {
		clock = SystemClock{}
	}
	return &OIDCVerifier{tokens: tokens, policy: policy, clock: clock}, nil
}

// Verify는 게이트 2를 실행한다: 먼저 서명을 검증하고(claim을 신뢰하기 전 전제), 통과하면
// claim 행렬을 적용한다. 한 칸이라도 어긋나면 거절 사유와 함께 Accepted=false를 낸다
// (RL-8). 통과하면 선점할 jti와, 운영 승인이 자기 신고임을 나타내는 SelfReport를 담는다.
func (v *OIDCVerifier) Verify(ctx context.Context, rawToken string) OIDCDecision {
	claims, err := v.tokens.VerifyToken(ctx, rawToken)
	if err != nil {
		return OIDCDecision{Accepted: false, Reason: "OIDC 서명 검증 실패"}
	}
	if reason := v.checkClaims(claims, v.clock.Now()); reason != "" {
		// jti는 담아 둔다 — 감사 기록이 어떤 토큰이 거절됐는지 알 수 있게(신뢰값 아님).
		return OIDCDecision{Accepted: false, Reason: reason, JTI: claims.JTI}
	}
	// 통과 — "우리 파이프라인에서 왔다"까지 기계 증명. "운영 승인됐다"는 environment
	// 결박이 플랫폼에서 서는지 판정되기 전까지 자기 신고다(잔여-5 · IV-37).
	return OIDCDecision{Accepted: true, JTI: claims.JTI, SelfReport: true}
}

// checkClaims는 DO-11 행렬이다. 각 칸이 하나의 침입 경로를 닫으며, 불일치는 그 칸을
// 짚는 거절 사유가 된다(""는 통과). 순서는 값 대조(싼 것) → 시간 → jti 선점 필수다.
//
// ★ sub는 검사하지 않는다(DO-11 각주). claims.Subject는 위 칸들의 합성일 뿐이라
// 대조하면 형식 변화에 조용히 무너진다 — 구성 요소를 각각 본 것으로 판정이 끝난다.
func (v *OIDCVerifier) checkClaims(c Claims, now time.Time) string {
	if c.Issuer != v.policy.Issuer {
		return "iss 불일치 (다른 발급자)"
	}
	if !contains(c.Audience, v.policy.Audience) {
		return "aud 불일치 (우리 배포 전용 audience 아님)"
	}
	if c.Repository != v.policy.Repository {
		return "repository 불일치"
	}
	// ★ 이름이 맞아도 수치 ID를 함께 본다 — 이름은 이전·삭제 후 재생성으로 재사용된다.
	if c.RepositoryID != v.policy.RepositoryID {
		return "repository_id 불일치 (이름 재사용 방어 — 수치 ID)"
	}
	if c.OwnerID != v.policy.OwnerID {
		return "repository_owner_id 불일치 (수치 ID)"
	}
	if !contains(v.policy.RefAllowlist, c.Ref) {
		return "ref 허용목록 밖 (임의 브랜치·태그 배포 금지)"
	}
	if c.JobWorkflowRef != v.policy.JobWorkflowRef {
		return "job_workflow_ref 불일치 (같은 저장소의 다른 워크플로)"
	}

	// 시간 — exp/nbf/iat. 게이트 1의 신선도와 같은 축이며 허용 skew를 함께 본다.
	if c.ExpiresAt == 0 || c.IssuedAt == 0 {
		return "시간 claim 부재 (exp/iat)"
	}
	skew := v.policy.Skew
	exp := time.Unix(c.ExpiresAt, 0)
	if now.After(exp.Add(skew)) {
		return "토큰 만료 (exp 경과)"
	}
	iat := time.Unix(c.IssuedAt, 0)
	if iat.After(now.Add(skew)) {
		return "iat 미래 (아직 발급되지 않은 토큰)"
	}
	if c.NotBefore != 0 {
		nbf := time.Unix(c.NotBefore, 0)
		if now.Add(skew).Before(nbf) {
			return "nbf 미도래 (아직 유효하지 않은 토큰)"
		}
	}

	// jti는 부작용 전에 선점해야 재전송을 막는다(DO-10 ⑶) — 비어 있으면 선점할 키가
	// 없으므로 거절한다.
	if strings.TrimSpace(c.JTI) == "" {
		return "jti 부재 (일회성 선점 불가 — 재전송 방어)"
	}
	return ""
}

// contains는 s에 target이 있는지 본다(정확 일치 — 부분·프리픽스 대조가 아니다).
func contains(s []string, target string) bool {
	for _, e := range s {
		if e == target {
			return true
		}
	}
	return false
}

// LoadOIDCPolicy는 환경에서 게이트 2 정책을 읽는다. 필수 식별자가 하나라도 없으면
// 오류를 반환해 게이트를 열지 않는다(fail-closed — claim을 대조할 기대값이 없으면
// 검증이 성립하지 않는다). skew는 게이트 1과 같은 AGENT_CLOCK_SKEW를 쓴다.
func LoadOIDCPolicy() (OIDCPolicy, error) {
	p := OIDCPolicy{
		Issuer:         os.Getenv("OIDC_ISSUER"),
		Audience:       os.Getenv("OIDC_AUDIENCE"),
		Repository:     os.Getenv("OIDC_REPOSITORY"),
		RepositoryID:   os.Getenv("OIDC_REPOSITORY_ID"),
		OwnerID:        os.Getenv("OIDC_OWNER_ID"),
		JobWorkflowRef: os.Getenv("OIDC_JOB_WORKFLOW_REF"),
		RefAllowlist:   splitAllowlist(os.Getenv("OIDC_REF_ALLOWLIST")),
	}
	if p.Issuer == "" || p.Audience == "" || p.Repository == "" || p.RepositoryID == "" ||
		p.OwnerID == "" || p.JobWorkflowRef == "" || len(p.RefAllowlist) == 0 {
		return OIDCPolicy{}, ErrOIDCPolicyIncomplete
	}

	// skew는 게이트 1과 단일 출처를 공유한다 — 명시적 0s(엄격)를 존중하고, 미설정이면
	// 안전한 기본값으로 채운다.
	p.Skew = DefaultClockSkew
	if raw := os.Getenv("AGENT_CLOCK_SKEW"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < 0 {
			return OIDCPolicy{}, ErrBadSkew
		}
		p.Skew = d
	}
	return p, nil
}

// splitAllowlist는 콤마로 구분된 ref 허용목록을 자른다(공백 제거·빈 항목 무시).
func splitAllowlist(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
