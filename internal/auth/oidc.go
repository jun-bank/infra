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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	// 배포 대상의 닫힌 집합(deploy.Target)은 deploy 패키지가 정본이다 — allowlist가 그
	// 집합을 다시 열거하면 정본이 둘이 되어 조용히 갈라진다. deploy는 auth를 import하지
	// 않으므로(deploy → store 방향뿐) 이 방향에 순환은 없다.
	"github.com/jun-bank/infra/internal/deploy"
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
	NotBefore      int64    // nbf — unix 초(0이면 부재 · 있는데 형식 오류는 malformedTime으로)
	ExpiresAt      int64    // exp — unix 초

	// malformedTime은 값이 존재하나 수치가 아닌 시간 claim의 이름이다(exp/iat/nbf 중 하나).
	// 비어 있으면 형식 문제 없음. 있으면 checkClaims가 거절한다 — absent(없음)와 invalid
	// (형식 오류)를 구분해, 있는데 형식 오류인 시간 claim을 무음 스킵하지 않는다.
	malformedTime string
}

// OIDCPolicy는 claim 행렬이 대조하는 기대값들이다. 전부 식별자이며 시크릿은 아니지만
// 환경마다 다르므로 코드가 아니라 환경에서 온다(OIDC_* — .env.example 참조).
//
// 저장소에 관한 세 칸(repository·repository_id·job_workflow_ref)은 전역 기대값이 아니라
// Allowlist의 항목별 값이다 — 배포 대상이 여럿이 되면서 "우리 저장소 하나"라는 기대가
// "등재된 저장소들 중 하나"로 바뀌었기 때문이다(design D2). 나머지 칸(iss·aud·owner_id·
// ref·시간)은 전역 공통 그대로다(A5).
type OIDCPolicy struct {
	Issuer       string        // 기대 iss(발급자 하나)
	Audience     string        // 기대 aud(우리 전용값)
	OwnerID      string        // 기대 repository_owner_id(수치 ID — 조직 전역 공통)
	RefAllowlist []string      // 배포 가능 ref 허용목록(기본 = 기본 브랜치)
	Allowlist    OIDCAllowlist // 등재 저장소 → 허용 target(A1·A2 — oidc_allowlist.go)
	Skew         time.Duration // exp/nbf/iat 판정 허용 시계 편차([구현 검증])
}

// 게이트 2가 내는 기계 판독 거절 코드다(RL-8 이력의 ReasonCode). 사람이 읽는 사유
// 문자열은 문면이 바뀌면 집계·알림이 조용히 깨지므로, **운영 대응이 갈리는** 사유에는
// 코드를 함께 싣는다:
//
//	UNREGISTERED_REPO      — 등재되지 않은 저장소(권한 없음 · 침입 조사 대상)
//	REPO_RENAMED           — ID는 등재됐으나 이름이 다름(allowlist 갱신 필요 · 운영 조치)
//	WORKFLOW_REF_MISMATCH  — 등재 저장소의 다른 워크플로(CI 설정 오류 또는 우회 시도)
//
// 나머지 행렬 칸(iss·aud·시간·jti 등)은 코드를 붙이지 않는다 — 대응이 "거절 확인"으로
// 같고, 코드 어휘를 필요 없이 늘리면 그 자체가 유지 대상이 된다. 필요해지면 그때 는다.
const (
	ReasonUnregisteredRepo    = "UNREGISTERED_REPO"
	ReasonRepoRenamed         = "REPO_RENAMED"
	ReasonWorkflowRefMismatch = "WORKFLOW_REF_MISMATCH"
)

// OIDCReject는 하나의 거절이다: 기계 판독 코드(없을 수 있다)와 사람이 읽는 사유.
// Reason이 비어 있으면 거절이 아니다(통과).
type OIDCReject struct {
	Code   string
	Reason string
}

// rejected는 이 값이 거절인지 본다(사유가 곧 거절의 존재다).
func (r OIDCReject) rejected() bool { return r.Reason != "" }

// OIDCDecision은 게이트 2의 결과다. 거절 사유(RL-8 기록 의무)와, 통과 시 선점할 jti,
// 그리고 운영 승인이 자기 신고에 머무는지(SelfReport · 잔여-5)를 담는다.
type OIDCDecision struct {
	Accepted bool
	Reason   string // Accepted=false일 때 영속화할 거절 사유(RL-8 — 사람이 읽는 문장)
	// ReasonCode는 그 거절의 기계 판독 코드다(위 Reason* 상수 중 하나 또는 빈 값).
	// 이력에 함께 남아 코드별 질의·알림이 문자열 매칭에 기대지 않게 한다.
	ReasonCode string
	JTI        string // 검증된 토큰의 jti — 부작용 전 선점에 쓴다(DO-10 ⑶)
	// AllowedTarget은 이 신원이 배포할 수 있는 대상 하나다(allowlist 항목의 target).
	// Accepted=true일 때만 의미가 있으며, 진입 층이 요청 manifest의 target과 대조해
	// repo↔target 결박을 세운다(A2 · design rev.2 변경 ①). 신원 판정의 산출물이므로
	// 하류는 이것을 재해석·재파싱하지 않는다.
	AllowedTarget deploy.Target
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
	iat, iatBad := mapUnix(mc, "iat")
	nbf, nbfBad := mapUnix(mc, "nbf")
	exp, expBad := mapUnix(mc, "exp")
	c := Claims{
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
		IssuedAt:       iat,
		NotBefore:      nbf,
		ExpiresAt:      exp,
	}
	// 값이 존재하나 수치가 아닌 시간 claim은 거절 대상으로 표시한다 — 서명된 토큰의
	// `"nbf":"invalid"` 같은 형식 오류가 0으로 무음 치환돼 검증을 건너뛰는 것을 막는다
	// (있는데 형식 오류 → 거절 · 반-silent-failure). 여럿이면 첫 칸을 사유로 짚는다.
	switch {
	case expBad:
		c.malformedTime = "exp"
	case iatBad:
		c.malformedTime = "iat"
	case nbfBad:
		c.malformedTime = "nbf"
	}
	return c
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
// malformed는 키가 존재하나 수치가 아님을 나타낸다 — 이때 0으로 무음 치환하지 않고
// 거절 대상으로 표시해야 한다(있는데 형식 오류 → 거절 · absent와 구분). 키 부재는
// malformed=false·0이며, 필수 여부는 checkClaims가 판정한다.
func mapUnix(mc jwt.MapClaims, key string) (seconds int64, malformed bool) {
	raw, ok := mc[key]
	if !ok {
		return 0, false // 부재 — 무음 스킵이 아니라 "없음"이다
	}
	switch v := raw.(type) {
	case float64:
		return int64(v), false
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n, false
		}
		return 0, true // 수치 문자열이 아님 → 형식 오류
	default:
		return 0, true // 존재하나 수치 아님(문자열·bool 등) → 형식 오류
	}
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
	target, rej := v.checkClaims(claims, v.clock.Now())
	if rej.rejected() {
		// jti는 담아 둔다 — 감사 기록이 어떤 토큰이 거절됐는지 알 수 있게(신뢰값 아님).
		return OIDCDecision{Accepted: false, Reason: rej.Reason, ReasonCode: rej.Code, JTI: claims.JTI}
	}
	// 통과 — "우리 파이프라인에서 왔다"까지 기계 증명. "운영 승인됐다"는 environment
	// 결박이 플랫폼에서 서는지 판정되기 전까지 자기 신고다(잔여-5 · IV-37). 허용 target을
	// 함께 실어 보내 진입 층이 요청 대상과 결박하게 한다(A2).
	return OIDCDecision{Accepted: true, JTI: claims.JTI, SelfReport: true, AllowedTarget: target}
}

// checkClaims는 DO-11 행렬이다. 각 칸이 하나의 침입 경로를 닫으며, 불일치는 그 칸을
// 짚는 거절 사유가 된다(사유 ""가 통과이며, 그때 첫 반환값이 이 신원의 허용 target이다).
// 순서는 값 대조(싼 것) → 시간 → jti 선점 필수다.
//
// 저장소 세 칸은 단일 기대값 대조가 아니라 allowlist 매칭이다(design D2): 수치 ID로
// 항목을 찾고(A1), 그 항목의 이름·워크플로가 전부 일치해야 통과한다. 거절 사유는 넷을
// 구분한다 — 미등재 / 이름 불일치(개명·이전 감지) / 워크플로 불일치 / (진입 층이 판정하는)
// target 불일치. 사유가 뭉개지면 거절 기록만 보고는 오설정과 침입을 가를 수 없다.
//
// ★ sub는 검사하지 않는다(DO-11 각주). claims.Subject는 위 칸들의 합성일 뿐이라
// 대조하면 형식 변화에 조용히 무너진다 — 구성 요소를 각각 본 것으로 판정이 끝난다.
func (v *OIDCVerifier) checkClaims(c Claims, now time.Time) (deploy.Target, OIDCReject) {
	if c.Issuer != v.policy.Issuer {
		return "", OIDCReject{Reason: "iss 불일치 (다른 발급자)"}
	}
	// aud는 정확히 우리 audience 하나여야 한다 — 포함(contains) 검사면 우리값에 다른
	// audience가 섞인 다중 aud 토큰도 통과한다. DO-11의 "전용" 문언은 단일값 기대이므로,
	// 배열이면 원소가 1개이고 그 값이 우리 audience와 같아야 한다(정확 일치).
	if len(c.Audience) != 1 || c.Audience[0] != v.policy.Audience {
		return "", OIDCReject{Reason: "aud 불일치 (우리 배포 전용 audience 정확히 하나 아님)"}
	}
	// ★ allowlist의 키는 수치 ID다 — 이름은 이전·삭제 후 재생성으로 재사용되지만 수치
	// ID는 재사용되지 않는다(A1). 이름은 아래에서 부가 대조한다.
	entry, listed := v.policy.Allowlist.lookup(c.RepositoryID)
	if !listed {
		return "", OIDCReject{Code: ReasonUnregisteredRepo, Reason: "미등재 저장소 (repository_id가 allowlist에 없다 — 배포 권한 없음)"}
	}
	// ID는 등재됐는데 이름이 다르다 = 저장소 개명·이전이거나 토큰 위조 시도다. 어느 쪽이든
	// allowlist가 현실과 어긋난 상태이므로 통과시키지 않고 사유를 구분해 남긴다.
	if !asciiEqualFold(c.Repository, entry.Repository) {
		return "", OIDCReject{Code: ReasonRepoRenamed, Reason: "repository 이름 불일치 (등재 ID의 이름은 " + entry.Repository + " — 개명·이전 감지)"}
	}
	if c.OwnerID != v.policy.OwnerID {
		return "", OIDCReject{Reason: "repository_owner_id 불일치 (수치 ID)"}
	}
	// ★ repository_owner(이름)·ref_type을 별도 칸으로 보지 않는 것은 무음 누락이 아니라
	// 의도된 대체다 — owner는 위 수치 repository_owner_id(이름 재사용에 강함)로, ref_type은
	// 아래 완전 ref 허용목록(refs/heads/main 등 ref 전체 대조)으로 각각 더 강하게 판정한다
	// (DO-11 문언의 이름·ref_type 검사보다 강한 검사로 대체).
	if !contains(v.policy.RefAllowlist, c.Ref) {
		return "", OIDCReject{Reason: "ref 허용목록 밖 (임의 브랜치·태그 배포 금지)"}
	}
	if c.JobWorkflowRef != entry.JobWorkflowRef {
		return "", OIDCReject{Code: ReasonWorkflowRefMismatch, Reason: "job_workflow_ref 불일치 (같은 저장소의 다른 워크플로)"}
	}

	// 시간 — exp/nbf/iat. 게이트 1의 신선도와 같은 축이며 허용 skew를 함께 본다.
	// 값이 존재하나 형식이 깨진 시간 claim은 무음 스킵하지 않고 거절한다(absent와 invalid를
	// 구분: 없으면 아래 필수 여부로, 있는데 형식 오류면 여기서 거절).
	if c.malformedTime != "" {
		return "", OIDCReject{Reason: "시간 claim 형식 오류 (" + c.malformedTime + " 값이 수치 아님 — 무음 스킵 금지)"}
	}
	if c.ExpiresAt == 0 || c.IssuedAt == 0 {
		return "", OIDCReject{Reason: "시간 claim 부재 (exp/iat)"}
	}
	skew := v.policy.Skew
	exp := time.Unix(c.ExpiresAt, 0)
	if now.After(exp.Add(skew)) {
		return "", OIDCReject{Reason: "토큰 만료 (exp 경과)"}
	}
	iat := time.Unix(c.IssuedAt, 0)
	if iat.After(now.Add(skew)) {
		return "", OIDCReject{Reason: "iat 미래 (아직 발급되지 않은 토큰)"}
	}
	if c.NotBefore != 0 {
		nbf := time.Unix(c.NotBefore, 0)
		if now.Add(skew).Before(nbf) {
			return "", OIDCReject{Reason: "nbf 미도래 (아직 유효하지 않은 토큰)"}
		}
	}

	// jti는 부작용 전에 선점해야 재전송을 막는다(DO-10 ⑶) — 비어 있으면 선점할 키가
	// 없으므로 거절한다.
	if strings.TrimSpace(c.JTI) == "" {
		return "", OIDCReject{Reason: "jti 부재 (일회성 선점 불가 — 재전송 방어)"}
	}
	return entry.Target, OIDCReject{}
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
//
// 저장소별 allowlist는 loadOIDCAllowlist가 소유한다(파일 모드 · 단일 env 세트 정규화 ·
// 각각의 기동 거부 가지 — oidc_allowlist.go). 로딩은 기동 시 1회이며 갱신은 재기동이다.
func LoadOIDCPolicy() (OIDCPolicy, error) {
	p := OIDCPolicy{
		Issuer:       os.Getenv("OIDC_ISSUER"),
		Audience:     os.Getenv("OIDC_AUDIENCE"),
		OwnerID:      os.Getenv("OIDC_OWNER_ID"),
		RefAllowlist: splitAllowlist(os.Getenv("OIDC_REF_ALLOWLIST")),
	}
	if p.Issuer == "" || p.Audience == "" || p.OwnerID == "" || len(p.RefAllowlist) == 0 {
		return OIDCPolicy{}, ErrOIDCPolicyIncomplete
	}

	allowlist, err := loadOIDCAllowlist()
	if err != nil {
		return OIDCPolicy{}, err
	}
	p.Allowlist = allowlist

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
