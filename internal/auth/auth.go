// Package auth는 두 배포 게이트 중 게이트 1이다: 어떤 SSH 전송이 열리기 전에 요청이
// 진짜이고 신선한지를 판정한다(ADR-027 DO-2). 그 순서는 안전 속성이다 — 여기서
// 검증을 통과하지 못한 요청은 절대 SSH 계층에 도달해서는 안 된다.
//
// 계약 출처(정본):
//   - ADR-027 DO-2   (서명 검증; 실패 시 거부 후 기록, RL-8)
//   - ADR-027 DO-10  (신선도 + 멱등성: 서명 범위, 만료/스큐, requestId/jti 예약,
//     동일 id/동일 digest 재생)
//   - ADR-027 DO-11  (OIDC 클레임 매트릭스; HMAC AND OIDC; sub는 매칭이 아니라 파생)
//
// 이 패키지가 이번 이슈(S1-2)에서 채우는 것은 HMAC 서명 + 신선도(DO-2 · DO-10 ⑴⑵)
// 까지다. OIDC 클레임 매트릭스(DO-11)는 게이트 1의 두 번째 절반으로 다음 마일스톤
// (S1-3)에서 붙는다 — 아래 Verify는 아직 OIDC를 강제하지 않으며, 그 사실을 조용히
// 숨기지 않는다(SelfReport 계약은 그 자리를 위해 남겨 둔다).
//
// 검증 실패는 삼켜버릴 에러가 아니다: DO-2/RL-8은 실패한 요청을 거부로 기록할 것을
// 요구한다. 그 기록은 배포 스키마에 대해 호출자(agent)가 소유하는 부작용이며
// (internal/store), 이 패키지는 타입화된 판정을 반환할 뿐 영속화하지 않는다.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"time"
)

// Request는 서명이 덮는 필드를 정확히 담는다(DO-10 ⑴). 서명 범위 밖의 값은 판정에
// 영향을 주어서는 안 된다("서명 밖의 값은 판정에 쓰지 않는다").
type Request struct {
	Method     string
	Path       string
	BodyDigest string // raw body의 digest — body 자체는 하류에서 재해시하지 않는다
	RequestID  string // 멱등성 키(DO-10 ⑶⑷)
	IssuedAt   string // RFC3339; 허용 스큐에 대해 검사(DO-10 ⑵)
	ExpiresAt  string // RFC3339; 과거면 거부 후 기록(DO-10 ⑵)
	Signature  []byte // 정규화된 (method,path,bodyDigest,requestId,issuedAt,expiresAt)에 대한 HMAC
	OIDCToken  string // GitHub Actions OIDC 토큰, 클레임 매트릭스로 검증(DO-11 — S1-3)
}

// Decision은 게이트 1의 결과다. 호출자가 거부 기록 의무(RL-8)를 충족할 수 있도록
// 거부에 대해 의도적으로 명시적이다.
type Decision struct {
	Accepted   bool
	Reason     string // Accepted가 false일 때 영속화할 거부 사유(RL-8)
	SelfReport bool   // 운영 승인이 자기 보고로만 가능했을 때 true(DO-11 ⑵ / 잔여-5)
}

// Verifier는 게이트 1을 실행한다. 인터넷 입력을 파싱하는 경계다; DO-14 ⑸에 따라 이
// 경계는 SSH 키나 DB 자격증명을 보유해서는 안 된다 — 그것들은 실행자 측에 있다.
// 이를 인터페이스로 유지함으로써 그 프로세스 분리를 보존한다.
type Verifier interface {
	// Verify는 HMAC(DO-2, DO-10)를 검사한다. S1-3에서 OIDC 클레임 매트릭스(DO-11)가
	// 같은 판정에 AND로 합류한다. 불일치가 하나라도 있으면 Reason과 함께
	// Accepted=false를 낸다. requestId/jti를 예약하지 않는다 — 예약은 internal/store가
	// 소유하는 지속적 부작용으로, 락 획득과 동일한 트랜잭션에서 일어나도록 한다(DO-17 ⑴).
	Verify(req Request) (Decision, error)
}

// Clock은 신선도 판정에 쓰는 현재 시각의 출처다. 실제 구현은 time.Now를 쓰고, 테스트는
// 만료·스큐 경계를 결정론적으로 밟기 위해 고정 시각을 주입한다(DO-10 ⑵ — 시각은
// 주입 가능해야 한다).
type Clock interface {
	Now() time.Time
}

// SystemClock은 벽시계를 읽는 기본 Clock이다.
type SystemClock struct{}

// Now는 현재 시각을 반환한다.
func (SystemClock) Now() time.Time { return time.Now() }

// DefaultClockSkew는 AGENT_CLOCK_SKEW가 없을 때 쓰는 허용 시계 편차다.
//
// ⚠️ 이 값은 [구현 검증]이다(DO-10 ⑵ · IV 축). 짧으면 정상 요청이 CI·엣지·허브의
// 시계 차이로 거절되고, 길면 탈취된 유효 요청의 재사용 창이 넓어진다 — 실제 값은
// 세 지점의 실측 편차를 보고 정해진다. 여기 상수는 안전한 기본값일 뿐이며 시크릿이
// 아니다(env로 덮어쓴다).
const DefaultClockSkew = 60 * time.Second

var (
	// ErrNoKey는 HMAC 키가 설정되지 않았음을 나타낸다. 키 없이 verifier를 만들지
	// 않는다 — 검증할 수 없는 경계를 여는 것은 fail-open이다.
	ErrNoKey = errors.New("auth: HMAC 키 미설정 (AGENT_HMAC_KEY는 .env에서 온다)")
	// ErrBadSkew는 AGENT_CLOCK_SKEW 값이 올바르지 않을 때 반환된다.
	ErrBadSkew = errors.New("auth: AGENT_CLOCK_SKEW 값이 올바르지 않다 (Go duration이어야 한다)")
)

// Config는 게이트 1의 검증 설정이다. 키는 시크릿이며 값은 전부 환경에서 온다
// (하드코딩 0 — .env.example 참조).
type Config struct {
	// Key는 HMAC 서명 키다(DO-2 · IV-14 ⑶ 발급·교체). 시크릿 — 코드에 값이 없다.
	Key []byte
	// Skew는 issuedAt/expiresAt 판정에 쓰는 허용 시계 편차다(DO-10 ⑵ · [구현 검증]).
	// 포인터로 두어 "미설정(nil)"과 "명시적 0s(엄격)"를 구분한다 — 값 타입이면 둘 다
	// 0이라, 운영자가 명시한 무-skew(엄격)가 기본값(60s)으로 조용히 완화된다. nil이면
	// DefaultClockSkew로 채우고, non-nil이면 명시적 0을 포함해 받은 값을 그대로 존중한다.
	Skew *time.Duration
}

// LoadConfig는 환경에서 검증 설정을 읽는다. 키가 없으면 오류를 반환해 게이트를 열지
// 않는다(fail-closed — 검증 못 하는 경계를 세우지 않는다).
func LoadConfig() (Config, error) {
	key := os.Getenv("AGENT_HMAC_KEY")
	if key == "" {
		return Config{}, ErrNoKey
	}

	// 기본값 채움은 여기(미설정일 때)만 한다. AGENT_CLOCK_SKEW가 명시적 "0s"면 0을
	// 그대로 실어 보낸다(무-skew=엄격) — 이 아래 계층은 받은 값을 되돌리지 않는다.
	skew := DefaultClockSkew
	if raw := os.Getenv("AGENT_CLOCK_SKEW"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < 0 {
			return Config{}, ErrBadSkew
		}
		skew = d
	}

	return Config{Key: []byte(key), Skew: &skew}, nil
}

// hmacVerifier는 HMAC-SHA256 + 신선도 판정을 하는 Verifier다.
type hmacVerifier struct {
	key   []byte
	skew  time.Duration
	clock Clock
}

// NewVerifier는 HMAC verifier를 만든다. clock이 nil이면 벽시계를 쓴다(테스트는
// 고정 시각을 주입한다). 키가 비어 있으면 오류다 — 키 없는 verifier를 만들지 않는다.
func NewVerifier(cfg Config, clock Clock) (Verifier, error) {
	if len(cfg.Key) == 0 {
		return nil, ErrNoKey
	}
	if clock == nil {
		clock = SystemClock{}
	}
	// 받은 값을 신뢰한다: 명시된 스큐(명시적 0=엄격 포함)를 조용히 되돌리지 않는다.
	// nil(미설정)일 때만 기본값을 채운다 — 직접 조립 시의 안전한 기본값이며, env
	// 미설정 경로의 기본값 채움은 LoadConfig가 소유한다.
	skew := DefaultClockSkew
	if cfg.Skew != nil {
		skew = *cfg.Skew
	}
	return &hmacVerifier{key: cfg.Key, skew: skew, clock: clock}, nil
}

// Canonicalize는 서명 대상 바이트열을 만든다(DO-10 ⑴ — 서명 범위). CI 서명자와 이
// 검증자가 반드시 같은 형태를 만들어야 하므로, 정규화는 여기 한 곳에서만 정의된다:
//   - method는 대문자로 정규화한다(HTTP method는 대소문자 무관 — 다른 표기를 같은
//     서명으로 취급하지 않도록 한 형태로 고정한다).
//   - path·bodyDigest·requestId·issuedAt·expiresAt는 받은 그대로 쓴다.
//   - 필드는 개행(\n)으로 잇는다. 개행은 필드 값에 나타나지 않으므로 경계가 모호하지
//     않다(method·RFC3339 시각·hex digest·URL path에 raw 개행이 없다).
//
// ⚠️ 이 형식(구분자·method 정규화)은 [구현 검증]이다 — CI 서명 워크플로와 짝을 맞춘
// 실제 계약이며, 한쪽만 바꾸면 모든 서명이 조용히 불일치한다.
func Canonicalize(req Request) []byte {
	var b strings.Builder
	b.WriteString(strings.ToUpper(req.Method))
	b.WriteByte('\n')
	b.WriteString(req.Path)
	b.WriteByte('\n')
	b.WriteString(req.BodyDigest)
	b.WriteByte('\n')
	b.WriteString(req.RequestID)
	b.WriteByte('\n')
	b.WriteString(req.IssuedAt)
	b.WriteByte('\n')
	b.WriteString(req.ExpiresAt)
	return []byte(b.String())
}

// Sign은 키로 정규화된 서명 범위에 대한 HMAC-SHA256을 계산한다. 검증자와 (테스트의)
// 서명자가 같은 함수를 쓰도록 노출한다 — 서명·검증이 갈라지지 않게 하는 단일 출처다.
func Sign(key []byte, req Request) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(Canonicalize(req))
	return mac.Sum(nil)
}

// Verify는 HMAC 서명(진위)과 신선도(만료·스큐)를 판정한다. 둘 중 하나라도 실패하면
// 거부하고 기록 가능한 사유를 담는다(RL-8 — 서명 실패는 무조건 거절).
//
// 판정 순서: 서명을 먼저 본다(진위). 서명이 맞아도 신선도가 어긋나면 거절한다 —
// HMAC은 진위를 증명할 뿐 freshness를 보장하지 않기 때문이다(DO-10 근거: 유효 요청
// 한 건을 탈취하면 같은 배포를 언제든 다시 실행할 수 있다).
func (v *hmacVerifier) Verify(req Request) (Decision, error) {
	// ⑴ 진위 — 상수 시간 HMAC 비교(hmac.Equal). 길이·내용 어느 쪽으로도 타이밍이
	// 새지 않는다. 서명 범위 밖의 값(예: OIDCToken)은 이 계산에 들어가지 않는다.
	expected := Sign(v.key, req)
	if !hmac.Equal(expected, req.Signature) {
		return Decision{Accepted: false, Reason: "서명 불일치"}, nil
	}

	// ⑵ 신선도 — issuedAt/expiresAt를 RFC3339로 파싱한다. 파싱 실패도 거절이다
	// (서명은 이 문자열을 덮으므로 형식 오류 = 위조되었거나 잘못 만든 요청).
	issuedAt, err := time.Parse(time.RFC3339, req.IssuedAt)
	if err != nil {
		return Decision{Accepted: false, Reason: "issuedAt 형식 오류"}, nil
	}
	expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		return Decision{Accepted: false, Reason: "expiresAt 형식 오류"}, nil
	}
	if !expiresAt.After(issuedAt) {
		return Decision{Accepted: false, Reason: "유효 창이 비었다 (expiresAt <= issuedAt)"}, nil
	}

	now := v.clock.Now()
	// 만료: 지금이 expiresAt를 스큐만큼 넘어섰으면 거절(DO-10 ⑵).
	if now.After(expiresAt.Add(v.skew)) {
		return Decision{Accepted: false, Reason: "요청 만료 (expiresAt 경과)"}, nil
	}
	// 미래: issuedAt가 지금보다 스큐 이상 앞서 있으면 거절(아직 유효하지 않다).
	if issuedAt.After(now.Add(v.skew)) {
		return Decision{Accepted: false, Reason: "요청이 아직 유효하지 않다 (issuedAt 미래)"}, nil
	}

	// HMAC + 신선도 통과. OIDC(DO-11)는 아직 강제하지 않으므로 운영 승인은 이 단계에서
	// 자기 보고 한계를 갖는다 — 그 사실을 SelfReport로 드러내 이력에 남긴다(잔여-5).
	return Decision{Accepted: true, SelfReport: true}, nil
}
