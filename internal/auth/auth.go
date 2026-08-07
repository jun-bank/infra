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
// 검증 실패는 삼켜버릴 에러가 아니다: DO-2/RL-8은 실패한 요청을 거부로 기록할 것을
// 요구한다. 그 기록은 배포 스키마에 대해 호출자(agent)가 소유하는 부작용이며
// (internal/store), 이 패키지는 타입화된 판정을 반환할 뿐 영속화하지 않는다.
package auth

import "errors"

// ErrNotImplemented는 스캐폴드 표면을 표시한다. 모든 스텁이 이를 반환하므로, 이를
// 성급히 연결한 호출자는 조용히 통과하는 대신 요란하게 실패한다.
var ErrNotImplemented = errors.New("auth: not implemented (scaffold)")

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
	OIDCToken  string // GitHub Actions OIDC 토큰, 클레임 매트릭스로 검증(DO-11)
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
	// Verify는 HMAC(DO-2, DO-10) AND OIDC 클레임 매트릭스(DO-11)를 검사한다. 둘 다
	// 통과해야 하며, 불일치가 하나라도 있으면 Reason과 함께 Accepted=false를 낸다.
	// requestId/jti를 예약하지 않는다 — 예약은 internal/store가 소유하는 지속적
	// 부작용으로, 락 획득과 동일한 트랜잭션에서 일어나도록 한다(DO-17 ⑴).
	Verify(req Request) (Decision, error)
}

// stubVerifier는 스캐폴드 구현이다.
type stubVerifier struct{}

// NewVerifier는 (미구현) 게이트 1 verifier를 반환한다.
func NewVerifier() Verifier { return stubVerifier{} }

func (stubVerifier) Verify(Request) (Decision, error) {
	// TODO(DO-2, DO-10, DO-11): 정규화된 서명 범위에 대한 상수 시간 HMAC;
	// 만료/스큐 검사; OIDC 클레임 매트릭스(iss, aud, repository+id, owner+id,
	// ref/ref_type 허용목록, job_workflow_ref, exp/nbf/iat, jti, environment).
	// sub는 파생하고, 문자열 매칭하지 않는다.
	return Decision{}, ErrNotImplemented
}
