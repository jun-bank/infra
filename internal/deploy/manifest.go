package deploy

import (
	"encoding/json"
	"errors"
	"strings"
)

// manifest 검증 — CI가 서명하는 배포 manifest의 완전성·일치 확인(ADR-027 DO-18).
//
// body는 gate 1(HMAC)이 body digest를 서명 범위에 넣어 이미 진위를 증명했다 — 여기서
// 하는 것은 "그 진짜 body가 배포로서 완전하고 서명된 요청과 일치하는가"다. 파싱은
// 대상 추출(모드 판정에 필요)과 완전성 검증 둘로 나뉜다: 대상은 락 이전에 알아야 하므로
// ParseManifest가, 나머지 DO-18 완전성·형식·requestId 일치는 실행 직전(락 보유 중)
// VerifyManifest가 확인한다.
//
// 계약 출처(정본 — 재해석하지 않는다):
//   - ADR-027 DO-18  (CI는 태그가 아니라 manifest 전체를 서명 · 필수 6칸 · pull/up은
//     digest로 고정 — 태그 금지)
//   - ADR-027 DO-10 ⑴ (서명 밖의 값은 판정에 쓰지 않는다 — manifest의 requestId는 서명된
//     envelope requestId와 일치해야 한다)

var (
	// ErrManifestMalformed는 body가 manifest JSON으로 디코드되지 않을 때다.
	ErrManifestMalformed = errors.New("deploy: manifest JSON 파싱 불가")
	// ErrManifestTarget는 대상이 닫힌 집합(core|settlement|ledger|gateway) 밖일 때다(DO-20 v0.5).
	ErrManifestTarget = errors.New("deploy: manifest 대상이 닫힌 집합(core|settlement|ledger|gateway) 밖")
	// ErrManifestIncomplete는 DO-18 필수 6칸 중 하나라도 비었을 때다.
	ErrManifestIncomplete = errors.New("deploy: manifest 필수 필드 누락(DO-18 6칸)")
	// ErrManifestDigest는 image digest가 sha256: 고정 형식이 아닐 때다(태그 금지 — DO-18 ⑵).
	ErrManifestDigest = errors.New("deploy: image digest가 sha256: 고정 형식이 아니다(DO-18 ⑵ — 가변 태그 금지)")
	// ErrManifestRequestID는 manifest의 requestId가 서명된 envelope requestId와 다를 때다.
	ErrManifestRequestID = errors.New("deploy: manifest requestId가 서명된 requestId와 불일치(DO-10 ⑴)")
)

// digestPrefix는 이미지 참조가 태그가 아니라 내용 주소(digest)임을 강제하는 접두사다.
const digestPrefix = "sha256:"

// digestHexLen은 sha256 digest의 hex 부분 길이다(256비트 = 64자 hex).
const digestHexLen = 64

// validSHA256Digest는 image 참조가 sha256: 접두 + 정확히 64자 소문자 hex인지 본다(DO-18 ⑵
// — 내용 주소 고정). 접두만 보고 통과시키면 sha256:abc·sha256:latest 같은 위조·오타가
// digest로 위장해 실행 대상 고정이 무너지므로, 길이와 hex 문자 집합을 함께 강제한다.
// OCI/Docker canonical digest는 소문자 hex만 쓴다(대문자는 canonical이 아니어서 pull
// 참조로 재현되지 않을 수 있다) — 그래서 0-9a-f만 허용하고 대문자 A-F는 거부한다.
func validSHA256Digest(d string) bool {
	hex, ok := strings.CutPrefix(d, digestPrefix)
	if !ok || len(hex) != digestHexLen {
		return false
	}
	for _, c := range hex {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// Valid는 대상이 닫힌 배포 집합에 속하는지 본다(DO-20 v0.5 — 정확히 넷). 노출하는 것은
// 이 집합이 배포 밖(게이트 2의 repo↔target allowlist)에서도 필요하고, 거기서 다시 열거하면
// 정본이 둘이 되기 때문이다 — 대상 집합의 단일 출처는 이 패키지다.
func (t Target) Valid() bool {
	switch t {
	case TargetCore, TargetSettlement, TargetLedger, TargetGateway:
		return true
	default:
		return false
	}
}

// ValidTargets는 닫힌 배포 대상 집합을 열거한다(진단 메시지·설정 검증용). 순서는 DO-20
// v0.5의 열거 순서다.
func ValidTargets() []Target {
	return []Target{TargetCore, TargetSettlement, TargetLedger, TargetGateway}
}

// TargetOf는 서명·인증된 body에서 target 필드 **하나만** 부분 디코드한다. 진입 층의
// repo↔target 결박 대조(게이트 2가 판정한 허용 target과의 대조)가 멱등 선점 이전에
// 서야 하는데, 그 자리에서 manifest 완전성까지 검증하면 검증의 정본이 둘이 된다 —
// 완전성·digest·requestId 일치는 여전히 VerifyManifest가 소유한다(단일 출처).
//
// 반환값은 검증되지 않은 원시 target이다(닫힌 집합 여부를 여기서 보지 않는다) —
// 호출자가 허용 target과 대조하며, 그 대조가 닫힌 집합 밖 값도 함께 걸러낸다.
func TargetOf(body []byte) (Target, error) {
	var probe struct {
		Target Target `json:"target"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", ErrManifestMalformed
	}
	return probe.Target, nil
}

// ParseManifest는 서명·인증된 body를 manifest로 디코드하고 대상만 확인한다. 대상은
// 모드 판정(DecideMode)에 필요하므로 락 이전에 알아야 한다 — 나머지 DO-18 완전성 검증은
// 락 획득 뒤 VerifyManifest가 실행 직전에 한다. 파싱 실패·대상 이탈은 거절 대상이다.
func ParseManifest(body []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Manifest{}, ErrManifestMalformed
	}
	if !m.Target.Valid() {
		return Manifest{}, ErrManifestTarget
	}
	return m, nil
}

// VerifyManifest는 실행 직전(락 보유 중) manifest가 완전하고 서명된 요청과 일치하는지
// 검증한다(DO-18). ⑴ 대상 재확인 ⑵ 필수 6칸 완전성 ⑶ image digest 고정 형식(태그 금지)
// ⑷ manifest의 requestId가 서명된 envelope requestId와 일치(DO-10 ⑴ — 서명 밖의 값은
// 판정에 쓰지 않는다). 어느 하나라도 어긋나면 거절한다 — 통과 없이 실행하지 않는다.
func VerifyManifest(m Manifest, signedRequestID string) error {
	if !m.Target.Valid() {
		return ErrManifestTarget
	}
	if m.CommitSHA == "" || m.ImageDigest == "" || m.ComposeRevision == "" || m.ConfigVersion == "" || m.RequestID == "" {
		return ErrManifestIncomplete
	}
	if !validSHA256Digest(m.ImageDigest) {
		return ErrManifestDigest
	}
	if m.RequestID != signedRequestID {
		return ErrManifestRequestID
	}
	return nil
}
