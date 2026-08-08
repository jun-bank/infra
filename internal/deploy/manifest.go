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
	// ErrManifestTarget는 대상이 닫힌 집합(core|settlement|ledger) 밖일 때다(DO-20).
	ErrManifestTarget = errors.New("deploy: manifest 대상이 닫힌 집합(core|settlement|ledger) 밖")
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

// validSHA256Digest는 image 참조가 sha256: 접두 + 정확히 64자 hex인지 본다(DO-18 ⑵ —
// 내용 주소 고정). 접두만 보고 통과시키면 sha256:abc·sha256:latest 같은 위조·오타가
// digest로 위장해 실행 대상 고정이 무너지므로, 길이와 hex 문자 집합을 함께 강제한다.
func validSHA256Digest(d string) bool {
	hex, ok := strings.CutPrefix(d, digestPrefix)
	if !ok || len(hex) != digestHexLen {
		return false
	}
	for _, c := range hex {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// valid는 대상이 닫힌 배포 집합에 속하는지 본다(DO-20 — 정확히 셋).
func (t Target) valid() bool {
	switch t {
	case TargetCore, TargetSettlement, TargetLedger:
		return true
	default:
		return false
	}
}

// ParseManifest는 서명·인증된 body를 manifest로 디코드하고 대상만 확인한다. 대상은
// 모드 판정(DecideMode)에 필요하므로 락 이전에 알아야 한다 — 나머지 DO-18 완전성 검증은
// 락 획득 뒤 VerifyManifest가 실행 직전에 한다. 파싱 실패·대상 이탈은 거절 대상이다.
func ParseManifest(body []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Manifest{}, ErrManifestMalformed
	}
	if !m.Target.valid() {
		return Manifest{}, ErrManifestTarget
	}
	return m, nil
}

// VerifyManifest는 실행 직전(락 보유 중) manifest가 완전하고 서명된 요청과 일치하는지
// 검증한다(DO-18). ⑴ 대상 재확인 ⑵ 필수 6칸 완전성 ⑶ image digest 고정 형식(태그 금지)
// ⑷ manifest의 requestId가 서명된 envelope requestId와 일치(DO-10 ⑴ — 서명 밖의 값은
// 판정에 쓰지 않는다). 어느 하나라도 어긋나면 거절한다 — 통과 없이 실행하지 않는다.
func VerifyManifest(m Manifest, signedRequestID string) error {
	if !m.Target.valid() {
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
