package dispatch

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// /internal 관리 표면 인가(canonical-v1) — 게이트웨이의 라우트 조회(GET)·전환(POST)에
// HMAC-SHA256 서명을 붙인다. 이 서명이 "이 표면을 호출한 주체가 배포 agent다"를 증명한다
// (LAN 경계만으로는 LAN 내 어떤 프로세스든 전환을 호출할 수 있다).
//
// ⚠️ N3(interop 치명): 이 파일은 배포 게이트 1의 auth.Sign을 **호출하지 않는다**. auth.Sign은
// 6필드 canonical(method·path·bodyDigest·requestId·issuedAt·expiresAt)을 내부에 하드코딩하는데,
// 관리 표면 canonical-v1은 **4필드**(method·path·bodyDigest·timestamp)다 — auth.Sign을 그대로
// 부르면 전건 불일치한다. 공유하는 것은 HMAC-SHA256 프리미티브(crypto/hmac·crypto/sha256)까지,
// canonical-v1은 관리 표면 전용 신규 형식이다.
//
// canonical-v1 규격(게이트웨이 검증기와 바이트 동일해야 한다 — B2, 한쪽만 바꾸면 전건 불일치):
//
//		<METHOD>\n<path>\n<bodyDigest>\n<timestamp>
//
//	  - METHOD 대문자 정규화(GET·POST).
//	  - path = 요청 경로(쿼리 제외). 관리 표면은 쿼리를 쓰지 않는다.
//	  - bodyDigest = "sha256:" + 소문자 hex(sha256(raw 수신 바이트)). 빈 body는 빈 바이트의
//	    고정 digest다 — "body 없음"도 서명 범위에 명시적으로 든다(빈 body 위조 차단).
//	  - timestamp = Unix 초, 엄격 10진(앞자리 0·부호·소수점 없음). 신선도 판정 입력.
//	  - 필드 사이만 개행("\n") — canonical 끝에는 개행이 없다.
//
// 서명 = HMAC-SHA256(key, canonical) → 소문자 hex. 키는 raw 바이트다(hex 디코드 아님).
const (
	// HeaderInternalSignature는 canonical-v1 HMAC 서명(소문자 hex)을 싣는 헤더다.
	HeaderInternalSignature = "X-Internal-Signature"
	// HeaderInternalTimestamp는 서명에 든 발신 Unix 초(엄격 10진)를 싣는 헤더다.
	HeaderInternalTimestamp = "X-Internal-Timestamp"
)

// emptyBodyDigest는 빈 body의 canonical-v1 bodyDigest다 — sha256(빈 바이트)의 고정 hex.
// GET처럼 body가 없는 요청도 이 값으로 서명 범위에 명시적으로 든다.
const emptyBodyDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// ErrNoInternalKey는 /internal 서명 키가 비어 있을 때 반환된다 — 키 없이 signer를 만들지
// 않는다(무서명 폴백 제거 · fail-closed).
var ErrNoInternalKey = errors.New("dispatch: /internal HMAC 키가 비어 있다 (GATEWAY_INTERNAL_HMAC_KEY는 .env에서 온다)")

// InternalSigner는 /internal 관리 표면 요청에 canonical-v1 HMAC-SHA256 서명을 붙인다.
// 키는 시크릿이며 값을 로그·오류에 노출하지 않는다.
type InternalSigner struct {
	key []byte
}

// NewInternalSigner는 raw 키 바이트로 signer를 만든다. 키가 비면 오류다(fail-closed).
func NewInternalSigner(key []byte) (*InternalSigner, error) {
	if len(key) == 0 {
		return nil, ErrNoInternalKey
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &InternalSigner{key: k}, nil
}

// internalBodyDigest는 raw 수신 바이트의 canonical-v1 bodyDigest를 만든다.
func internalBodyDigest(raw []byte) string {
	if len(raw) == 0 {
		return emptyBodyDigest
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// canonicalV1은 서명 대상 바이트열을 만든다(4필드 · 필드 사이만 "\n" · 끝 개행 없음).
// method는 대문자로 정규화한다. 게이트웨이 검증기가 반드시 같은 형태를 만들어야 한다.
func canonicalV1(method, path, bodyDigest, timestamp string) []byte {
	return []byte(strings.ToUpper(method) + "\n" + path + "\n" + bodyDigest + "\n" + timestamp)
}

// signCanonicalV1은 canonical 바이트열에 대한 HMAC-SHA256을 소문자 hex로 계산한다.
func (s *InternalSigner) signCanonicalV1(canonical []byte) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

// headersFor는 요청에 붙일 서명·타임스탬프 헤더 값을 만든다. ts는 발신 Unix 초다.
// path는 요청 경로(쿼리 제외), body는 raw 요청 바이트(GET은 nil)다.
func (s *InternalSigner) headersFor(method, path string, body []byte, ts int64) (signature, timestamp string) {
	timestamp = strconv.FormatInt(ts, 10)
	canonical := canonicalV1(method, path, internalBodyDigest(body), timestamp)
	return s.signCanonicalV1(canonical), timestamp
}
