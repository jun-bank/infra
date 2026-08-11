// manifest 검증의 단위 테스트 — DO-18 ⑵ digest 고정 형식(sha256: + 64자 소문자 hex)을
// 직접 검증한다. 태그·오타·대문자 hex가 digest로 위장해 실행 대상 고정이 무너지는 것을
// 막는다.
package deploy

import (
	"strings"
	"testing"
)

// validSHA256Digest는 소문자 hex만 canonical로 인정한다(OCI/Docker). 대문자 A-F는
// canonical이 아니므로 거부한다 — pull 참조로 재현되지 않을 수 있다.
func TestValidSHA256DigestLowercaseOnly(t *testing.T) {
	good := []string{
		"sha256:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("0", 64),
		"sha256:" + strings.Repeat("f", 64),
		"sha256:" + strings.Repeat("9", 64),
	}
	for _, d := range good {
		if !validSHA256Digest(d) {
			t.Errorf("소문자 canonical digest가 거부됨: %q", d)
		}
	}

	bad := []string{
		"sha256:" + strings.Repeat("A", 64),         // 대문자 — canonical 아님
		"sha256:" + strings.Repeat("a", 63) + "F",   // 끝자리 대문자
		"sha256:DEADBEEF" + strings.Repeat("a", 56), // 대문자 섞임
		"sha256:latest",
		"sha256:abc",
		"sha256:" + strings.Repeat("g", 64), // 비hex
		"v1.2.3",
		"latest",
		"",
	}
	for _, d := range bad {
		if validSHA256Digest(d) {
			t.Errorf("비canonical/위조 digest가 통과됨(거부되어야 한다): %q", d)
		}
	}
}
