// manifest 검증의 단위 테스트 — DO-18 ⑵ digest 고정 형식(sha256: + 64자 소문자 hex)을
// 직접 검증한다. 태그·오타·대문자 hex가 digest로 위장해 실행 대상 고정이 무너지는 것을
// 막는다.
package deploy

import (
	"encoding/json"
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

// TestTargetOfAgreesWithFullDecode는 결박 대조가 쓰는 부분 디코더(TargetOf)와 실행 경로가
// 쓰는 전체 디코더(ParseManifest)가 **같은 body에 대해 같은 target을 본다**는 계약을 못박는다.
//
// 이 계약이 깨지면 결박이 통째로 우회된다: 진입 층이 body를 "core"로 읽고 허용 대상과
// 맞다고 통과시킨 뒤, 실행 경로가 같은 body를 "gateway"로 읽으면 허용되지 않은 대상이
// 배포된다. 두 디코더가 갈릴 만한 입력(중복 키·키 대소문자·여분 필드·타입 위반)을 함께 민다.
func TestTargetOfAgreesWithFullDecode(t *testing.T) {
	const digest = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bodies := []struct {
		name string
		body string
	}{
		{"정상", `{"target":"core","commitSha":"c1","imageDigest":"` + digest + `","composeRevision":"r","configVersion":"v","requestId":"r1"}`},
		{"중복 키(뒤가 이긴다)", `{"target":"core","target":"gateway"}`},
		{"중복 키(앞이 core)", `{"target":"gateway","target":"core"}`},
		{"키 대소문자(JSON 디코더는 대소문자 무시 매칭)", `{"TARGET":"ledger"}`},
		{"키 대소문자 혼합", `{"TaRgEt":"settlement"}`},
		{"여분 필드", `{"unknown":1,"target":"core","nested":{"target":"gateway"}}`},
		{"target 부재", `{"commitSha":"c1"}`},
		{"target 빈 값", `{"target":""}`},
		{"닫힌 집합 밖", `{"target":"oracle-edge"}`},
		{"공백 포함", `{"target":" core "}`},
		{"대문자 값", `{"target":"CORE"}`},
		{"배열 최상위", `["core"]`},
		{"JSON 아님", `not json at all`},
		{"빈 body", ``},
		{"target이 수치", `{"target":123}`},
	}

	for _, tc := range bodies {
		t.Run(tc.name, func(t *testing.T) {
			// 전체 디코드 — 실행 경로(ParseManifest)가 target을 읽는 바로 그 방식이다.
			var full Manifest
			fullErr := json.Unmarshal([]byte(tc.body), &full)

			got, err := TargetOf([]byte(tc.body))

			if (fullErr != nil) != (err != nil) {
				t.Fatalf("오류 여부가 갈렸다: TargetOf err=%v · 전체 디코드 err=%v", err, fullErr)
			}
			if err != nil {
				return // 둘 다 파싱 불가 — target을 비교할 것이 없다
			}
			if got != full.Target {
				t.Fatalf("두 디코더가 다른 target을 봤다: TargetOf=%q · 전체 디코드=%q (결박 우회 경로)", got, full.Target)
			}
			// 전체 디코드가 성공하고 대상이 유효하면 ParseManifest도 같은 값을 내야 한다.
			if full.Target.Valid() {
				m, perr := ParseManifest([]byte(tc.body))
				if perr != nil {
					t.Fatalf("유효 대상인데 ParseManifest가 실패했다: %v", perr)
				}
				if m.Target != got {
					t.Fatalf("ParseManifest=%q · TargetOf=%q", m.Target, got)
				}
			}
		})
	}
}
