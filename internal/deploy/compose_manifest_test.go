package deploy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// manifest 동봉 2분법과 표현 계약(infra#19 R5). 여기서 잡으려는 것은 **조용히 무시되는
// 결박**이다: 미지 필드·중복 키·비정규 base64는 전부 "agent가 무엇을 읽었는지"와 "CI가
// 무엇을 서명했는지"를 갈라놓을 수 있고, 그 갈림은 배포가 성공한 것처럼 보이는 채로 일어난다.

// manifestCompose는 길이가 3의 배수가 **아니도록** 주석 한 줄을 달고 있다 — base64 패딩이
// 실제로 붙어야 "패딩 제거" 위조를 시험할 수 있다(길이가 3의 배수면 패딩이 없어 그 케이스가
// 아무것도 바꾸지 않는 무음 통과 테스트가 된다).
const manifestCompose = "services:\n  app:\n    image: ${DEPLOY_IMAGE_REF}\n# canon\n"

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// bodyOf는 manifest JSON body를 만든다(extra는 그대로 이어붙인다 — 위조 실험용).
func bodyOf(extra string) []byte {
	base := `{"target":"core","commitSha":"c1","imageDigest":"` + validDigest + `",` +
		`"composeRevision":"sha256:` + sha256Hex(manifestCompose) + `",` +
		`"configVersion":"v1","requestId":"req-1"`
	if extra != "" {
		base += "," + extra
	}
	return []byte(base + "}")
}

func embeddedBody() []byte {
	return bodyOf(`"composeContent":"` + b64(manifestCompose) + `","appService":"app"`)
}

// 정상 동봉 body는 통과하고, 디코드된 바이트가 원문 그대로여야 한다.
func TestParseManifestStrictAcceptsEmbedded(t *testing.T) {
	m, err := ParseManifestStrict(embeddedBody())
	if err != nil {
		t.Fatalf("정상 동봉 manifest가 거절됐다: %v", err)
	}
	if !m.ComposeEmbedded() || m.ComposePathCode() != ComposePathEmbedded {
		t.Fatalf("경로 판정=%q", m.ComposePathCode())
	}
	content, rev, cerr := m.EmbeddedCompose()
	if cerr != nil {
		t.Fatal(cerr)
	}
	if string(content) != manifestCompose {
		t.Fatalf("디코드된 원문이 다르다: %q", content)
	}
	if rev != sha256Hex(manifestCompose) {
		t.Fatalf("revision=%q", rev)
	}
}

// legacy(둘 다 부재)는 그대로 통과하고 경로 표기가 갈린다 — 이 표기가 이관 순서 위반의
// 유일한 관측 신호다(G-11).
func TestParseManifestStrictAcceptsLegacy(t *testing.T) {
	m, err := ParseManifestStrict(bodyOf(""))
	if err != nil {
		t.Fatalf("legacy manifest가 거절됐다: %v", err)
	}
	if m.ComposeEmbedded() || m.ComposePathCode() != ComposePathLegacy {
		t.Fatalf("경로 판정=%q", m.ComposePathCode())
	}
}

// 2분법 — 부분 조합·null·빈 문자열은 전부 거절이다. 판정이 **키의 존재**로 갈리는 것이
// 핵심이다: null은 디코드하면 빈 문자열이라 부재와 구별되지 않고, 같게 다루면 부분 조합이
// legacy로 접혀 결박이 조용히 사라진다.
func TestComposeDichotomy(t *testing.T) {
	cases := []struct {
		name  string
		extra string
	}{
		{"content만", `"composeContent":"` + b64(manifestCompose) + `"`},
		{"appService만", `"appService":"app"`},
		{"content null", `"composeContent":null,"appService":"app"`},
		{"appService null", `"composeContent":"` + b64(manifestCompose) + `","appService":null`},
		{"둘 다 null", `"composeContent":null,"appService":null`},
		{"content 빈 문자열", `"composeContent":"","appService":"app"`},
		{"appService 빈 문자열", `"composeContent":"` + b64(manifestCompose) + `","appService":""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseManifestStrict(bodyOf(tc.extra))
			if !errors.Is(err, ErrManifestComposeMix) {
				t.Fatalf("부분 조합이 거절되지 않았다(또는 다른 이유로 거절): %v", err)
			}
		})
	}
}

// U-33(blind 핵심 방어선): 비정규 base64. 디코드는 성공하지만 **재인코딩이 입력과 다르다** —
// Go의 디코더가 개행을 건너뛰기 때문에 디코드 성공만으로는 "같은 바이트"가 보장되지 않고,
// 표현이 여럿이면 CI가 계산한 revision과 agent가 보는 바이트가 갈릴 여지가 생긴다.
func TestBase64CanonicalContract(t *testing.T) {
	enc := b64(manifestCompose)
	if !strings.HasSuffix(enc, "=") {
		t.Fatalf("픽스처가 패딩을 만들지 않는다 — \"패딩 제거\" 케이스가 무음 통과한다: %q", enc)
	}
	cases := []struct{ name, content string }{
		{"개행 삽입", enc[:8] + "\\n" + enc[8:]},
		{"공백 삽입", enc[:8] + " " + enc[8:]},
		{"패딩 제거", strings.TrimRight(enc, "=")},
		{"URL-safe 알파벳", base64.URLEncoding.EncodeToString([]byte("services:\n  app:\n    image: ${DEPLOY_IMAGE_REF}\n??>>"))},
		{"base64 아님", "not-base64!!"},
		{"빈 문자열 아닌 공백", "   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := bodyOf(`"composeContent":"` + tc.content + `","appService":"app"`)
			_, err := ParseManifestStrict(body)
			if err == nil {
				t.Fatal("비정규 base64가 통과했다")
			}
			if !errors.Is(err, ErrManifestComposeEncoding) && !errors.Is(err, ErrManifestComposeHash) &&
				!errors.Is(err, ErrManifestJSONStrict) && !errors.Is(err, ErrManifestMalformed) {
				t.Fatalf("거절 분류가 다르다: %v", err)
			}
		})
	}

	// 정상 표현은 통과한다(검증이 정당한 입력을 막지 않는다).
	if _, err := ParseManifestStrict(embeddedBody()); err != nil {
		t.Fatalf("정규 base64가 거절됐다: %v", err)
	}
}

// 디코드된 원문이 텍스트로 성립하지 않으면 거절이다(NUL·BOM·비UTF-8).
func TestEmbeddedContentMustBeCleanText(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"NUL 포함", "services:\x00\n"},
		{"BOM 시작", "\xEF\xBB\xBFservices:\n"},
		{"비UTF-8", "services: \xff\xfe\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"target":"core","commitSha":"c1","imageDigest":"` + validDigest + `",` +
				`"composeRevision":"sha256:` + sha256Hex(tc.raw) + `",` +
				`"configVersion":"v1","requestId":"req-1",` +
				`"composeContent":"` + b64(tc.raw) + `","appService":"app"}`)
			if _, err := ParseManifestStrict(body); !errors.Is(err, ErrManifestComposeEncoding) {
				t.Fatalf("거절 분류가 다르다: %v", err)
			}
		})
	}
}

// CP-1 선대조 — 내용과 revision이 어긋나면 거절이다(위조 시나리오의 본진).
func TestComposeRevisionMustMatchContent(t *testing.T) {
	forged := "services:\n  app:\n    image: ${DEPLOY_IMAGE_REF}\n    privileged: true\n"
	body := bodyOf(`"composeContent":"` + b64(forged) + `","appService":"app"`) // revision은 원본 것
	if _, err := ParseManifestStrict(body); !errors.Is(err, ErrManifestComposeHash) {
		t.Fatalf("내용 위조가 해시 대조에 걸리지 않았다: %v", err)
	}
}

// revision 형식 — sha256: + 64자 **소문자** hex 정확일치.
func TestComposeRevisionFormat(t *testing.T) {
	for _, tc := range []struct{ name, rev string }{
		{"대문자 hex", "sha256:" + strings.ToUpper(sha256Hex(manifestCompose))},
		{"접두사 없음", sha256Hex(manifestCompose)},
		{"길이 부족", "sha256:abc"},
		{"placeholder", "rev1"},
		{"빈 값", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"target":"core","commitSha":"c1","imageDigest":"` + validDigest + `",` +
				`"composeRevision":"` + tc.rev + `",` +
				`"configVersion":"v1","requestId":"req-1",` +
				`"composeContent":"` + b64(manifestCompose) + `","appService":"app"}`)
			if _, err := ParseManifestStrict(body); !errors.Is(err, ErrManifestComposeRevision) {
				t.Fatalf("거절 분류가 다르다: %v", err)
			}
		})
	}
}

// 엄격 JSON — 미지 필드·중복 키(중첩 포함)·후행 데이터는 전부 거절이다. 관용 파서에서는
// 이것들이 조용히 무시되거나 뒤엣것이 이기므로, 서명된 것과 실행되는 것이 갈릴 수 있다.
func TestStrictJSONContract(t *testing.T) {
	dupTop := `{"target":"core","target":"gateway","commitSha":"c1","imageDigest":"` + validDigest +
		`","composeRevision":"sha256:` + sha256Hex(manifestCompose) + `","configVersion":"v1","requestId":"req-1"}`
	cases := []struct{ name, body string }{
		{"미지 필드", string(bodyOf(`"extraField":"x"`))},
		{"중첩 미지 필드", string(bodyOf(`"nested":{"a":1}`))},
		{"최상위 중복 키", dupTop},
		{"동봉 필드 중복 키", string(bodyOf(`"composeContent":"` + b64(manifestCompose) + `","composeContent":"` + b64("services: {}") + `","appService":"app"`))},
		{"후행 데이터", string(bodyOf("")) + `{"target":"gateway"}`},
		{"후행 쓰레기", string(bodyOf("")) + "  garbage"},
		{"최상위 배열", `["core"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseManifestStrict([]byte(tc.body))
			if err == nil {
				t.Fatal("엄격 계약 위반이 통과했다")
			}
			if !errors.Is(err, ErrManifestJSONStrict) && !errors.Is(err, ErrManifestMalformed) {
				t.Fatalf("거절 분류가 다르다: %v", err)
			}
		})
	}
}

// 인코딩 길이 상한은 **디코드 전에** 본다(G-03) — 디코드 후 상한만 있으면 거대 문자열을
// 메모리에 펼치는 것 자체를 막지 못한다.
func TestEncodedLengthCapBeforeDecode(t *testing.T) {
	huge := strings.Repeat("A", maxEncodedComposeBytes+4)
	body := bodyOf(`"composeContent":"` + huge + `","appService":"app"`)
	if _, err := ParseManifestStrict(body); !errors.Is(err, ErrManifestComposeEncoding) {
		t.Fatalf("거절 분류가 다르다: %v", err)
	}
}

// 관용 파서(ParseManifest)는 락 이전의 target 추출 전용으로 그대로 남는다 — 이 분업이
// 깨지면 진입 층의 결박 대조(TargetOf와의 일치)가 함께 흔들린다.
func TestLenientParserStillLenientForTargetExtraction(t *testing.T) {
	m, err := ParseManifest(bodyOf(`"extraField":"x"`))
	if err != nil || m.Target != TargetCore {
		t.Fatalf("관용 파서가 미지 필드에서 실패했다(락 이전 target 추출 계약): m=%+v err=%v", m, err)
	}
}
