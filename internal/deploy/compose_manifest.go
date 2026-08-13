package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jun-bank/infra/internal/compose"
)

// manifest의 **동봉 2분법**과 표현 계약(infra#19 · 설계 rev.2 R5).
//
// 왜 별도 파서인가: 기존 ParseManifest는 표준 json.Unmarshal이라 미지 필드를 조용히 무시하고
// 중복 키는 뒤엣것이 이긴다. 동봉 이전에는 그 관용이 무해했지만(서명이 body 전체를 덮으므로
// 무시된 필드가 실행에 닿지 않았다), 동봉 이후에는 **무시된 필드가 곧 무시된 결박**이다 —
// `composeContent`를 대문자 변형이나 중복 키로 흘려 넣고 agent가 어느 쪽을 읽는지 갈리면
// 서명된 내용과 실행되는 내용이 갈린다. 그래서 실행 직전 검증은 토큰 수준의 엄격 파서가 맡는다.
//
// ParseManifest(관용)와 ParseManifestStrict(엄격)의 역할 분담:
//   - ParseManifest — 락 **이전**의 target 추출 전용(모드 판정·repo↔target 결박 대조). 이
//     자리의 계약은 "진입 층의 부분 디코더(TargetOf)와 같은 target을 본다"이며 그대로 둔다.
//   - ParseManifestStrict — 락 보유 중, 실행 직전. 여기서 통과한 Manifest만 dispatch로 간다.

var (
	// ErrManifestJSONStrict는 manifest JSON이 엄격 계약(미지 필드·중복 키·후행 데이터 없음)을
	// 어겼을 때다.
	ErrManifestJSONStrict = errors.New("deploy: manifest JSON이 엄격 계약을 어겼다(미지 필드·중복 키·후행 데이터)")
	// ErrManifestComposeMix는 동봉 필드가 부분 조합일 때다(둘 중 하나만·null·빈 문자열).
	ErrManifestComposeMix = errors.New("deploy: 동봉 필드 부분 조합 — composeContent·appService는 함께 있고 둘 다 비어 있지 않아야 한다")
	// ErrManifestComposeRevision은 동봉인데 composeRevision이 sha256:<64소문자hex>가 아닐 때다.
	ErrManifestComposeRevision = errors.New("deploy: 동봉 manifest의 composeRevision이 sha256:<64소문자hex> 정확 형식이 아니다")
	// ErrManifestComposeEncoding은 composeContent가 canonical base64 계약을 어겼을 때다.
	ErrManifestComposeEncoding = errors.New("deploy: composeContent가 canonical base64 계약을 어겼다")
	// ErrManifestComposeHash는 디코드된 원문의 sha256이 composeRevision과 다를 때다(CP-1 선대조).
	ErrManifestComposeHash = errors.New("deploy: 동봉 compose 내용의 sha256이 composeRevision과 불일치(CP-1 선대조 실패)")
	// ErrManifestComposeRequired는 동봉이 필수인데 legacy manifest가 온 것이다(R7 REQUIRE).
	ErrManifestComposeRequired = errors.New("deploy: 동봉 compose가 필수인데 manifest에 없다(다운그레이드 차단)")
)

// maxEncodedComposeBytes는 composeContent **인코딩 문자열**의 길이 상한이다(G-03 — 96KiB).
// 디코드 후 상한(64KiB)과 별개로 두는 이유: 디코드 전에 걸러야 거대 문자열을 메모리에 펼치는
// 것 자체를 막는다. CI가 지키는 manifest 32KiB 상한과도 별개다 — 저쪽은 발행 게이트이고
// 이쪽은 agent의 자기 방어라, 발행 게이트를 지나지 않은 입력에도 서야 한다.
const maxEncodedComposeBytes = 96 * 1024

// 이력·응답에 싣는 compose 경로 표기(G-11). 조용한 폴백을 금지하려면 "어느 경로로 배포됐나"가
// 요청마다 이력에 남아야 한다 — legacy 표기가 급증하는 것이 이관 순서 위반의 관측 신호다.
const (
	// ComposePathEmbedded는 서명에 동봉된 compose로 실행했음을 뜻한다.
	ComposePathEmbedded = "EMBEDDED_COMPOSE"
	// ComposePathLegacy는 호스트 compose 파일로 실행했음을 뜻한다(과도기 — 명시 opt-in).
	ComposePathLegacy = "LEGACY_COMPOSE_PATH"
)

// ComposeEmbedded는 이 manifest가 동봉 경로인지 보고한다. ParseManifestStrict를 통과한
// manifest에서만 의미가 있다 — 2분법이 거기서 강제되므로, 통과한 뒤에는 이 한 필드가
// 곧 경로 판정이다.
func (m Manifest) ComposeEmbedded() bool { return m.ComposeContent != "" }

// ComposePathCode는 이력 detail에 실을 경로 코드다(G-11).
func (m Manifest) ComposePathCode() string {
	if m.ComposeEmbedded() {
		return ComposePathEmbedded
	}
	return ComposePathLegacy
}

// ParseManifestStrict는 실행 직전(락 보유 중) manifest를 엄격하게 읽는다:
// ⑴ 최상위 JSON 객체 · 중복 키 없음(중첩 포함) · 후행 데이터 없음 ⑵ 미지 필드 없음
// ⑶ 동봉 2분법 ⑷ 동봉이면 composeRevision 형식 + base64 canonical + 디코드 상한 + UTF-8
// + sha256 선대조까지. 여기서 통과한 값만 dispatch로 간다.
//
// ⑷를 여기서 끝내는 이유: 이 실패들은 전부 **요청이 잘못된 것**이라 422로 닫혀야 하고
// (실행 계층 실패 502와 구별된다), 부작용이 생기기 한참 전에 판정할 수 있다.
func ParseManifestStrict(body []byte) (Manifest, error) {
	keys, err := strictTopLevelKeys(body)
	if err != nil {
		return Manifest{}, err
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var m Manifest
	if derr := dec.Decode(&m); derr != nil {
		// 미지 필드는 여기서 걸린다 — 구 agent가 조용히 무시하던 자리다(이관 ① 순서의 근거).
		return Manifest{}, fmt.Errorf("%w: %v", ErrManifestJSONStrict, derr)
	}
	if !m.Target.Valid() {
		return Manifest{}, ErrManifestTarget
	}

	// 2분법 — 키의 **존재**로 판정한다. 명시적 null·빈 문자열은 "있는데 비었다"이므로
	// 부분 조합으로 거절된다(둘 다 아예 없을 때만 legacy).
	hasContent, hasService := keys["composeContent"], keys["appService"]
	switch {
	case !hasContent && !hasService:
		return m, nil // legacy — composeRevision은 기존 placeholder 그대로 둔다
	case !hasContent || !hasService:
		return Manifest{}, fmt.Errorf("%w: composeContent=%v appService=%v", ErrManifestComposeMix, hasContent, hasService)
	}
	if m.ComposeContent == "" || m.AppService == "" {
		return Manifest{}, fmt.Errorf("%w: 값이 비어 있다(null·\"\" 포함)", ErrManifestComposeMix)
	}
	if _, _, cerr := m.EmbeddedCompose(); cerr != nil {
		return Manifest{}, cerr
	}
	return m, nil
}

// EmbeddedCompose는 동봉 내용을 canonical base64 계약에 따라 디코드하고 sha256 선대조까지
// 마친 **원문 바이트**와 그 hex revision을 준다(CP-1). 순수 함수이므로 검증 지점과 실행
// 지점이 각자 불러도 같은 값을 얻는다 — 바이트를 층 사이로 들고 다니지 않기 위한 선택이다.
//
// base64 계약(rev.2 R5)의 핵심은 **디코드→재인코딩 == 입력**이다. 이 한 줄이 개행·공백·
// 비패딩·non-strict 잔여 비트를 한꺼번에 닫는다: Go의 base64 디코더는 `\r`·`\n`을 조용히
// 건너뛰므로 디코드 성공만으로는 "같은 바이트"가 보장되지 않고, 표현이 여럿이면 CI가 계산한
// revision과 agent가 보는 바이트가 갈릴 수 있다.
func (m Manifest) EmbeddedCompose() ([]byte, string, error) {
	if m.ComposeContent == "" {
		return nil, "", ErrManifestComposeMix
	}
	revHex, ok := strings.CutPrefix(m.ComposeRevision, digestPrefix)
	if !ok || !validLowerHex(revHex) {
		return nil, "", fmt.Errorf("%w: %q", ErrManifestComposeRevision, m.ComposeRevision)
	}
	if len(m.ComposeContent) > maxEncodedComposeBytes {
		return nil, "", fmt.Errorf("%w: 인코딩 길이 %d > %d", ErrManifestComposeEncoding, len(m.ComposeContent), maxEncodedComposeBytes)
	}
	content, err := base64.StdEncoding.Strict().DecodeString(m.ComposeContent)
	if err != nil {
		return nil, "", fmt.Errorf("%w: 디코드 실패: %v", ErrManifestComposeEncoding, err)
	}
	if base64.StdEncoding.EncodeToString(content) != m.ComposeContent {
		return nil, "", fmt.Errorf("%w: 비정규 표현(재인코딩 불일치 — 개행·공백·패딩 변형)", ErrManifestComposeEncoding)
	}
	if len(content) > compose.MaxComposeBytes {
		return nil, "", fmt.Errorf("%w: 디코드 후 %d바이트 > %d", ErrManifestComposeEncoding, len(content), compose.MaxComposeBytes)
	}
	if terr := compose.ValidUTF8Text(content); terr != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrManifestComposeEncoding, terr)
	}
	// CP-1 선대조 — 인증된 in-memory 바이트에서 바로 잰다(파일을 거치지 않는다).
	sum := sha256.Sum256(content)
	if got := hex.EncodeToString(sum[:]); got != revHex {
		return nil, "", fmt.Errorf("%w: 기대=%s 실제=%s", ErrManifestComposeHash, revHex, got)
	}
	return content, revHex, nil
}

// validLowerHex는 소문자 hex 64자인지 본다(digest와 같은 canonical 규칙 — 대문자는
// canonical이 아니라 재현되지 않을 수 있다).
func validLowerHex(s string) bool {
	if len(s) != digestHexLen {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// strictTopLevelKeys는 body를 토큰 수준으로 훑어 ⑴ 중복 키(중첩 포함) ⑵ 후행 데이터를
// 거절하고 최상위 키 집합을 준다. encoding/json의 구조체 디코드로는 이 둘을 볼 수 없다 —
// 중복 키는 뒤엣것이 조용히 이기고, 첫 값 뒤의 쓰레기는 Unmarshal이 아니라 Decoder만 본다.
//
// 최상위 키 집합이 필요한 이유는 2분법이 "값이 무엇인가"가 아니라 "키가 있는가"로 갈리기
// 때문이다: `"composeContent": null`은 디코드하면 빈 문자열이라 부재와 구별되지 않는데,
// 그 둘을 같게 다루면 부분 조합이 legacy로 접혀 결박이 조용히 사라진다.
func strictTopLevelKeys(body []byte) (map[string]bool, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, ErrManifestMalformed
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, ErrManifestMalformed
	}
	keys := map[string]bool{}
	for dec.More() {
		kt, kerr := dec.Token()
		if kerr != nil {
			return nil, ErrManifestMalformed
		}
		key, ok := kt.(string)
		if !ok {
			return nil, ErrManifestMalformed
		}
		if keys[key] {
			return nil, fmt.Errorf("%w: 최상위 중복 키 %q", ErrManifestJSONStrict, key)
		}
		keys[key] = true
		if verr := skipJSONValue(dec); verr != nil {
			return nil, verr
		}
	}
	if _, cerr := dec.Token(); cerr != nil { // 닫는 '}'
		return nil, ErrManifestMalformed
	}
	// 첫 값 뒤에 무엇이든 남아 있으면 거절이다 — 두 번째 JSON 문서를 이어붙여 파서마다
	// 다른 것을 읽게 하는 우회를 닫는다.
	if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
		return nil, fmt.Errorf("%w: 첫 JSON 값 뒤에 데이터가 남아 있다", ErrManifestJSONStrict)
	}
	return keys, nil
}

// skipJSONValue는 값 하나를 소비하며, 그 안의 객체에서도 중복 키를 거절한다(중첩 포함).
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return ErrManifestMalformed
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil // 스칼라
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, kerr := dec.Token()
			if kerr != nil {
				return ErrManifestMalformed
			}
			key, kok := kt.(string)
			if !kok {
				return ErrManifestMalformed
			}
			if seen[key] {
				return fmt.Errorf("%w: 중첩 객체의 중복 키 %q", ErrManifestJSONStrict, key)
			}
			seen[key] = true
			if verr := skipJSONValue(dec); verr != nil {
				return verr
			}
		}
	case '[':
		for dec.More() {
			if verr := skipJSONValue(dec); verr != nil {
				return verr
			}
		}
	}
	if _, cerr := dec.Token(); cerr != nil { // 닫는 '}' 또는 ']'
		return ErrManifestMalformed
	}
	return nil
}
