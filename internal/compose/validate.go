package compose

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	// yaml.v3는 이 결박의 **유일한 신규 직접 의존**이다. 근거: 동봉 compose의 구조를
	// 판정하려면 compose가 보는 것과 같은 구조를 봐야 하고(B2'), 정규식·문자열 스캔으로
	// 대신하면 앵커·병합 키·대체 표기(맵형 ports/volumes)가 전부 fail-open 지뢰가 된다.
	// typed struct로 디코드하지 않고 yaml.Node를 직접 순회하는 이유도 같다 — 라이브러리
	// 기본값·관용 변환에 판정을 위임하면 "검증기가 본 구조 ≠ compose가 실행할 구조"가 된다.
	"gopkg.in/yaml.v3"
)

// 상한 — 전부 선언값이며 근거는 설계 rev.2/2.2다(파서 방어 · DoS 차단).
const (
	// MaxComposeBytes는 디코드 후 원문의 크기 상한이다(64KiB).
	MaxComposeBytes = 64 * 1024
	// maxNodes는 YAML 노드 수 상한이다(G-16 선언값).
	maxNodes = 1000
	// maxDepth는 중첩 깊이 상한이다(G-16 선언값). 문서 노드를 깊이 0으로 센다.
	maxDepth = 10
	// containerPort는 배포 대상 서비스의 컨테이너 포트다 — 설계 rev.2 R3에서 고정값으로
	// 못박혔다(ports는 `${DEPLOY_HOST_PORT}:8080` 정확일치 1항목뿐). healthcheck의 프로브
	// 포트도 이 값과 일치해야 한다(G-06) — 서로 다른 포트를 보면 헬스가 엉뚱한 프로세스를
	// 재는 경로가 열린다. ⚠️ 컨테이너 포트가 다른 서비스가 생기면 재설계 항목이다.
	containerPort = 8080
	// minDurationSec·maxDurationSec는 healthcheck duration의 허용 범위다(G-07 선언값).
	minDurationSec = 1
	maxDurationSec = 300
)

// HostPortVar는 compose가 호스트 포트를 읽는 **유일한** 변수명이다(닫힌 신뢰 주입 2종 중 하나).
const HostPortVar = "DEPLOY_HOST_PORT"

// VolumeRule은 등재된 볼륨 **정확 튜플**이다(프리픽스가 아니다 — 프리픽스 허용은 하위
// 경로 전체를 여는 것과 같다). env DEPLOY_COMPOSE_VOLUME_ALLOW의 `target:src:dst:mode` 한 항.
type VolumeRule struct {
	Src  string // 호스트 경로(절대·Clean)
	Dst  string // 컨테이너 경로(절대·Clean)
	Mode string // ro|rw
}

func (r VolumeRule) String() string { return r.Src + ":" + r.Dst + ":" + r.Mode }

// Policy는 이 배포 대상에 적용할 닫힌 목록이다. 전부 **호스트 배선**에서 오며 요청 입력이
// 아니다 — 동봉된 compose가 스스로 자기 허용 범위를 넓힐 수 있으면 allowlist가 아니다.
type Policy struct {
	// AppService는 이 배포의 대상 서비스명이다(manifest.appService ∧ 호스트 env
	// DEPLOY_APP_SERVICE와 이미 일치가 확인된 값 — 여기서 compose 정의와 3자를 닫는다).
	AppService string
	// ImageEnvVar는 image가 참조해야 하는 유일한 변수명이다(예: DEPLOY_IMAGE_REF).
	ImageEnvVar string
	// EnvAllow는 이 target의 등재 environment 키다(pass-through 목록 — 값은 호스트가 소유).
	EnvAllow []string
	// VolumeAllow는 이 target의 등재 볼륨 정확 튜플이다.
	VolumeAllow []VolumeRule
	// EvalSymlinks는 볼륨 호스트 경로의 심볼릭 링크 해소기다(테스트 주입용 — 비면
	// filepath.EvalSymlinks). 해소 결과가 선언 경로와 다르면 거절한다(경로 탈출 차단).
	EvalSymlinks func(string) (string, error)
}

// Spec은 검증을 통과한 compose가 **실행에 요구하는 것**이다. 실행 층은 이 값만 보고
// subprocess env를 조립한다 — compose 파일을 다시 읽어 해석하지 않는다(정본 하나).
type Spec struct {
	// Service는 정의된 유일한 서비스명이다(= Policy.AppService).
	Service string
	// EnvKeys는 compose가 pass-through로 요구하는 등재 키들이다(선언 순서).
	EnvKeys []string
	// NeedsHostPort는 ports가 선언돼 DEPLOY_HOST_PORT 주입이 필요한지다.
	NeedsHostPort bool
}

// 서비스에 허용되는 키의 닫힌 목록(rev.2 R1: `command` 제거 — 임의 실행 표면).
// 여기 없는 키는 전부 거절이다: privileged·cap_add·devices·network_mode·pid·deploy·
// build·user·entrypoint … 를 하나씩 금지 목록에 적지 않는 이유가 이것이다(금지 목록은
// 새 compose 스펙이 나올 때마다 조용히 뒤처진다 — 닫힌 허용 목록은 그러지 않는다).
var allowedServiceKeys = map[string]bool{
	"image": true, "ports": true, "environment": true, "restart": true,
	"healthcheck": true, "extra_hosts": true, "volumes": true,
}

// restart의 닫힌 값 목록(rev.2: always 제외 — 값 자체는 저위험이나 닫힌 목록 원칙).
var allowedRestart = map[string]bool{"no": true, "unless-stopped": true, "on-failure": true}

// healthcheck의 닫힌 하위 키 목록.
var allowedHealthcheckKeys = map[string]bool{
	"test": true, "interval": true, "timeout": true, "retries": true, "start_period": true,
}

// extraHostEntry는 extra_hosts에 허용되는 유일한 항목이다(정확일치).
const extraHostEntry = "host.docker.internal:host-gateway"

// 허용 태그 — 이 다섯 밖(!!null·!!float·!!timestamp·!!binary·커스텀 !foo)은 전부 거절한다.
var allowedTags = map[string]bool{
	"!!map": true, "!!seq": true, "!!str": true, "!!int": true, "!!bool": true,
}

// healthcheckTest는 허용되는 유일한 CMD-SHELL 문자열 형식이다(rev.2.1 C3 — 자유 문자열
// CMD-SHELL은 임의 셸 실행 표면이므로 포트 하나만 가변인 고정 패턴으로 닫는다).
var healthcheckTest = regexp.MustCompile(`^wget -qO- http://127\.0\.0\.1:([0-9]{1,5})/actuator/health \|\| exit 1$`)

// durationPattern은 healthcheck duration의 허용 형식이다(`^\d+(s|m)$`).
var durationPattern = regexp.MustCompile(`^([0-9]{1,6})(s|m)$`)

// Validate는 동봉 compose 원문(디코드된 바이트)이 CP-7 닫힌 allowlist를 통과하는지 본다.
// **부작용 0**이다 — 파일을 쓰지 않으며, 유일한 파일시스템 접촉은 볼륨 호스트 경로의
// 심볼릭 링크 해소(읽기 전용)뿐이다.
//
// 순서: 크기 → YAML 파싱(문서 1개) → 구조 순회(앵커·병합·중복·태그·비문자열 키·깊이·노드 수)
// → `$` 전면 금지 스캔(허용 2형식만 면제) → 닫힌 스키마(최상위·서비스·필드별).
//
// `$` 스캔을 **필드 검증과 따로, 그 앞에** 도는 것이 요점이다: 필드별 검증에 섞으면 새 필드가
// 늘 때마다 보간 차단을 다시 짜야 하고, 무엇보다 한 필드의 허용 목록이 넓어지는 순간 그 자리에서
// 보간이 조용히 열린다. 전역 스캔 + 면제 2개는 필드가 늘어도 기본이 "금지"로 남는다.
func Validate(content []byte, p Policy) (Spec, error) {
	if len(content) == 0 {
		return Spec{}, errf(CodeSize, "동봉 compose가 비어 있다")
	}
	if len(content) > MaxComposeBytes {
		return Spec{}, errf(CodeSize, "동봉 compose가 상한을 넘는다: %d바이트 > %d", len(content), MaxComposeBytes)
	}

	dec := yaml.NewDecoder(bytes.NewReader(content))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return Spec{}, errf(CodeYAMLParse, "동봉 compose에 YAML 문서가 없다")
		}
		return Spec{}, errf(CodeYAMLParse, "YAML 파싱 실패: %v", err)
	}
	// 문서는 정확히 1개다 — 2번째 문서가 있으면 "검증한 문서"와 "compose가 읽는 문서"가
	// 갈릴 수 있다(멀티독 우회).
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Spec{}, errf(CodeMultiDoc, "YAML 문서가 2개 이상이다 — 정확히 1개여야 한다")
		}
		return Spec{}, errf(CodeYAMLParse, "두 번째 문서 확인 중 파싱 실패: %v", err)
	}

	v := &validator{policy: p}
	if err := v.walk(&doc, 0); err != nil {
		return Spec{}, err
	}
	if len(doc.Content) != 1 {
		return Spec{}, errf(CodeYAMLParse, "YAML 문서 루트가 정확히 1개가 아니다: %d", len(doc.Content))
	}
	// 보간 차단은 **필드 검증보다 먼저** 선다. 순서를 뒤집으면 `restart: "$X"`가 restart
	// 닫힌 목록에, `${EVIL}`이 environment 등재 목록에 먼저 걸려 — 거절은 되지만 **보간
	// 차단이 잡은 것이 아니게** 된다. 그러면 어느 날 한 필드의 목록이 넓어지는 순간
	// 그 자리에서 보간이 조용히 열린다. 전역 금지가 1차 방어선임을 순서로 못박는다.
	if err := v.checkNoInterpolation(); err != nil {
		return Spec{}, err
	}
	return v.validateRoot(doc.Content[0])
}

// validator는 한 번의 검증에 걸친 상태다(순회 카운터·스칼라 목록).
type validator struct {
	policy  Policy
	nodes   int
	scalars []*yaml.Node
}

// walk는 구조 불변식을 노드 종류와 무관하게 먼저 강제한다(B2' — 검증기와 compose가 같은
// 구조를 본다). 여기서 걸리는 것들은 "필드 검증에 닿기도 전에" 판정을 흔드는 것들이다:
// 앵커·별칭(같은 노드를 다른 자리에 재사용) · 병합 키(다른 매핑의 키를 끌어옴) · 중복 키
// (파서마다 앞/뒤가 이긴다) · 낯선 태그(타입 강제 변환) · 비문자열 키.
func (v *validator) walk(n *yaml.Node, depth int) error {
	if n == nil {
		return nil
	}
	v.nodes++
	if v.nodes > maxNodes {
		return errf(CodeNodeLimit, "YAML 노드 수가 상한을 넘는다(>%d)", maxNodes)
	}
	if depth > maxDepth {
		return errf(CodeDepth, "YAML 중첩 깊이가 상한을 넘는다(>%d · line %d)", maxDepth, n.Line)
	}
	if n.Kind == yaml.AliasNode {
		return errf(CodeAnchor, "별칭(*%s) 참조는 허용되지 않는다(line %d)", n.Value, n.Line)
	}
	if n.Anchor != "" {
		return errf(CodeAnchor, "앵커(&%s) 정의는 허용되지 않는다(line %d)", n.Anchor, n.Line)
	}

	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if err := v.walk(c, depth+1); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		if n.Tag != "!!map" {
			return errf(CodeTag, "매핑에 허용되지 않는 태그가 붙었다: %s(line %d)", n.Tag, n.Line)
		}
		if len(n.Content)%2 != 0 {
			return errf(CodeYAMLParse, "매핑의 키/값 개수가 맞지 않는다(line %d)", n.Line)
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k, val := n.Content[i], n.Content[i+1]
			// 병합 키는 **미지 키로 뭉개지 않는다** — 다른 매핑을 끌어와 실효 구조를 바꾸는
			// 고유한 우회이므로 고유 코드로 닫는다(오분류 방지).
			if k.Kind == yaml.ScalarNode && (k.Value == "<<" || k.Tag == "!!merge") {
				return errf(CodeMergeKey, "병합 키 `<<`는 허용되지 않는다(line %d)", k.Line)
			}
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return errf(CodeNonStringKey, "매핑 키는 문자열이어야 한다(kind=%d tag=%s line %d)", k.Kind, k.Tag, k.Line)
			}
			// 키 비교는 **바이트 그대로**다 — 유니코드 정규화·대소문자 접기를 하지 않는다.
			// 정규화하면 변형 키가 정본 키로 접혀 "미지 키 거절"을 우회한다(변형 키는
			// 정규화되지 않은 채 미지 키로 걸리는 것이 옳다).
			if seen[k.Value] {
				return errf(CodeDupKey, "같은 매핑에 중복 키가 있다: %q(line %d)", k.Value, k.Line)
			}
			seen[k.Value] = true
			if err := v.walk(k, depth+1); err != nil {
				return err
			}
			if err := v.walk(val, depth+1); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return errf(CodeTag, "시퀀스에 허용되지 않는 태그가 붙었다: %s(line %d)", n.Tag, n.Line)
		}
		for _, c := range n.Content {
			if err := v.walk(c, depth+1); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if !allowedTags[n.Tag] {
			return errf(CodeTag, "허용되지 않는 태그다: %s(값 %q · line %d)", n.Tag, n.Value, n.Line)
		}
		v.scalars = append(v.scalars, n)
	default:
		return errf(CodeYAMLParse, "알 수 없는 YAML 노드 종류다(kind=%d line %d)", n.Kind, n.Line)
	}
	return nil
}

// checkNoInterpolation은 디코드된 **모든 스칼라(값과 키)** 에서 `$`를 금지한다(G-04 —
// 주석은 디코드 대상이 아니므로 대상 밖). 면제는 **완전일치 2형식**뿐이다:
//
//	${<imageEnvVar>}            — 닫힌 신뢰 주입 ⑴ 이미지 참조
//	${DEPLOY_HOST_PORT}:8080    — 닫힌 신뢰 주입 ⑵ 슬롯 호스트 포트
//
// 면제를 **값**으로 판정하고 노드 위치로 하지 않는 이유: 이 검사는 필드 검증보다 앞서므로
// 아직 어느 노드가 image인지 모른다. 값 기준으로 면제해도 안전한 것은, 이 두 값이 엉뚱한
// 자리(environment·restart·volumes·healthcheck)에 놓이면 그 필드의 닫힌 검증이 각각
// 거절하기 때문이다 — 어떤 필드도 임의 문자열을 받지 않는다.
//
// 디코드 **후** 값을 보는 것이 또 하나의 핵심이다: 원문 바이트 스캔은 `"\x24"` 같은 YAML
// 이스케이프를 놓치지만, 디코드 후 값은 compose가 실제로 볼 문자열 그대로다.
func (v *validator) checkNoInterpolation() error {
	allowedImage := "${" + v.policy.ImageEnvVar + "}"
	allowedPorts := fmt.Sprintf("${%s}:%d", HostPortVar, containerPort)
	for _, s := range v.scalars {
		if !strings.ContainsRune(s.Value, '$') {
			continue
		}
		if s.Value == allowedImage || s.Value == allowedPorts {
			continue
		}
		return errf(CodeInterpolation, "허용된 2형식(%q·%q) 밖에서 `$`가 등장했다: %q(line %d) — 보간 소스는 닫힌 주입값뿐이다", allowedImage, allowedPorts, s.Value, s.Line)
	}
	return nil
}

// validateRoot는 최상위부터 닫힌 스키마를 강제한다.
func (v *validator) validateRoot(root *yaml.Node) (Spec, error) {
	if root.Kind != yaml.MappingNode {
		return Spec{}, errf(CodeTopLevel, "최상위가 매핑이 아니다(line %d)", root.Line)
	}
	// 최상위는 services **단일 키**다(G-02) — version·networks·volumes·configs·secrets는
	// 물론 `x-` 확장 키도 거절한다. 확장 키는 compose가 해석하지 않는다고 알려져 있지만,
	// 앵커의 숙주로 쓰이는 자리라 허용하면 구조 검증의 표면이 늘어난다.
	if len(root.Content) != 2 || root.Content[0].Value != "services" {
		return Spec{}, errf(CodeTopLevel, "최상위는 `services` 단일 키여야 한다: %v", mapKeys(root))
	}
	services := root.Content[1]
	if services.Kind != yaml.MappingNode {
		return Spec{}, errf(CodeNodeKind, "services가 매핑이 아니다(line %d)", services.Line)
	}
	// 서비스는 **정확히 1개**다(rev.2 R1) — 사이드카를 허용하면 그 이미지가 digest 결박
	// 밖이 되고(사후조건이 증명하지 못한다) allowlist 표면·replica 문제가 함께 돌아온다.
	if len(services.Content) != 2 {
		return Spec{}, errf(CodeServiceCount, "서비스는 정확히 1개여야 한다: %d개 %v", len(services.Content)/2, mapKeys(services))
	}
	name := services.Content[0].Value
	// CP-3 3자 일치의 마지막 한 자리 — manifest.appService·호스트 env는 호출자가 이미 맞췄고,
	// 여기서 compose 정의가 그 이름을 실제로 정의하는지 닫는다.
	if name != v.policy.AppService {
		return Spec{}, errf(CodeServiceName, "정의된 서비스명이 appService와 다르다: compose=%q appService=%q(CP-3 3자 일치)", name, v.policy.AppService)
	}

	svc := services.Content[1]
	if svc.Kind != yaml.MappingNode {
		return Spec{}, errf(CodeNodeKind, "서비스 %q의 정의가 매핑이 아니다(line %d)", name, svc.Line)
	}

	spec := Spec{Service: name}
	fields := map[string]*yaml.Node{}
	for i := 0; i < len(svc.Content); i += 2 {
		key, val := svc.Content[i].Value, svc.Content[i+1]
		if !allowedServiceKeys[key] {
			return Spec{}, errf(CodeUnknownKey, "서비스 %q에 미지 키가 있다: %q(line %d) — 허용 키는 %v뿐이다", name, key, svc.Content[i].Line, sortedKeys(allowedServiceKeys))
		}
		fields[key] = val
	}

	// image는 필수다 — 없으면 무엇을 띄우는지가 서명 밖에서 정해진다.
	img, ok := fields["image"]
	if !ok {
		return Spec{}, errf(CodeImage, "서비스 %q에 image가 없다(digest 결박 불가)", name)
	}
	if err := v.validateImage(img); err != nil {
		return Spec{}, err
	}
	if n, ok := fields["ports"]; ok {
		if err := v.validatePorts(n); err != nil {
			return Spec{}, err
		}
		spec.NeedsHostPort = true
	}
	if n, ok := fields["environment"]; ok {
		keys, err := v.validateEnvironment(n)
		if err != nil {
			return Spec{}, err
		}
		spec.EnvKeys = keys
	}
	if n, ok := fields["restart"]; ok {
		if err := v.validateRestart(n); err != nil {
			return Spec{}, err
		}
	}
	if n, ok := fields["healthcheck"]; ok {
		if err := v.validateHealthcheck(n); err != nil {
			return Spec{}, err
		}
	}
	if n, ok := fields["extra_hosts"]; ok {
		if err := v.validateExtraHosts(n); err != nil {
			return Spec{}, err
		}
	}
	if n, ok := fields["volumes"]; ok {
		if err := v.validateVolumes(n); err != nil {
			return Spec{}, err
		}
	}
	return spec, nil
}

// validateImage는 image가 `${<imageEnvVar>}` **정확일치**인지 본다(CP-3 · 닫힌 주입 1종).
// 기본값 문법(`${X:-latest}`)이 통과하면 주입 실패 시 조용히 :latest가 뜬다 — 그것이
// 이 정확일치가 막는 것이다.
func (v *validator) validateImage(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return errf(CodeNodeKind, "image는 문자열이어야 한다(kind=%d tag=%s line %d)", n.Kind, n.Tag, n.Line)
	}
	want := "${" + v.policy.ImageEnvVar + "}"
	if n.Value != want {
		return errf(CodeImage, "image는 %q 정확일치여야 한다: %q(line %d)", want, n.Value, n.Line)
	}
	return nil
}

// validatePorts는 ports가 `${DEPLOY_HOST_PORT}:8080` 한 항목뿐인지 본다. 호스트 IP 바인딩
// 형식(`127.0.0.1:x:y`)·맵형(long syntax)·정수 축약은 전부 거절이다 — 노출 표면이 서명
// 밖에서 정해지지 않게 한다.
func (v *validator) validatePorts(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return errf(CodeNodeKind, "ports는 시퀀스여야 한다(맵형 long syntax 거절 · kind=%d line %d)", n.Kind, n.Line)
	}
	if len(n.Content) != 1 {
		return errf(CodePorts, "ports는 정확히 1항목이어야 한다: %d개(line %d)", len(n.Content), n.Line)
	}
	item := n.Content[0]
	if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
		return errf(CodeNodeKind, "ports 항목은 문자열이어야 한다(kind=%d tag=%s line %d)", item.Kind, item.Tag, item.Line)
	}
	want := fmt.Sprintf("${%s}:%d", HostPortVar, containerPort)
	if item.Value != want {
		return errf(CodePorts, "ports 항목은 %q 정확일치여야 한다: %q(line %d)", want, item.Value, item.Line)
	}
	return nil
}

// validateEnvironment는 pass-through **목록 형식만** 허용한다(rev.2.1 C2): `["KEY", …]`.
// 맵 형식·`K=V` 형식·값 포함은 거절이다 — 값의 소유는 호스트 .env이고(CP-5), compose에
// 리터럴 값이 실리면 시크릿이 서명 대상에 섞여 들어간다(CF-6).
func (v *validator) validateEnvironment(n *yaml.Node) ([]string, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, errf(CodeNodeKind, "environment는 시퀀스(pass-through 키 목록)여야 한다 — 맵 형식은 값 동봉 경로라 거절한다(kind=%d line %d)", n.Kind, n.Line)
	}
	allow := map[string]bool{}
	for _, k := range v.policy.EnvAllow {
		allow[k] = true
	}
	var keys []string
	seen := map[string]bool{}
	for _, item := range n.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return nil, errf(CodeNodeKind, "environment 항목은 문자열이어야 한다(kind=%d tag=%s line %d)", item.Kind, item.Tag, item.Line)
		}
		if strings.Contains(item.Value, "=") {
			return nil, errf(CodeEnvironment, "environment 항목에 값이 포함됐다(K=V 형식 거절): %q(line %d) — 값의 소유는 호스트 .env다(CP-5)", item.Value, item.Line)
		}
		if !allow[item.Value] {
			return nil, errf(CodeEnvironment, "environment 키가 이 대상의 등재 목록 밖이다: %q(line %d · 등재=%v)", item.Value, item.Line, v.policy.EnvAllow)
		}
		if seen[item.Value] {
			return nil, errf(CodeEnvironment, "environment 키가 중복됐다: %q(line %d)", item.Value, item.Line)
		}
		seen[item.Value] = true
		keys = append(keys, item.Value)
	}
	return keys, nil
}

// validateRestart는 restart를 닫힌 값 목록으로 제한한다. 문자열 노드만 받는다 —
// 따옴표 없는 `true`/`false`는 !!bool로 읽혀 여기서 노드 종류 위반이 된다(yaml.v3는
// YAML 1.2 core schema라 no/off/yes는 문자열로 남는다 — 실측 확인).
func (v *validator) validateRestart(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return errf(CodeNodeKind, "restart는 문자열이어야 한다(tag=%s line %d)", n.Tag, n.Line)
	}
	if !allowedRestart[n.Value] {
		return errf(CodeRestart, "restart 값이 닫힌 목록 밖이다: %q(허용=%v · line %d)", n.Value, sortedKeys(allowedRestart), n.Line)
	}
	return nil
}

// validateHealthcheck는 고정 패턴 하나만 허용한다(rev.2.1 C3). 자유 문자열 CMD-SHELL은
// 임의 셸 실행 표면이므로, 가변인 것은 포트 숫자뿐이고 그 포트마저 ports의 컨테이너
// 포트와 일치해야 한다(G-06 — 헬스가 엉뚱한 프로세스를 재는 것을 막는다).
func (v *validator) validateHealthcheck(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return errf(CodeNodeKind, "healthcheck는 매핑이어야 한다(kind=%d line %d)", n.Kind, n.Line)
	}
	fields := map[string]*yaml.Node{}
	for i := 0; i < len(n.Content); i += 2 {
		key, val := n.Content[i].Value, n.Content[i+1]
		if !allowedHealthcheckKeys[key] {
			return errf(CodeHealthcheck, "healthcheck에 미지 키가 있다: %q(허용=%v · line %d)", key, sortedKeys(allowedHealthcheckKeys), n.Content[i].Line)
		}
		fields[key] = val
	}
	test, ok := fields["test"]
	if !ok {
		return errf(CodeHealthcheck, "healthcheck에 test가 없다(line %d)", n.Line)
	}
	if test.Kind != yaml.SequenceNode {
		return errf(CodeNodeKind, "healthcheck.test는 시퀀스여야 한다(문자열 축약 형식 거절 · kind=%d line %d)", test.Kind, test.Line)
	}
	if len(test.Content) != 2 {
		return errf(CodeHealthcheck, "healthcheck.test는 정확히 2항목(CMD-SHELL + 고정 명령)이어야 한다: %d개(line %d)", len(test.Content), test.Line)
	}
	for _, item := range test.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return errf(CodeNodeKind, "healthcheck.test 항목은 문자열이어야 한다(kind=%d tag=%s line %d)", item.Kind, item.Tag, item.Line)
		}
	}
	if test.Content[0].Value != "CMD-SHELL" {
		return errf(CodeHealthcheck, "healthcheck.test[0]은 %q여야 한다: %q(line %d)", "CMD-SHELL", test.Content[0].Value, test.Content[0].Line)
	}
	m := healthcheckTest.FindStringSubmatch(test.Content[1].Value)
	if m == nil {
		return errf(CodeHealthcheck, "healthcheck.test[1]이 고정 패턴과 다르다(포트만 가변): %q(line %d)", test.Content[1].Value, test.Content[1].Line)
	}
	port, err := strconv.Atoi(m[1])
	if err != nil || port < 1 || port > 65535 {
		return errf(CodeHealthcheck, "healthcheck 프로브 포트가 1~65535 밖이다: %q", m[1])
	}
	if port != containerPort {
		return errf(CodeHealthcheck, "healthcheck 프로브 포트(%d)가 컨테이너 포트(%d)와 다르다 — 헬스가 다른 프로세스를 잰다(G-06)", port, containerPort)
	}
	for _, key := range []string{"interval", "timeout", "start_period"} {
		d, ok := fields[key]
		if !ok {
			continue
		}
		if err := validateDuration(key, d); err != nil {
			return err
		}
	}
	if r, ok := fields["retries"]; ok {
		if r.Kind != yaml.ScalarNode || r.Tag != "!!int" {
			return errf(CodeNodeKind, "healthcheck.retries는 정수여야 한다(tag=%s line %d)", r.Tag, r.Line)
		}
		nRet, err := strconv.Atoi(r.Value)
		if err != nil || nRet < 1 {
			return errf(CodeHealthcheck, "healthcheck.retries는 1 이상의 정수여야 한다: %q(line %d)", r.Value, r.Line)
		}
	}
	return nil
}

// validateDuration은 `^\d+(s|m)$` 형식과 1s~300s 범위를 함께 강제한다(G-07 선언값).
// 형식만 보면 `99999s`가 통과해 헬스 대기가 사실상 무한이 된다 — 범위가 그것을 닫는다.
func validateDuration(key string, n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return errf(CodeNodeKind, "healthcheck.%s는 문자열이어야 한다(tag=%s line %d)", key, n.Tag, n.Line)
	}
	m := durationPattern.FindStringSubmatch(n.Value)
	if m == nil {
		return errf(CodeHealthcheck, "healthcheck.%s는 `<정수>s` 또는 `<정수>m` 형식이어야 한다: %q(line %d)", key, n.Value, n.Line)
	}
	num, err := strconv.Atoi(m[1])
	if err != nil {
		return errf(CodeHealthcheck, "healthcheck.%s의 수치를 읽을 수 없다: %q", key, n.Value)
	}
	sec := num
	if m[2] == "m" {
		sec = num * 60
	}
	if sec < minDurationSec || sec > maxDurationSec {
		return errf(CodeHealthcheck, "healthcheck.%s는 %ds~%ds 범위여야 한다: %q(=%ds · line %d)", key, minDurationSec, maxDurationSec, n.Value, sec, n.Line)
	}
	return nil
}

// validateExtraHosts는 정확일치 1형식만 허용한다 — 임의 호스트명→IP 매핑은 배포 대상이
// 어디로 말을 거는지를 서명 밖에서 바꾸는 수단이다.
func (v *validator) validateExtraHosts(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return errf(CodeNodeKind, "extra_hosts는 시퀀스여야 한다(맵 형식 거절 · kind=%d line %d)", n.Kind, n.Line)
	}
	for _, item := range n.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return errf(CodeNodeKind, "extra_hosts 항목은 문자열이어야 한다(kind=%d tag=%s line %d)", item.Kind, item.Tag, item.Line)
		}
		if item.Value != extraHostEntry {
			return errf(CodeExtraHosts, "extra_hosts 항목은 %q 정확일치만 허용한다: %q(line %d)", extraHostEntry, item.Value, item.Line)
		}
	}
	return nil
}

// validateVolumes는 항목을 등재된 **정확 튜플**과 대조한다(rev.2 R4 — 프리픽스 아님).
// 세 겹으로 막는다: ⑴ 형식(절대경로·Clean·3칸·mode) ⑵ 등재 튜플 정확일치 ⑶ 심볼릭 링크
// 해소 후 재대조. ⑶이 없으면 등재 경로 자체가 다른 곳을 가리키도록 바꿔치기되는 순간
// allowlist가 통째로 무의미해진다(경로 문자열은 그대로인데 실제 대상이 바뀐다).
func (v *validator) validateVolumes(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return errf(CodeNodeKind, "volumes는 시퀀스(짧은 문자열 표기)여야 한다 — 맵형 long syntax는 거절한다(kind=%d line %d)", n.Kind, n.Line)
	}
	eval := v.policy.EvalSymlinks
	if eval == nil {
		eval = filepath.EvalSymlinks
	}
	allow := map[string]bool{}
	for _, r := range v.policy.VolumeAllow {
		allow[VolumeRule{Src: filepath.Clean(r.Src), Dst: filepath.Clean(r.Dst), Mode: r.Mode}.String()] = true
	}
	for _, item := range n.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return errf(CodeNodeKind, "volumes 항목은 문자열이어야 한다(kind=%d tag=%s line %d)", item.Kind, item.Tag, item.Line)
		}
		parts := strings.Split(item.Value, ":")
		if len(parts) != 3 {
			return errf(CodeVolume, "volumes 항목은 `<host>:<container>:<ro|rw>` 정확히 3칸이어야 한다(named volume·mode 생략 거절): %q(line %d)", item.Value, item.Line)
		}
		src, dst, mode := parts[0], parts[1], parts[2]
		if mode != "ro" && mode != "rw" {
			return errf(CodeVolume, "volumes mode는 ro|rw여야 한다: %q(line %d)", mode, item.Line)
		}
		for _, p := range []struct{ name, val string }{{"host", src}, {"container", dst}} {
			if !filepath.IsAbs(p.val) {
				return errf(CodeVolume, "volumes %s 경로는 절대경로여야 한다: %q(line %d)", p.name, p.val, item.Line)
			}
			if strings.Contains(p.val, "..") {
				return errf(CodeVolume, "volumes %s 경로에 `..`이 있다: %q(line %d)", p.name, p.val, item.Line)
			}
		}
		// G-05: Clean 후 등재 튜플과 정확 일치. Clean이 `/a//b`·`/a/./b` 같은 표기 차이를
		// 없애므로, 같은 경로를 다르게 적어 대조를 비껴가는 경로가 닫힌다.
		cleanSrc, cleanDst := filepath.Clean(src), filepath.Clean(dst)
		rule := VolumeRule{Src: cleanSrc, Dst: cleanDst, Mode: mode}
		if !allow[rule.String()] {
			return errf(CodeVolume, "volumes 항목이 이 대상의 등재 튜플 밖이다: %q(line %d · 등재=%v)", rule.String(), item.Line, v.policy.VolumeAllow)
		}
		resolved, err := eval(cleanSrc)
		if err != nil {
			// 해소 실패(경로 부재·권한)는 통과가 아니다 — 무엇을 마운트하는지 증명하지 못했다.
			return errf(CodeVolume, "volumes 호스트 경로의 심볼릭 링크 해소 실패(증명 불가 · fail-closed): %q: %v", cleanSrc, err)
		}
		if filepath.Clean(resolved) != cleanSrc {
			return errf(CodeVolume, "volumes 호스트 경로가 심볼릭 링크로 다른 곳을 가리킨다: %q → %q(등재 경로와 불일치)", cleanSrc, resolved)
		}
	}
	return nil
}

// mapKeys는 매핑 노드의 키를 진단 메시지용으로 뽑는다.
func mapKeys(n *yaml.Node) []string {
	var out []string
	for i := 0; i < len(n.Content); i += 2 {
		out = append(out, n.Content[i].Value)
	}
	return out
}

// sortedKeys는 닫힌 목록을 결정적 순서로 뽑는다(오류 메시지가 실행마다 달라지지 않게).
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidUTF8Text는 디코드된 동봉 바이트가 텍스트로서 성립하는지 본다(NUL·BOM·비UTF-8 거절).
// manifest 층이 base64 계약과 함께 부르며, 여기 두는 이유는 "무엇이 유효한 compose 원문인가"의
// 정본이 이 패키지이기 때문이다.
func ValidUTF8Text(b []byte) error {
	if !utf8.Valid(b) {
		return errf(CodeSize, "동봉 compose가 유효한 UTF-8이 아니다")
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return errf(CodeSize, "동봉 compose에 NUL 바이트가 있다")
	}
	if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		return errf(CodeSize, "동봉 compose가 BOM으로 시작한다 — 원문은 BOM 없는 UTF-8이어야 한다")
	}
	return nil
}
