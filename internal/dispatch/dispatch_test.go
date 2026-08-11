// dispatch 실행 층의 단위 테스트 — 실제 docker를 돌리지 않고 명령 조립을 검증한다.
// 치명 결함(raw shell 유입·태그 실행·비번 누출·범위 없는 down)을 argv/env/stdin 수준에서
// 막는다. 러너를 페이크로 교체해 부작용 없이 계약을 assert한다(DO-23 ⑴).
package dispatch

import (
	"context"
	"strings"
	"testing"
)

// captureRunner는 마지막 실행의 argv·env·stdin을 포착하는 페이크 러너다(부작용 0).
type captureRunner struct {
	argv  []string
	env   []string
	stdin string
	out   string
	err   error
}

func (c *captureRunner) fn() runnerFunc {
	return func(_ context.Context, argv []string, env []string, stdin string) (string, error) {
		c.argv, c.env, c.stdin = argv, env, stdin
		return c.out, c.err
	}
}

func newExec(cfg Config, r *captureRunner) *Executor {
	return &Executor{cfg: cfg, run: r.fn()}
}

var baseCfg = Config{
	ComposeFile: "/etc/deploy/green.yml",
	Project:     "core-green",
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// assertNoRawShell은 argv에 셸 평가 흔적이 없는지 본다(DO-23 ⑴ raw shell 금지).
func assertNoRawShell(t *testing.T, argv []string) {
	t.Helper()
	if len(argv) == 0 {
		t.Fatal("빈 argv")
	}
	switch argv[0] {
	case "sh", "bash", "/bin/sh", "/bin/bash", "zsh":
		t.Fatalf("raw shell 실행 파일: %q", argv[0])
	}
	for _, a := range argv {
		if a == "-c" {
			t.Fatalf("셸 -c 플래그가 argv에 있다(문자열 평가 위험): %v", argv)
		}
		if strings.ContainsAny(a, "|;&") && a != "{{.RestartCount}}" {
			t.Fatalf("argv 요소에 셸 메타문자: %q", a)
		}
	}
}

func TestPullArgvNoPrefix(t *testing.T) {
	r := &captureRunner{}
	e := newExec(baseCfg, r)
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	if err := e.Pull(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	want := []string{"docker", "pull", ref}
	if !eq(r.argv, want) {
		t.Fatalf("pull argv = %v, 기대 %v", r.argv, want)
	}
	assertNoRawShell(t, r.argv)
	if r.stdin != "" {
		t.Fatalf("프리픽스 없음인데 stdin 주입됨: %q", r.stdin)
	}
}

func TestPullArgvWithSudo(t *testing.T) {
	r := &captureRunner{}
	cfg := baseCfg
	cfg.SudoPrefix = []string{"sudo", "-S"}
	cfg.SudoPassword = "s3cret"
	e := newExec(cfg, r)
	ref := "repo@sha256:" + strings.Repeat("b", 64)
	if err := e.Pull(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	want := []string{"sudo", "-S", "docker", "pull", ref}
	if !eq(r.argv, want) {
		t.Fatalf("sudo pull argv = %v, 기대 %v", r.argv, want)
	}
	if r.stdin != "s3cret\n" {
		t.Fatalf("sudo -S인데 비번 stdin 미주입: %q", r.stdin)
	}
}

// Q3: 프리픽스가 비면 비번이 있어도 stdin에 절대 손대지 않는다.
func TestEmptyPrefixStdinUntouched(t *testing.T) {
	r := &captureRunner{}
	cfg := baseCfg
	cfg.SudoPrefix = nil
	cfg.SudoPassword = "should-not-leak"
	e := newExec(cfg, r)
	if err := e.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.stdin != "" {
		t.Fatalf("프리픽스 비었는데 stdin에 비번 흘림(누출·hang 위험): %q", r.stdin)
	}
}

func TestUpArgvAndImageEnv(t *testing.T) {
	r := &captureRunner{}
	e := newExec(baseCfg, r)
	ref := "registry.example/core@sha256:" + strings.Repeat("c", 64)
	if err := e.Up(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	want := []string{"docker", "compose", "-f", "/etc/deploy/green.yml", "-p", "core-green", "up", "-d", "--no-build"}
	if !eq(r.argv, want) {
		t.Fatalf("up argv = %v, 기대 %v", r.argv, want)
	}
	assertNoRawShell(t, r.argv)
	// --no-build 존재
	if !contains(r.argv, "--no-build") {
		t.Fatal("up argv에 --no-build 없음(빌드 도구 없음 — DO-4/P1)")
	}
	// 이미지 참조는 argv가 아니라 env 치환으로 주입한다.
	if contains(r.argv, ref) {
		t.Fatalf("이미지 참조가 up argv에 직접 들어감(env 치환이어야 한다): %v", r.argv)
	}
	if len(r.env) != 1 || r.env[0] != "DEPLOY_IMAGE_REF="+ref {
		t.Fatalf("up env = %v, 기대 [DEPLOY_IMAGE_REF=%s]", r.env, ref)
	}
}

func TestUpCustomImageEnvVar(t *testing.T) {
	r := &captureRunner{}
	cfg := baseCfg
	cfg.ImageEnvVar = "REHEARSAL_IMAGE"
	e := newExec(cfg, r)
	ref := "traefik/whoami@sha256:" + strings.Repeat("d", 64)
	if err := e.Up(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if len(r.env) != 1 || r.env[0] != "REHEARSAL_IMAGE="+ref {
		t.Fatalf("커스텀 env = %v, 기대 [REHEARSAL_IMAGE=%s]", r.env, ref)
	}
}

// Q2: down은 항상 -p <project>로 green 프로젝트만 대상. --rmi 없음(이미지 보존 — RL-5).
func TestDownArgvScopedNoRmi(t *testing.T) {
	r := &captureRunner{}
	e := newExec(baseCfg, r)
	if err := e.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"docker", "compose", "-f", "/etc/deploy/green.yml", "-p", "core-green", "down"}
	if !eq(r.argv, want) {
		t.Fatalf("down argv = %v, 기대 %v", r.argv, want)
	}
	assertNoRawShell(t, r.argv)
	if !contains(r.argv, "-p") || !contains(r.argv, "core-green") {
		t.Fatalf("down argv에 -p <project> 없음(범위 없는 down 금지 — Q2): %v", r.argv)
	}
	if contains(r.argv, "--rmi") {
		t.Fatalf("down argv에 --rmi 있음(이미지 삭제 금지 — RL-5): %v", r.argv)
	}
}

func TestStatusArgv(t *testing.T) {
	r := &captureRunner{}
	e := newExec(baseCfg, r)
	if _, err := e.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"docker", "compose", "-f", "/etc/deploy/green.yml", "-p", "core-green", "ps"}
	if !eq(r.argv, want) {
		t.Fatalf("status argv = %v, 기대 %v", r.argv, want)
	}
	assertNoRawShell(t, r.argv)
}

// 닫힌 열거 밖 Action은 argv를 만들지 않고 거부한다(DO-23 ⑴).
func TestArgvRejectsUnknownAction(t *testing.T) {
	if _, err := baseCfg.argv(Action("frobnicate"), ""); err == nil {
		t.Fatal("열거 밖 action이 argv를 만들었다(거부되어야 한다)")
	}
	if Action("frobnicate").Valid() {
		t.Fatal("열거 밖 action이 Valid()를 통과했다")
	}
	for _, a := range []Action{ActionPull, ActionUp, ActionDown, ActionStatus} {
		if !a.Valid() {
			t.Fatalf("열거 내 action %q가 Valid() 실패", a)
		}
	}
}

func TestRestartCountParse(t *testing.T) {
	r := &captureRunner{out: "  5\n"}
	e := newExec(baseCfg, r)
	n, err := e.RestartCount(context.Background(), "core-green-app-1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("재시작 횟수 = %d, 기대 5", n)
	}
	want := []string{"docker", "inspect", "-f", "{{.RestartCount}}", "core-green-app-1"}
	if !eq(r.argv, want) {
		t.Fatalf("inspect argv = %v, 기대 %v", r.argv, want)
	}
}

func TestRestartCountParseError(t *testing.T) {
	r := &captureRunner{out: "not-a-number"}
	e := newExec(baseCfg, r)
	if _, err := e.RestartCount(context.Background(), "x"); err == nil {
		t.Fatal("비정수 출력인데 파싱 오류 없음")
	}
}

// --- C1: sudo 프리픽스 검증 ----------------------------------------------------

// 악성·잘못된 프리픽스는 조립에서 거부되어야 한다(raw root shell 차단 — DO-23 ⑴).
func TestValidateSudoPrefixRejectsMalicious(t *testing.T) {
	bad := [][]string{
		{"sudo", "-S", "sh", "-c", "rm -rf /"}, // raw shell
		{"sudo", "sh"},                         // 셸 실행 파일
		{"sudo", "bash", "-c"},                 // 셸 + -c
		{"sudo", "-c", "whoami"},               // -c(명령 실행)
		{"sudo", "-s"},                         // -s(셸)
		{"sudo", "-i"},                         // -i(로그인 셸)
		{"sudo", "docker"},                     // 뒤 토큰이 명령(플래그 아님)
		{"sudo", "-S", ";", "id"},              // 셸 메타문자
		{"sudo", "-S", "&&", "id"},             // 셸 메타문자
		{"sudo", "-S", "$(id)"},                // 명령 치환
		{"doas", "-S"},                         // 첫 토큰이 sudo 아님
		{"/bin/sh", "-c"},                      // 셸 직접
		{"sudo", "/etc/x"},                     // 경로(플래그 아님)
	}
	for _, p := range bad {
		if err := ValidateSudoPrefix(p); err == nil {
			t.Errorf("악성/잘못된 프리픽스가 통과됨(거부되어야 한다): %v", p)
		}
		if _, err := NewExecutor(Config{SudoPrefix: p, ComposeFile: "/x", Project: "p"}); err == nil {
			t.Errorf("NewExecutor가 악성 프리픽스를 받아들임: %v", p)
		}
	}
}

// 정상 프리픽스(빈 값·sudo·sudo+플래그)는 통과해야 한다.
func TestValidateSudoPrefixAcceptsSafe(t *testing.T) {
	good := [][]string{
		nil,
		{},
		{"sudo"},
		{"sudo", "-S"},
		{"sudo", "-S", "-k"},
		{"sudo", "-n"},
	}
	for _, p := range good {
		if err := ValidateSudoPrefix(p); err != nil {
			t.Errorf("정상 프리픽스가 거부됨 %v: %v", p, err)
		}
		if _, err := NewExecutor(Config{SudoPrefix: p, ComposeFile: "/x", Project: "p"}); err != nil {
			t.Errorf("NewExecutor가 정상 프리픽스를 거부함 %v: %v", p, err)
		}
	}
}

// --- C2/P1/P6: 이미지 무결성 대조 + 부분기동 검출 -------------------------------

// scriptRunner는 argv에 특정 부분문자열이 있으면 그에 매핑된 출력을 돌려주는 페이크다.
// projectContainerIDs(ps -a -q)와 inspectState(inspect)가 서로 다른 명령이라 last-call만
// 잡는 captureRunner로는 검증할 수 없어, 명령별 응답을 스크립트한다(부작용 0).
// state[id] = "{{.State.Status}} {{.Config.Image}}" 한 줄(예: "running repo@sha256:...").
type scriptRunner struct {
	psOut      string            // compose ps -a -q 출력(줄바꿈 구분 컨테이너 ID)
	psErr      error             // ps 오류
	state      map[string]string // 컨테이너 ID → "<status> <image>" inspect 출력
	inspectErr error
}

func (s *scriptRunner) fn() runnerFunc {
	return func(_ context.Context, argv []string, _ []string, _ string) (string, error) {
		if contains(argv, "ps") && contains(argv, "-q") {
			return s.psOut, s.psErr
		}
		if contains(argv, "inspect") {
			if s.inspectErr != nil {
				return "", s.inspectErr
			}
			id := argv[len(argv)-1] // inspect ... <id>
			return s.state[id], nil
		}
		return "", nil
	}
}

func running(image string) string { return "running " + image }

// 실행중 컨테이너가 모두 pinned digest면 통과.
func TestVerifyImageDigestMatch(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	s := &scriptRunner{psOut: "c1\nc2\n", state: map[string]string{"c1": running(ref), "c2": running(ref)}}
	e := &Executor{cfg: baseCfg, run: s.fn()}
	if err := e.VerifyImageDigest(context.Background(), ref); err != nil {
		t.Fatalf("일치인데 대조 실패: %v", err)
	}
}

// P6: 사이드카(다른 이미지)가 함께 떠 있어도, 실행중 ≥1개가 pinned digest면 통과한다
// (all-match 요구는 정상 배포를 오탐했다 — 사이드카·orphan을 실패시키지 않는다).
func TestVerifyImageDigestSidecarPasses(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	sidecar := "prom/node-exporter@sha256:" + strings.Repeat("b", 64)
	s := &scriptRunner{psOut: "app\nside\n", state: map[string]string{"app": running(ref), "side": running(sidecar)}}
	e := &Executor{cfg: baseCfg, run: s.fn()}
	if err := e.VerifyImageDigest(context.Background(), ref); err != nil {
		t.Fatalf("app이 pinned digest로 떴는데 사이드카 때문에 대조 실패: %v", err)
	}
}

// P1: 부분기동 — 프로젝트에 종료(exited) 컨테이너가 있으면 app이 pinned로 떠 있어도 실패
// (worker가 up 직후 종료됐는데 app 2xx면 COMPLETED로 위장하는 silent 부분기동 차단).
func TestVerifyImageDigestPartialBootFails(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	s := &scriptRunner{psOut: "app\nworker\n", state: map[string]string{"app": running(ref), "worker": "exited " + ref}}
	e := &Executor{cfg: baseCfg, run: s.fn()}
	err := e.VerifyImageDigest(context.Background(), ref)
	if err == nil {
		t.Fatal("worker 종료(부분기동)인데 대조 통과(silent COMPLETED 위험)")
	}
	if !strings.Contains(err.Error(), "worker") && !strings.Contains(err.Error(), "exited") {
		t.Fatalf("부분기동 오류에 종료 컨테이너 정보가 없음: %v", err)
	}
}

// P6: 실행중 컨테이너 중 pinned digest 일치가 0개면(엉뚱 이미지 — :latest·오타) 실패.
func TestVerifyImageDigestWrongImageFails(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	wrong := "registry.example/core:latest"
	s := &scriptRunner{psOut: "c1\n", state: map[string]string{"c1": running(wrong)}}
	e := &Executor{cfg: baseCfg, run: s.fn()}
	err := e.VerifyImageDigest(context.Background(), ref)
	if err == nil {
		t.Fatal("실행 이미지가 pinned digest와 불일치인데 오류 없음(silent COMPLETED 위험)")
	}
	// 기대 pinned 참조를 오류에 담아야 한다(어떤 값이 떠야 했는지).
	if !strings.Contains(err.Error(), ref) {
		t.Fatalf("오류에 기대 pinned 참조가 없음: %v", err)
	}
}

// 뜬 컨테이너가 없으면 pinned digest 실행을 증명할 수 없다 → 오류(fail-closed).
func TestVerifyImageDigestNoContainers(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	s := &scriptRunner{psOut: "\n", state: map[string]string{}}
	e := &Executor{cfg: baseCfg, run: s.fn()}
	if err := e.VerifyImageDigest(context.Background(), ref); err == nil {
		t.Fatal("컨테이너 0개인데 대조 통과(증명 불가 = 오류여야 한다)")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
