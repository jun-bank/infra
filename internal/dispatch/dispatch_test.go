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

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
