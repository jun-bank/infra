package dispatch

import (
	"context"
	"os"
	"strings"
	"testing"
)

// 동봉 compose 실행 위생(infra#19 R3) — candidate `-f`, `--project-directory` 고정,
// subprocess env 최소화. 이 셋이 함께 서야 "실행되는 실효 설정 = 서명 바이트 + 닫힌 주입값"이
// 성립한다. 하나라도 빠지면 보간 소스가 서명 밖으로 새고, 그 누수는 배포가 성공한 것처럼
// 보이는 채로 일어난다.

func boundExec(t *testing.T, r *captureRunner, injected []string) *Executor {
	t.Helper()
	base := newExec(Config{ComposeFile: "/etc/deploy/legacy.yml", Project: "core-green", AppService: "app"}, r)
	e, err := base.WithCompose("/srv/ws/core/green/compose.sha256-"+strings.Repeat("a", 64)+".yml", "/srv/ws/core/green", injected)
	if err != nil {
		t.Fatalf("결박 실행기 파생 실패: %v", err)
	}
	return e
}

// candidate 결박은 **모든 compose 하위 명령**에 걸려야 한다. up만 걸리고 down·ps가 옛 파일을
// 보면, 정리와 헬스 판정이 이번 배포와 다른 정의를 다루게 된다.
func TestWithComposeBindsEveryComposeCommand(t *testing.T) {
	wantFile := "/srv/ws/core/green/compose.sha256-" + strings.Repeat("a", 64) + ".yml"
	const wantDir = "/srv/ws/core/green"

	calls := map[string]func(*Executor, *captureRunner) error{
		"up": func(e *Executor, _ *captureRunner) error {
			return e.Up(context.Background(), "registry.example/core@sha256:"+strings.Repeat("b", 64))
		},
		"down":   func(e *Executor, _ *captureRunner) error { return e.Down(context.Background()) },
		"status": func(e *Executor, _ *captureRunner) error { _, err := e.Status(context.Background()); return err },
		"ps -q": func(e *Executor, _ *captureRunner) error {
			_, err := e.GreenContainers(context.Background())
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			r := &captureRunner{}
			e := boundExec(t, r, nil)
			if err := call(e, r); err != nil {
				t.Fatal(err)
			}
			if !contains(r.argv, wantFile) {
				t.Fatalf("argv가 candidate를 가리키지 않는다: %v", r.argv)
			}
			if contains(r.argv, "/etc/deploy/legacy.yml") {
				t.Fatalf("argv에 호스트 compose 파일이 남아 있다: %v", r.argv)
			}
			if !argPair(r.argv, "--project-directory", wantDir) {
				t.Fatalf("--project-directory %q가 없다: %v", wantDir, r.argv)
			}
			// 프로젝트명(슬롯 정체성)은 파생돼도 그대로여야 한다 — 바뀌면 down이 남의
			// 컨테이너를 다룬다.
			if !argPair(r.argv, "-p", "core-green") {
				t.Fatalf("-p 프로젝트명이 바뀌었다: %v", r.argv)
			}
		})
	}
}

// legacy 경로는 --project-directory를 붙이지 않는다(기존 동작 불변).
func TestLegacyConfigHasNoProjectDirectory(t *testing.T) {
	r := &captureRunner{}
	if err := newExec(baseCfg, r).Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if contains(r.argv, "--project-directory") {
		t.Fatalf("legacy 경로에 --project-directory가 붙었다(기존 동작 변경): %v", r.argv)
	}
}

// env 최소화 — 격리된 실행기는 호스트 env를 상속하지 않는다. 상속하면 COMPOSE_FILE 같은
// 변수가 우리가 준 -f를 덮고, 호스트의 아무 변수나 `${...}` 보간 소스가 된다.
func TestIsolatedEnvDropsHostEnvironment(t *testing.T) {
	t.Setenv("COMPOSE_FILE", "/tmp/evil.yml")
	t.Setenv("COMPOSE_PROJECT_NAME", "evil")
	t.Setenv("EVIL_SECRET", "leaked")

	r := &captureRunner{}
	e := boundExec(t, r, []string{"CORE_BLUE_URI=http://127.0.0.1:1", "DEPLOY_HOST_PORT=18080"})
	ref := "registry.example/core@sha256:" + strings.Repeat("c", 64)
	if err := e.Up(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if !r.env.isolated {
		t.Fatal("결박 실행기가 격리 env로 돌지 않는다 — 호스트 env가 보간 소스로 남는다")
	}
	want := map[string]bool{
		"CORE_BLUE_URI=http://127.0.0.1:1": true,
		"DEPLOY_HOST_PORT=18080":           true,
		"DEPLOY_IMAGE_REF=" + ref:          true,
	}
	if len(r.env.vars) != len(want) {
		t.Fatalf("주입 집합이 닫혀 있지 않다: %v", r.env.vars)
	}
	for _, kv := range r.env.vars {
		if !want[kv] {
			t.Fatalf("등재 밖 변수가 주입됐다: %q(전체 %v)", kv, r.env.vars)
		}
	}
}

// 실제 프로세스 env 조립까지 내려가 확인한다 — envSpec만 보면 osExec이 그것을 어떻게 쓰는지는
// 검증되지 않는다. 여기서 잡으려는 것은 "격리 플래그는 켰는데 상속을 그대로 하는" 무음 누수다.
func TestOsExecIsolatedEnvIsClosed(t *testing.T) {
	t.Setenv("COMPOSE_FILE", "/tmp/evil.yml")
	t.Setenv("EVIL_SECRET", "leaked")

	out, err := osExec(context.Background(), []string{"/usr/bin/env"}, envSpec{
		isolated: true,
		vars:     []string{"DEPLOY_HOST_PORT=18080"},
	}, "")
	if err != nil {
		t.Skipf("/usr/bin/env 실행 불가(환경 제약): %v", err)
	}
	got := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if line != "" {
			got[line] = true
		}
	}
	if !got["DEPLOY_HOST_PORT=18080"] {
		t.Fatalf("주입값이 child env에 없다: %v", out)
	}
	if got["COMPOSE_FILE=/tmp/evil.yml"] || got["EVIL_SECRET=leaked"] {
		t.Fatalf("격리 실행인데 호스트 env가 상속됐다(COMPOSE_* 누수): %v", out)
	}
	if !got["PATH="+os.Getenv("PATH")] {
		t.Fatalf("PATH가 없다 — docker CLI를 찾지 못한다: %v", out)
	}
}

// 비격리(legacy·pull)는 기존대로 상속한다 — 레지스트리 인증(HOME·DOCKER_CONFIG)이 그 위에 선다.
func TestOsExecNonIsolatedInherits(t *testing.T) {
	t.Setenv("JUNBANK_INHERIT_PROBE", "yes")
	out, err := osExec(context.Background(), []string{"/usr/bin/env"}, envSpec{vars: []string{"X=1"}}, "")
	if err != nil {
		t.Skipf("/usr/bin/env 실행 불가(환경 제약): %v", err)
	}
	if !strings.Contains(out, "JUNBANK_INHERIT_PROBE=yes") {
		t.Fatalf("비격리 실행인데 호스트 env를 상속하지 않았다(기존 동작 변경): %v", out)
	}
}

// 파생은 원본을 변형하지 않는다 — 실행기는 프로버가 함께 붙들고 있는 공유 객체라, 제자리에서
// 고치면 판정 중인 프로버가 다른 compose 파일을 보게 된다.
func TestWithComposeDoesNotMutateOriginal(t *testing.T) {
	r := &captureRunner{}
	base := newExec(Config{ComposeFile: "/etc/deploy/legacy.yml", Project: "core-green"}, r)
	if _, err := base.WithCompose("/srv/ws/core/green/c.yml", "/srv/ws/core/green", nil); err != nil {
		t.Fatal(err)
	}
	if base.ComposeFile() != "/etc/deploy/legacy.yml" || base.ProjectDirectory() != "" {
		t.Fatalf("원본이 변형됐다: file=%q dir=%q", base.ComposeFile(), base.ProjectDirectory())
	}
}

// 상대 경로 결박은 거부한다 — cwd에 따라 다른 파일을 실행하게 된다.
func TestWithComposeRequiresAbsolutePaths(t *testing.T) {
	base := newExec(baseCfg, &captureRunner{})
	for _, c := range []struct{ name, file, dir string }{
		{"상대 compose 파일", "compose.yml", "/srv/ws"},
		{"상대 기준 디렉터리", "/srv/ws/c.yml", "ws"},
		{"빈 compose 파일", "", "/srv/ws"},
		{"빈 기준 디렉터리", "/srv/ws/c.yml", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := base.WithCompose(c.file, c.dir, nil); err == nil {
				t.Fatal("거절되어야 하는데 통과했다")
			}
		})
	}
}

// argPair는 argv에 `flag value`가 이 순서로 인접해 있는지 본다(플래그만 있고 값이 다른
// 자리에 붙는 오조립을 잡는다).
func argPair(argv []string, flag, value string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag && argv[i+1] == value {
			return true
		}
	}
	return false
}
