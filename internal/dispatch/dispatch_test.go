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
	want := []string{"docker", "compose", "-f", "/etc/deploy/green.yml", "-p", "core-green", "up", "-d", "--no-build", "--remove-orphans"}
	if !eq(r.argv, want) {
		t.Fatalf("up argv = %v, 기대 %v", r.argv, want)
	}
	assertNoRawShell(t, r.argv)
	// --no-build 존재
	if !contains(r.argv, "--no-build") {
		t.Fatal("up argv에 --no-build 없음(빌드 도구 없음 — DO-4/P1)")
	}
	// --remove-orphans 존재(H2 임시 완화 — orphan 마스킹 차단)
	if !contains(r.argv, "--remove-orphans") {
		t.Fatal("up argv에 --remove-orphans 없음(orphan 마스킹 완화 — H2)")
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
		{"sudo", "-Ss"},                        // P5: 결합 short flag(-S+-s 셸) — allowlist 밖
		{"sudo", "-b"},                         // P5: 명령을 백그라운드로(완료판정과 실변이 분리)
		{"sudo", "--background"},               // P5: -b 롱폼
		{"sudo", "-p", "prompt"},               // P5: 미열거 플래그(+ 인자)
		{"sudo", "-Sk"},                        // P5: 임의 결합 short flag
		{"sudo", "-A"},                         // P5: 미열거 플래그(askpass)
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
		{"sudo", "-S", "-k", "-n"},               // P5: 열거 허용 플래그 조합
		{"sudo", "--stdin", "--reset-timestamp"}, // P5: 롱폼 허용
		{"sudo", "--non-interactive"},            // P5: 롱폼 허용
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

// --- #21: 사후조건을 대상 app 서비스에 identity로 결박 -------------------------
//
// 여기 네 테스트가 H2(fail-open)·M1(오탐)의 닫힘을 증명한다. 결박의 축은 compose가 붙이는
// 서비스 라벨 하나이며(composeServiceLabel), 판정은 그 서비스의 컨테이너만 본다.

// svcCfg는 대상 app 서비스로 결박된 설정이다(현 .9 구조의 서비스명 = "app").
var svcCfg = Config{ComposeFile: "/etc/deploy/green.yml", Project: "core-green", AppService: "app"}

// line은 inspect 한 줄(status image service)을 만든다 — inspectStateFormat의 출력 형태다.
func line(status, image, service string) string { return status + " " + image + " " + service }

// H2(fail-open) 닫힘: 사이드카가 pinned digest를 실행 중이어도 **대상 app 서비스**가 틀린
// 이미지(:latest·env 오타)를 실행 중이면 실패한다. 결박 전에는 사이드카의 일치가 app의
// 일치를 대신해 엉뚱한 이미지가 COMPLETED로 기록될 수 있었다.
func TestVerifyImageDigestSidecarPinnedButAppWrongFails(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	wrong := "registry.example/core:latest"
	s := &scriptRunner{psOut: "app1\nside1\n", state: map[string]string{
		"app1":  line("running", wrong, "app"),           // 배포 대상 — 틀린 이미지
		"side1": line("running", ref, "metrics-sidecar"), // 사이드카 — 우연히 pinned digest
	}}
	e := &Executor{cfg: svcCfg, run: s.fn()}
	err := e.VerifyImageDigest(context.Background(), ref)
	if err == nil {
		t.Fatal("app이 틀린 이미지인데 사이드카의 pinned digest가 통과시켰다(H2 fail-open — silent COMPLETED)")
	}
	// 무엇이 기대였고 실제 app이 무엇을 실행 중인지가 오류에 남아야 한다.
	if !strings.Contains(err.Error(), ref) || !strings.Contains(err.Error(), wrong) {
		t.Fatalf("오류에 기대 pinned 참조·실제 실행 이미지가 없다: %v", err)
	}
}

// M1(fail-closed 오탐) 닫힘: 정상 종료한 one-shot/init 컨테이너나 정지 orphan이 있어도
// 대상 app 서비스가 정상이면 통과한다(다른 서비스의 exited는 부분기동이 아니다).
func TestVerifyImageDigestOneShotExitedPasses(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	s := &scriptRunner{psOut: "app1\nmigrate1\norphan1\n", state: map[string]string{
		"app1":     line("running", ref, "app"),                                                // 대상 — 정상
		"migrate1": line("exited", ref, "db-migrate"),                                          // one-shot 정상 종료
		"orphan1":  line("exited", "registry.example/old@sha256:"+strings.Repeat("c", 64), ""), // 라벨 없는 정지 orphan
	}}
	e := &Executor{cfg: svcCfg, run: s.fn()}
	if err := e.VerifyImageDigest(context.Background(), ref); err != nil {
		t.Fatalf("app이 정상인데 one-shot 종료·정지 orphan을 부분기동으로 오판했다(M1): %v", err)
	}
}

// 대상 app 서비스의 컨테이너가 하나도 없으면 실패한다 — 사이드카만 떠 있는 상태를 통과로
// 삼지 않는다(증명 불가 = 실패 · 기존 계약 유지).
func TestVerifyImageDigestNoTargetServiceContainerFails(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	s := &scriptRunner{psOut: "side1\n", state: map[string]string{
		"side1": line("running", ref, "metrics-sidecar"),
	}}
	e := &Executor{cfg: svcCfg, run: s.fn()}
	err := e.VerifyImageDigest(context.Background(), ref)
	if err == nil {
		t.Fatal("대상 app 서비스 컨테이너가 0개인데 통과(사이드카만으로 사후조건이 증명될 수 없다)")
	}
	if !strings.Contains(err.Error(), "app") {
		t.Fatalf("오류에 대상 서비스명이 없다: %v", err)
	}
}

// 부분기동 판정은 **대상 서비스 안에서는** 그대로 산다 — app replica 하나가 죽었으면
// 다른 replica가 pinned digest로 살아 있어도 실패한다(silent 부분기동 차단).
func TestVerifyImageDigestAppReplicaExitedFails(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	s := &scriptRunner{psOut: "app1\napp2\n", state: map[string]string{
		"app1": line("running", ref, "app"),
		"app2": line("exited", ref, "app"),
	}}
	e := &Executor{cfg: svcCfg, run: s.fn()}
	err := e.VerifyImageDigest(context.Background(), ref)
	if err == nil {
		t.Fatal("대상 서비스 컨테이너가 종료됐는데 통과(부분기동 위장)")
	}
	if !strings.Contains(err.Error(), "app2") {
		t.Fatalf("부분기동 오류에 종료된 대상 컨테이너가 없다: %v", err)
	}
}

// F1: 결박된 서비스 안에서는 all-match다 — 같은 app 서비스의 replica가 [pinned + 틀린 이미지]로
// 섞여 뜨면(rolling 잔재·부분 재생성) 실패한다. ≥1-match면 그 mixed-replica가 COMPLETED로
// 위장하고 틀린 이미지를 실행하는 replica가 트래픽을 받는다.
func TestVerifyImageDigestMixedReplicaFails(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	wrong := "registry.example/core:latest"
	s := &scriptRunner{psOut: "app1\napp2\n", state: map[string]string{
		"app1": line("running", ref, "app"),   // 새 버전
		"app2": line("running", wrong, "app"), // 같은 서비스인데 틀린 이미지
	}}
	e := &Executor{cfg: svcCfg, run: s.fn()}
	err := e.VerifyImageDigest(context.Background(), ref)
	if err == nil {
		t.Fatal("같은 서비스에 틀린 이미지 replica가 섞였는데 통과(mixed-replica 위장)")
	}
	// 어느 컨테이너가 무엇을 실행 중인지가 오류에 남아야 한다(진단 가능성).
	if !strings.Contains(err.Error(), "app2") || !strings.Contains(err.Error(), wrong) {
		t.Fatalf("불일치 목록이 오류에 없다: %v", err)
	}
	// 대상 서비스가 전부 pinned면 통과한다(검사가 정상 배포를 막지 않는다).
	s2 := &scriptRunner{psOut: "app1\napp2\n", state: map[string]string{
		"app1": line("running", ref, "app"), "app2": line("running", ref, "app"),
	}}
	if err := (&Executor{cfg: svcCfg, run: s2.fn()}).VerifyImageDigest(context.Background(), ref); err != nil {
		t.Fatalf("replica가 전부 pinned인데 실패: %v", err)
	}
}

// F3: 결박이 켜졌는데 프로젝트에 컨테이너는 있고 대상 서비스 매치가 0개면 빈 목록을 조용히
// 돌려주지 않는다 — 같은 상황을 실패로 닫는 VerifyImageDigest ⑶과 같은 축의 오류다.
func TestGreenContainersNoTargetServiceMatchErrors(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	s := &scriptRunner{psOut: "side1\n", state: map[string]string{
		"side1": line("running", ref, "metrics-sidecar"),
	}}
	e := &Executor{cfg: svcCfg, run: s.fn()}
	ids, err := e.GreenContainers(context.Background())
	if err == nil {
		t.Fatalf("대상 서비스 매치 0개인데 무음 통과: ids=%v (재시작 검사가 빈 대상으로 돈다)", ids)
	}
	if !strings.Contains(err.Error(), "app") {
		t.Fatalf("오류에 대상 서비스명이 없다: %v", err)
	}
}

// inspect는 서비스 라벨을 함께 읽는다(결박의 입력) — 포맷이 바뀌면 결박이 조용히 꺼진다.
func TestInspectStateReadsComposeServiceLabel(t *testing.T) {
	r := &captureRunner{out: line("running", "img", "app")}
	e := newExec(svcCfg, r)
	st, err := e.inspectState(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if st.service != "app" || st.status != "running" || st.image != "img" {
		t.Fatalf("inspect 파싱 = %+v, running/img/app 기대", st)
	}
	if !contains(r.argv, "-f") || !contains(r.argv, inspectStateFormat) {
		t.Fatalf("inspect argv에 라벨 포맷이 없다: %v", r.argv)
	}
	if !strings.Contains(inspectStateFormat, composeServiceLabel) {
		t.Fatalf("inspect 포맷에 compose 서비스 라벨이 없다: %q", inspectStateFormat)
	}
	assertNoRawShell(t, r.argv)
}

// 라벨이 없는 컨테이너는 대상이 아니다 — 결박이 켜졌는데 소속을 증명하지 못하는 컨테이너를
// 대상으로 세면 결박이 무의미해진다(라벨 부재 = 세 번째 칸 없음).
func TestVerifyImageDigestUnlabeledContainerNotTarget(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	s := &scriptRunner{psOut: "x1\n", state: map[string]string{"x1": "running " + ref}}
	e := &Executor{cfg: svcCfg, run: s.fn()}
	if err := e.VerifyImageDigest(context.Background(), ref); err == nil {
		t.Fatal("라벨 없는 컨테이너를 대상 app으로 세어 통과했다(결박 무력화)")
	}
}

// CD-1 재시작 검사 대상도 같은 결박을 따른다 — 대상 서비스의 컨테이너만 돌려준다
// (사이드카 재시작이 앱 준비성 판정을 실패시키지 않는다 · 트레이드오프는 구현 주석).
func TestGreenContainersBoundToAppService(t *testing.T) {
	ref := "registry.example/core@sha256:" + strings.Repeat("a", 64)
	s := &scriptRunner{psOut: "app1\nside1\n", state: map[string]string{
		"app1":  line("running", ref, "app"),
		"side1": line("running", ref, "metrics-sidecar"),
	}}
	e := &Executor{cfg: svcCfg, run: s.fn()}
	ids, err := e.GreenContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !eq(ids, []string{"app1"}) {
		t.Fatalf("재시작 검사 대상 = %v, [app1] 기대(대상 서비스만)", ids)
	}
}

// 결박 미설정(단일 경로 모드의 하위호환)은 프로젝트 전체를 보던 기존 판정 그대로다 —
// ps -q 한 번으로 끝나고(추가 inspect 없음) 라벨 유무와 무관하다.
func TestGreenContainersUnboundKeepsProjectScope(t *testing.T) {
	r := &captureRunner{out: "app1\nside1\n"}
	e := newExec(baseCfg, r) // AppService 없음
	ids, err := e.GreenContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !eq(ids, []string{"app1", "side1"}) {
		t.Fatalf("결박 없음: 대상 = %v, [app1 side1] 기대(프로젝트 전체)", ids)
	}
	if !contains(r.argv, "ps") || !contains(r.argv, "-q") {
		t.Fatalf("결박 없음인데 ps -q가 아니다: %v", r.argv)
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

// 회귀(2026-08-12 통합 실측 · troubleshooting-false-unknown.md): image가 무관한 compose
// 명령(down·ps·status)도 image env를 주입해야 한다. compose 파일의 image: ${VAR}는 프로젝트
// 로드 시 검증되므로, VAR가 비면 "invalid compose project"로 명령이 실패해 정리(down)·이미지
// 대조(ps)가 무너지고 false-UNKNOWN이 된다. up만 주입하던 비대칭을 이 테스트가 고정한다.
func TestComposeOpsInjectImageEnv(t *testing.T) {
	cfg := Config{ComposeFile: "/etc/deploy/green.yml", Project: "core-green", ImageEnvVar: "CORE_IMAGE"}
	wantEnv := "CORE_IMAGE=" + composeImagePlaceholder

	hasEnv := func(env []string) bool {
		for _, e := range env {
			if e == wantEnv {
				return true
			}
		}
		return false
	}

	t.Run("down", func(t *testing.T) {
		r := &captureRunner{}
		if err := newExec(cfg, r).Down(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !hasEnv(r.env) {
			t.Fatalf("down env에 %q 없음: %v", wantEnv, r.env)
		}
	})
	t.Run("GreenContainers", func(t *testing.T) {
		r := &captureRunner{}
		if _, err := newExec(cfg, r).GreenContainers(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !hasEnv(r.env) {
			t.Fatalf("ps -q env에 %q 없음: %v", wantEnv, r.env)
		}
	})
	t.Run("Status", func(t *testing.T) {
		r := &captureRunner{}
		if _, err := newExec(cfg, r).Status(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !hasEnv(r.env) {
			t.Fatalf("status env에 %q 없음: %v", wantEnv, r.env)
		}
	})
	t.Run("up은 placeholder가 아니라 실제 digest를 주입", func(t *testing.T) {
		r := &captureRunner{}
		ref := "ghcr.io/jun-bank/core@sha256:" + strings.Repeat("a", 64)
		if err := newExec(cfg, r).Up(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
		want := "CORE_IMAGE=" + ref
		found := false
		for _, e := range r.env {
			if e == want {
				found = true
			}
			if e == wantEnv {
				t.Fatalf("up이 placeholder를 주입함(digest 고정 붕괴): %v", r.env)
			}
		}
		if !found {
			t.Fatalf("up env에 실제 digest %q 없음: %v", want, r.env)
		}
	})
}
