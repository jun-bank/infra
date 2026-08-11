// Package dispatch는 특권 실행 모듈이다 — ROLE=agent/main 모드가 자기 호스트에서 특권
// 조작(컨테이너 pull·compose up/down·상태 조회)을 수행할 때 쓰는 내부 실행 층이다. 구
// DO-13의 root 소유 SSH forced-command(별도 cmd/dispatcher)를 대체해, 같은 계약을 agent
// 모드의 내부 모듈로 흡수한다(ADR-027 DO-23 ⑴).
//
// 계약 출처(정본 — 이 코드는 이를 재해석하지 않는다):
//   - ADR-027 DO-23  (특권 = .env 서버 자격 + sudo · 수용된 잔여 위험 잔여-7;
//     완화 ⑴ 실행은 열거된 명령만, raw shell·임의 flag 금지 · ⑵ 인터넷 입력은
//     서명 검증 통과 후에만 특권 경로에 닿는다 — 코드 층 경계)
//   - ADR-027 DO-18  (pull·up은 digest로 고정 — 태그 금지. 이미지 참조 = <repo>@<digest>)
//   - ADR-027 DO-16  (원격/로컬 실행 3상태: 미실행 / 완료 / UNKNOWN)
//   - ADR-029 IA-5   (허용 import는 닫힌 목록으로 리뷰가 지킨다 — Go 관용구)
//
// 핵심 불변식: Action은 닫힌 열거이며 그 밖의 값은 어떤 것도 실행되지 않는다. 명령은
// exec.CommandContext에 인자 슬라이스로만 전달한다 — sh -c·문자열 셸 평가는 절대 없다
// (DO-23 ⑴ raw shell 금지). compose 파일 경로·프로젝트명·이미지 repo는 설정에서 오고
// 요청 입력이 아니다(자유도를 낮추는 것이 이 모듈의 핵심이다).
package dispatch

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Action은 이 모듈이 수행할 수 있는 닫힌 연산 집합이다(DO-23 ⑴: 열거된 명령만).
// 이 집합 밖의 값은 받아들이지 않으며, raw shell·임의 flag를 위한 자리는 의도적으로
// 두지 않는다.
type Action string

const (
	ActionPull   Action = "pull"   // digest로 이미지를 pull
	ActionUp     Action = "up"     // 고정된 manifest를 compose up(green)
	ActionDown   Action = "down"   // compose down(이미지는 남긴다 — RL-5)
	ActionStatus Action = "status" // 부작용 없는 query(DO-16)
)

// allowed는 허용 Action의 닫힌 목록이다.
var allowed = map[Action]bool{
	ActionPull: true, ActionUp: true, ActionDown: true, ActionStatus: true,
}

// Valid는 act가 열거에 속하는지 보고한다.
func (a Action) Valid() bool { return allowed[a] }

// Config는 실행 모듈의 고정 설정이다(DO-23 ⑴). 임의의 flag·볼륨·경로를 요청에서 받지
// 않고, 여기서 오는 값만 명령 조립에 쓴다. compose 파일·프로젝트명은 코드/env에서 오며
// 요청 입력이 아니다.
type Config struct {
	// SudoPrefix는 각 명령 앞에 붙는 프리픽스다(공백 split된 슬라이스). 비면 프리픽스
	// 없이 직접 실행한다(docker 그룹 소속 개발 머신). 실호스트는 예: ["sudo","-S"].
	SudoPrefix []string
	// SudoPassword는 sudo -S용 비밀번호다(있을 때만 child stdin으로 주입). 프리픽스가
	// 비었으면 절대 stdin에 주입하지 않는다(직접 실행 hang·누출 방지 — Q3).
	SudoPassword string
	// ComposeFile은 compose 파일 경로다(-f). 요청이 아니라 설정에서 온다.
	ComposeFile string
	// Project는 green 전용 compose 프로젝트명이다(-p). down은 항상 이 프로젝트만
	// 대상으로 한다 — 공유·무범위 down 금지(blue를 죽이지 않게 — Q2).
	Project string
	// ImageEnvVar는 compose up이 digest 고정 참조를 읽는 env 변수명이다. compose 파일이
	// image: ${<ImageEnvVar>} 로 이 값을 참조한다. 비면 defaultImageEnvVar를 쓴다.
	ImageEnvVar string
}

// defaultImageEnvVar는 ImageEnvVar 미지정 시의 기본 env 변수명이다.
const defaultImageEnvVar = "DEPLOY_IMAGE_REF"

// imageEnvVar는 설정된 env 변수명(없으면 기본)을 준다.
func (c Config) imageEnvVar() string {
	if c.ImageEnvVar == "" {
		return defaultImageEnvVar
	}
	return c.ImageEnvVar
}

// commandLine은 sudo 프리픽스를 앞에 붙인 전체 argv를 만든다(순수 함수 — raw shell 없음).
// base는 이미 토큰 단위로 쪼개진 인자다(예: "docker","pull",ref). 반환값은 그대로
// exec.CommandContext(argv[0], argv[1:]...) 로 실행돼 셸 해석을 거치지 않는다.
func (c Config) commandLine(base ...string) []string {
	if len(c.SudoPrefix) == 0 {
		return base
	}
	argv := make([]string, 0, len(c.SudoPrefix)+len(base))
	argv = append(argv, c.SudoPrefix...)
	argv = append(argv, base...)
	return argv
}

// argv는 Action별 전체 명령 argv를 조립한다(순수 함수 — 테스트가 argv를 직접 assert한다).
// ref는 pull에서만 쓰인다(up은 env 치환으로 주입하므로 argv에 넣지 않는다 — 아래 Up 참조).
// 열거 밖 Action은 argv를 만들지 않고 거부한다(DO-23 ⑴ — 닫힌 열거의 마지막 방어선).
func (c Config) argv(act Action, ref string) ([]string, error) {
	switch act {
	case ActionPull:
		// pull은 digest 고정 참조를 인자로 직접 받는다(DO-18 ⑵).
		return c.commandLine("docker", "pull", ref), nil
	case ActionUp:
		// up은 green 프로젝트를 --no-build로 띄운다(호스트에 빌드 도구 없음 — DO-4/P1).
		// 이미지 참조는 argv가 아니라 env 치환으로 주입한다(compose 파일이 ${env}를 읽는다).
		return c.commandLine("docker", "compose", "-f", c.ComposeFile, "-p", c.Project, "up", "-d", "--no-build"), nil
	case ActionDown:
		// down은 green 프로젝트만 종료한다(-p 항상 포함 — Q2). --rmi 없음: 이미지를
		// 지우지 않는다(RL-5 — 호스트 로컬 되돌림이 성립해야 한다).
		return c.commandLine("docker", "compose", "-f", c.ComposeFile, "-p", c.Project, "down"), nil
	case ActionStatus:
		// status는 부작용 없는 조회다(DO-16).
		return c.commandLine("docker", "compose", "-f", c.ComposeFile, "-p", c.Project, "ps"), nil
	default:
		return nil, fmt.Errorf("dispatch: action이 닫힌 열거 밖이다: %q", act)
	}
}

// runnerFunc는 조립된 argv를 실제로 실행하는 함수다. 기본은 osExec이며, 단위 테스트는
// 이를 교체해 argv·env·stdin을 실제 exec 없이 포착한다(부작용 없는 계약 검증).
type runnerFunc func(ctx context.Context, argv []string, env []string, stdin string) (string, error)

// Executor는 Config를 들고 열거된 특권 명령을 실행한다. 실행 경로는 오직 argv 슬라이스
// 이며 문자열 셸 평가가 없다.
type Executor struct {
	cfg Config
	run runnerFunc
}

// NewExecutor는 기본(실제 exec) 러너로 Executor를 만든다. sudo 프리픽스가 열거된 안전
// 형태(첫 토큰 정확히 "sudo" + 나머지는 플래그만)가 아니면 오류를 반환한다 — 잘못된
// 프리픽스가 raw root shell을 여는 것을 조립 시점에 막는다(DO-23 ⑴ raw shell 금지).
func NewExecutor(cfg Config) (*Executor, error) {
	if err := ValidateSudoPrefix(cfg.SudoPrefix); err != nil {
		return nil, err
	}
	return &Executor{cfg: cfg, run: osExec}, nil
}

// allowedSudoFlags는 프리픽스에 허용되는 sudo 플래그의 닫힌 allowlist다(정확 토큰만).
// 비대화 비밀번호 주입(-S)·타임스탬프 무효화(-k)·비대화 실패(-n)와 각 롱폼만 둔다 —
// 이들은 명령을 백그라운드로 돌리거나 셸을 열지 않는다. 여기에 없는 것은 전부 거부한다.
var allowedSudoFlags = map[string]bool{
	"-S": true, "--stdin": true, // 비밀번호를 stdin에서 읽는다
	"-k": true, "--reset-timestamp": true, // sudo 타임스탬프 무효화
	"-n": true, "--non-interactive": true, // 프롬프트 없이 실패
}

// ValidateSudoPrefix는 sudo 프리픽스가 안전한 열거 형태인지 검증한다(DO-23 ⑴). 프리픽스는
// 각 특권 명령 앞에 argv로 그대로 붙으므로, 여기서 자유도를 닫지 않으면 설정 값이 raw root
// shell을 열거나(예: "sudo -S sh -c ...") 명령을 백그라운드로 돌려 완료 판정과 실제 변이를
// 분리(-b/--background)할 수 있다. 규칙(엄격 allowlist):
//   - 비어 있으면 통과한다(프리픽스 없음 = docker 그룹 소속 직접 실행).
//   - 첫 토큰은 정확히 "sudo" 여야 한다(다른 실행 파일 금지 — 임의 wrapper·셸 차단).
//   - 나머지 토큰은 allowedSudoFlags에 속한 정확 토큰만 허용한다. 결합 short flag(-Ss·-Sk)·
//     -b/--background·-s/-i/-c(셸)·-p(prompt)·askpass·미열거 플래그·셸 메타문자·경로·명령은
//     전부 거부한다 — allowlist에 정확히 일치하지 않으면 통과하지 못한다.
func ValidateSudoPrefix(prefix []string) error {
	if len(prefix) == 0 {
		return nil
	}
	if prefix[0] != "sudo" {
		return fmt.Errorf("dispatch: sudo 프리픽스의 첫 토큰은 정확히 %q 여야 한다(raw shell·임의 wrapper 금지 — DO-23 ⑴): %q", "sudo", prefix[0])
	}
	for _, tok := range prefix[1:] {
		if !allowedSudoFlags[tok] {
			return fmt.Errorf("dispatch: sudo 프리픽스 뒤 토큰은 명시 허용 플래그(-S·--stdin·-k·--reset-timestamp·-n·--non-interactive)만 정확 토큰으로 허용한다 — 결합 short flag·-b/--background·셸 플래그·경로·명령·미열거 플래그 전부 거부(DO-23 ⑴): %q", tok)
		}
	}
	return nil
}

// stdin은 child에 흘릴 stdin 내용을 정한다(Q3). 프리픽스가 비어있지 않고 AND
// SudoPassword가 설정됐을 때만 비번을 준다 — 리터럴 "sudo -S" 부분문자열로 게이팅하지
// 않는다. 프리픽스가 비면 빈 문자열을 반환해 stdin에 손대지 않는다.
func (e *Executor) stdin() string {
	if len(e.cfg.SudoPrefix) > 0 && e.cfg.SudoPassword != "" {
		return e.cfg.SudoPassword + "\n"
	}
	return ""
}

// Pull은 digest로 고정된 이미지를 pull한다(DO-18 ⑵). ref = <repo>@sha256:...
func (e *Executor) Pull(ctx context.Context, imageRef string) error {
	argv, err := e.cfg.argv(ActionPull, imageRef)
	if err != nil {
		return err
	}
	_, err = e.run(ctx, argv, nil, e.stdin())
	return err
}

// Up은 green 프로젝트를 compose up한다. 이미지 참조는 ImageEnvVar env로 주입해 compose
// 파일의 image: ${...} 가 그 digest 고정 참조로 뜨게 한다(DO-18 ⑵).
func (e *Executor) Up(ctx context.Context, imageRef string) error {
	argv, err := e.cfg.argv(ActionUp, imageRef)
	if err != nil {
		return err
	}
	env := []string{e.cfg.imageEnvVar() + "=" + imageRef}
	_, err = e.run(ctx, argv, env, e.stdin())
	return err
}

// Down은 green 프로젝트만 compose down한다(이미지는 남긴다 — RL-5, Q2).
func (e *Executor) Down(ctx context.Context) error {
	argv, err := e.cfg.argv(ActionDown, "")
	if err != nil {
		return err
	}
	_, err = e.run(ctx, argv, nil, e.stdin())
	return err
}

// Status는 부작용 없는 상태 조회다(DO-16). 조립된 출력을 그대로 준다.
func (e *Executor) Status(ctx context.Context) (string, error) {
	argv, err := e.cfg.argv(ActionStatus, "")
	if err != nil {
		return "", err
	}
	return e.run(ctx, argv, nil, e.stdin())
}

// RestartCount는 컨테이너 재시작 횟수를 읽는다(docker inspect — 부작용 없는 조회).
// CD-1 그린 위장 방어의 입력이다: 재시작 정책이 헬스 대기 중 죽은 프로세스를 되살려
// "연속 N회"를 다른 프로세스의 성공으로 이어붙이는 것을 이 값의 증가로 감지한다.
func (e *Executor) RestartCount(ctx context.Context, name string) (int, error) {
	// inspect는 열거된 4개 mutate action이 아니라 status 계열의 부작용 없는 조회다.
	argv := e.cfg.commandLine("docker", "inspect", "-f", "{{.RestartCount}}", name)
	out, err := e.run(ctx, argv, nil, e.stdin())
	if err != nil {
		return 0, err
	}
	n, perr := strconv.Atoi(strings.TrimSpace(out))
	if perr != nil {
		return 0, fmt.Errorf("dispatch: 재시작 횟수 파싱 불가 %q: %w", out, perr)
	}
	return n, nil
}

// GreenContainers는 green 프로젝트에 현재 뜬 컨테이너 ID 목록을 준다(docker compose ps -q
// — 부작용 없는 조회). 컨테이너명을 설정에 하드코딩하지 않고 compose 프로젝트에서 파생해,
// 이미지 대조(C2)·재시작 검사(CD-1 그린 위장 방어)가 항상 실제 뜬 컨테이너를 대상으로
// 하게 한다. 빈 목록은 오류가 아니라 빈 슬라이스로 준다 — 판정은 호출자가 한다.
func (e *Executor) GreenContainers(ctx context.Context) ([]string, error) {
	argv := e.cfg.commandLine("docker", "compose", "-f", e.cfg.ComposeFile, "-p", e.cfg.Project, "ps", "-q")
	out, err := e.run(ctx, argv, nil, e.stdin())
	if err != nil {
		return nil, fmt.Errorf("dispatch: green 컨테이너 조회 실패(compose ps -q): %w", err)
	}
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			ids = append(ids, s)
		}
	}
	return ids, nil
}

// projectContainerIDs는 green 프로젝트의 모든 컨테이너 ID를 준다(docker compose ps -a -q
// — 부작용 없는 조회). ps -q(실행중만)와 달리 -a로 종료·실패 컨테이너까지 포함해, 사후조건
// 판정이 부분기동(일부 서비스가 up 직후 종료)을 검출할 수 있게 한다(P1). 빈 목록은 오류가
// 아니라 빈 슬라이스로 준다 — 판정은 호출자가 한다.
func (e *Executor) projectContainerIDs(ctx context.Context) ([]string, error) {
	argv := e.cfg.commandLine("docker", "compose", "-f", e.cfg.ComposeFile, "-p", e.cfg.Project, "ps", "-a", "-q")
	out, err := e.run(ctx, argv, nil, e.stdin())
	if err != nil {
		return nil, fmt.Errorf("dispatch: 프로젝트 컨테이너 조회 실패(compose ps -a -q): %w", err)
	}
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			ids = append(ids, s)
		}
	}
	return ids, nil
}

// containerState는 한 컨테이너의 실행 상태와 이미지 참조다(사후조건 판정 입력).
type containerState struct {
	id     string
	status string // docker State.Status: running·exited·dead·created·restarting·paused
	image  string // Config.Image — 컨테이너 생성에 쓰인 이미지 참조(우리가 준 참조)
}

func (s containerState) running() bool { return s.status == "running" }

// inspectState는 한 컨테이너의 상태·이미지를 한 번의 inspect로 읽는다(부작용 없는 조회).
// {{.State.Status}}로 실행중/종료를 구분하고, {{.Config.Image}}로 우리가 준 참조와 대조한다.
// 상태·이미지 참조 모두 공백을 포함하지 않으므로 첫 공백으로 안전하게 가른다.
// ⚠️ [구현 검증]: docker가 {{.Config.Image}}로 digest 참조를 그대로 돌려주는지(vs 정규화·
// image ID)와 {{.State.Status}} 문자열 값은 리허설에서 재확인한다 — 불일치 시 실제 값이
// 판정·error에 그대로 드러난다. {{.Image}}(config ID)는 manifest digest와 다른 해시라
// 직접 대조에 쓸 수 없다.
func (e *Executor) inspectState(ctx context.Context, id string) (containerState, error) {
	argv := e.cfg.commandLine("docker", "inspect", "-f", "{{.State.Status}} {{.Config.Image}}", id)
	out, err := e.run(ctx, argv, nil, e.stdin())
	if err != nil {
		return containerState{}, fmt.Errorf("dispatch: 컨테이너 상태 조회 실패(inspect %s): %w", id, err)
	}
	status, image, _ := strings.Cut(strings.TrimSpace(out), " ")
	return containerState{id: id, status: strings.TrimSpace(status), image: strings.TrimSpace(image)}, nil
}

// VerifyImageDigest는 green 프로젝트의 사후조건을 증명한다(DO-16 ⑶ — "기대 digest의
// 컨테이너가 돌고 있다"). 세 갈래로 본다:
//   - P1 부분기동 검출: 프로젝트에 종료/실패(running이 아닌) 컨테이너가 있으면 실패한다 —
//     up 직후 worker가 종료됐는데 app만 2xx면 부분기동인데도 COMPLETED로 위장하므로,
//     기대 서비스가 전부 running일 때만 통과한다. ⚠️ 가정: compose가 정상 종료하는
//     one-shot init 컨테이너를 쓰면 이 모델 밖이다(그 경우 그 서비스는 별도로 다뤄야 한다).
//   - P6 이미지 대조: 실행중 컨테이너 중 ≥1개의 Config.Image가 pinned digest 참조와 같으면
//     app이 그 digest로 떴음이 증명된다. 다른 이미지의 사이드카·orphan은 실패시키지 않는다
//     (all-match 요구는 정상 배포를 오탐했다). 실행중 일치가 0개면(엉뚱 이미지 — :latest·
//     env 오타) 실패하며, 기대 참조를 error에 담는다.
//
// 뜬 컨테이너가 없거나(증명 불가)·조회 실패·부분기동·불일치면 오류다.
func (e *Executor) VerifyImageDigest(ctx context.Context, imageRef string) error {
	ids, err := e.projectContainerIDs(ctx)
	if err != nil {
		return fmt.Errorf("dispatch: 이미지 대조 불가(컨테이너 조회 실패): %w", err)
	}
	if len(ids) == 0 {
		return fmt.Errorf("dispatch: green 컨테이너가 없다 — 사후조건으로 pinned digest(%s) 실행을 증명할 수 없다", imageRef)
	}
	var running []containerState
	var stopped []string
	for _, id := range ids {
		st, gerr := e.inspectState(ctx, id)
		if gerr != nil {
			return fmt.Errorf("dispatch: 이미지 대조 불가: %w", gerr)
		}
		if st.running() {
			running = append(running, st)
		} else {
			stopped = append(stopped, fmt.Sprintf("%s(%s)", st.id, st.status))
		}
	}
	// P1: 종료/실패 컨테이너가 하나라도 있으면 부분기동 — 실패(silent COMPLETED 차단).
	if len(stopped) > 0 {
		return fmt.Errorf("dispatch: 부분기동 — 종료/실패 컨테이너가 있다(기대 서비스가 전부 running이어야 한다): %v", stopped)
	}
	// P6: 실행중 컨테이너 중 하나라도 pinned digest면 app이 그 digest로 떴음이 증명된다.
	for _, st := range running {
		if st.image == imageRef {
			return nil
		}
	}
	var got []string
	for _, st := range running {
		got = append(got, st.image)
	}
	return fmt.Errorf("dispatch: 실행 이미지가 pinned digest와 불일치 — 실행중 컨테이너 중 기대=%q 일치 0개, 실제=%v", imageRef, got)
}

// osExec는 기본 러너다. argv[0]를 실행 파일로, 나머지를 인자 슬라이스로 넘겨 셸 해석을
// 거치지 않는다(DO-23 ⑴). stdin이 비어있지 않을 때만 child stdin에 흘린다.
func osExec(ctx context.Context, argv []string, env []string, stdin string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("dispatch: 빈 argv — 실행 불가")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		return out, fmt.Errorf("dispatch: 명령 실패(%s): %w · 출력=%s", argv[0], err, out)
	}
	return out, nil
}
