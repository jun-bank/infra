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
	// AppService는 이 배포의 대상 app compose 서비스명이다(#21 — 사후조건 identity 결박).
	// 컨테이너의 소속 서비스는 docker가 붙이는 composeServiceLabel 라벨로 식별하며, 이 값이
	// 설정되면 사후조건(이미지 대조·부분기동 판정)과 재시작 검사가 **그 서비스의 컨테이너만**
	// 본다. 비면 프로젝트 전체를 보는 기존 판정 그대로다(하위호환 — 단일 경로 모드의 선택
	// 설정이며, 블루-그린 모드에서는 main이 기동 시 필수로 강제한다).
	AppService string
}

// composeServiceLabel은 docker compose가 각 컨테이너에 붙이는 서비스명 라벨이다 — 컨테이너가
// 어느 compose 서비스의 것인지를 말하는 정본이다(compose 프로젝트 라벨과 짝). 컨테이너명
// 규칙(<project>-<service>-<n>)을 문자열로 파싱하지 않는 이유가 이것이다: 이름 규칙은
// compose 버전·container_name 설정에 따라 흔들리지만 이 라벨은 compose가 소유하는 계약이다.
// ⚠️ [구현 검증] 해소 근거 = .9 호스트 실측(이슈 #21 기록): core-green-app-1 컨테이너의 이
// 라벨 값이 "app"으로 확인됐다 — 현 .9 compose 구조의 대상 서비스명은 "app"이다. 호스트
// compose 구조가 바뀌면 DEPLOY_APP_SERVICE 값도 함께 바뀐다(잔여-6/#19와 같은 축).
const composeServiceLabel = "com.docker.compose.service"

// defaultImageEnvVar는 ImageEnvVar 미지정 시의 기본 env 변수명이다.
const defaultImageEnvVar = "DEPLOY_IMAGE_REF"

// composeImagePlaceholder는 image가 무관한 compose 하위 명령(down·ps·status)이 프로젝트를
// 파싱하도록 image env에 넣는 비어있지 않은 값이다. compose 파일의 image: ${VAR} 는 프로젝트
// 로드 시 모든 서비스의 image/build를 먼저 검증하므로, VAR가 비면 "invalid compose project"로
// 명령이 컨테이너를 건드리기도 전에 실패한다(통합 실측 — troubleshooting-false-unknown.md).
// 이 명령들은 기존 컨테이너를 프로젝트 라벨로 다루므로 image 값 자체는 실행에 쓰이지 않는다 —
// 파싱만 되면 되고, pull되지 않을 값으로 두어 오용을 눈에 띄게 한다. up은 별도로 실제 pinned
// digest를 주입한다(digest 고정은 up이 늘 실주입하므로 유지된다).
const composeImagePlaceholder = "noncreate.invalid/unused:noncreate-ops-only"

// imageEnvVar는 설정된 env 변수명(없으면 기본)을 준다.
func (c Config) imageEnvVar() string {
	if c.ImageEnvVar == "" {
		return defaultImageEnvVar
	}
	return c.ImageEnvVar
}

// composeEnv는 image-무관 compose 명령(down·ps·status)에 주입할 image env를 만든다.
// up이 실제 digest를 주입하는 것과 짝을 이뤄, 모든 compose 명령이 프로젝트를 파싱할 수 있게
// 한다(imageEnvVar는 기본값이 있어 항상 비어있지 않다). 실행 대상 컨테이너는 프로젝트 라벨로
// 정해지므로 여기 image 값(placeholder)은 어떤 컨테이너도 만들거나 pull하지 않는다.
func (c Config) composeEnv() []string {
	return []string{c.imageEnvVar() + "=" + composeImagePlaceholder}
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
		// --remove-orphans: 이전 revision의 orphan을 제거한다(위생 — 남은 컨테이너가 포트·
		// 볼륨을 붙들지 않게). 사후조건 fail-open(H2)의 방어는 더 이상 이 플래그에 기대지
		// 않는다 — VerifyImageDigest가 대상 app 서비스로 결박돼(#21) orphan·사이드카가 무엇을
		// 실행 중이든 app의 일치를 대신해 주지 못한다.
		return c.commandLine("docker", "compose", "-f", c.ComposeFile, "-p", c.Project, "up", "-d", "--no-build", "--remove-orphans"), nil
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

// AppService는 이 실행기가 결박된 대상 app compose 서비스명이다(비면 결박 없음 — 프로젝트
// 전체 판정). 읽기 전용 접근자이며, 조립(env → Config) 배선이 실제로 이어졌는지 boot 테스트가
// 관측하기 위해 있다 — 결박이 조용히 끊기면 H2 fail-open이 그대로 되돌아온다(#21).
func (e *Executor) AppService() string { return e.cfg.AppService }

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
	// image-무관 명령이지만 compose 파일이 ${VAR}를 프로젝트 로드 시 검증하므로 env를 준다
	// (없으면 "invalid compose project"로 정리가 실패해 false-UNKNOWN이 된다 — 통합 실측).
	_, err = e.run(ctx, argv, e.cfg.composeEnv(), e.stdin())
	return err
}

// Status는 부작용 없는 상태 조회다(DO-16). 조립된 출력을 그대로 준다.
func (e *Executor) Status(ctx context.Context) (string, error) {
	argv, err := e.cfg.argv(ActionStatus, "")
	if err != nil {
		return "", err
	}
	return e.run(ctx, argv, e.cfg.composeEnv(), e.stdin())
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

// GreenContainers는 CD-1 재시작 검사(그린 위장 방어)의 대상 컨테이너 ID 목록을 준다
// (docker compose ps -q — 부작용 없는 조회). 컨테이너명을 설정에 하드코딩하지 않고 compose
// 프로젝트에서 파생해, 검사가 항상 실제 뜬 컨테이너를 대상으로 하게 한다. 빈 목록은 오류가
// 아니라 빈 슬라이스로 준다 — 판정은 호출자가 한다(health가 0개면 fail-closed로 닫는다).
//
// AppService가 설정되면 사후조건과 **같은 결박**을 적용해 대상 app 서비스의 컨테이너만
// 본다(#21). ⚠️ 트레이드오프(의도한 축소): 그린 위장 방어의 원래 의도는 "어느 컨테이너든
// 재시작하면 감지"였고, 이 축소로 **사이드카·one-shot의 재시작은 더 이상 헬스를 실패시키지
// 않는다**. 그 대가를 지는 이유는 판정 대상이 앱이기 때문이다 — 사이드카 재시작은 앱이
// 준비됐는지와 무관한데도 정상 배포를 반복 실패시켰고(M1과 같은 오탐 축), 반대로 방어가
// 실제로 막아야 하는 것(재시작 정책이 죽은 **앱** 프로세스를 되살려 연속 2xx를 다른
// 프로세스의 성공으로 이어붙이는 것)은 앱 서비스 안에서 전부 관측된다. 앱 서비스의 재시작은
// 여전히 baseline 대비 증가로 즉시 실패시킨다(방어선 자체는 그대로 켜져 있다).
func (e *Executor) GreenContainers(ctx context.Context) ([]string, error) {
	argv := e.cfg.commandLine("docker", "compose", "-f", e.cfg.ComposeFile, "-p", e.cfg.Project, "ps", "-q")
	out, err := e.run(ctx, argv, e.cfg.composeEnv(), e.stdin())
	if err != nil {
		return nil, fmt.Errorf("dispatch: green 컨테이너 조회 실패(compose ps -q): %w", err)
	}
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			ids = append(ids, s)
		}
	}
	if e.cfg.AppService == "" || len(ids) == 0 {
		return ids, nil
	}
	states, serr := e.targetStates(ctx, ids)
	if serr != nil {
		// 소속 서비스를 확정하지 못하면 대상을 좁힐 수 없다 — 조용히 전체로 넓히지 않고
		// 오류를 낸다(health가 fail-closed로 받는다).
		return nil, fmt.Errorf("dispatch: green 컨테이너 서비스 식별 실패(재시작 검사 대상 확정 불가): %w", serr)
	}
	var target []string
	for _, st := range states {
		target = append(target, st.id)
	}
	return target, nil
}

// projectContainerIDs는 green 프로젝트의 모든 컨테이너 ID를 준다(docker compose ps -a -q
// — 부작용 없는 조회). ps -q(실행중만)와 달리 -a로 종료·실패 컨테이너까지 포함해, 사후조건
// 판정이 부분기동(일부 서비스가 up 직후 종료)을 검출할 수 있게 한다(P1). 빈 목록은 오류가
// 아니라 빈 슬라이스로 준다 — 판정은 호출자가 한다.
func (e *Executor) projectContainerIDs(ctx context.Context) ([]string, error) {
	argv := e.cfg.commandLine("docker", "compose", "-f", e.cfg.ComposeFile, "-p", e.cfg.Project, "ps", "-a", "-q")
	out, err := e.run(ctx, argv, e.cfg.composeEnv(), e.stdin())
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

// containerState는 한 컨테이너의 실행 상태·이미지 참조·소속 compose 서비스다(사후조건 판정 입력).
type containerState struct {
	id      string
	status  string // docker State.Status: running·exited·dead·created·restarting·paused
	image   string // Config.Image — 컨테이너 생성에 쓰인 이미지 참조(우리가 준 참조)
	service string // composeServiceLabel 값 — 이 컨테이너가 어느 compose 서비스의 것인가(#21)
}

func (s containerState) running() bool { return s.status == "running" }

// inspectStateFormat은 상태·이미지·서비스 라벨을 공백으로 이어 한 줄로 내는 inspect 포맷이다.
// 세 값 모두 공백을 포함하지 않으므로(상태는 열거값, 이미지 참조·compose 서비스명은 공백 불가)
// 공백 분해가 안전하다. 라벨이 없는 컨테이너는 세 번째 칸이 빈 문자열이 된다(text/template의
// index는 없는 키에 zero value를 준다) — 그 컨테이너는 "서비스 미상"으로 다뤄진다.
const inspectStateFormat = "{{.State.Status}} {{.Config.Image}} {{index .Config.Labels \"" + composeServiceLabel + "\"}}"

// inspectState는 한 컨테이너의 상태·이미지·소속 서비스를 한 번의 inspect로 읽는다(부작용
// 없는 조회). {{.State.Status}}로 실행중/종료를 구분하고, {{.Config.Image}}로 우리가 준
// 참조와 대조하며, 서비스 라벨로 "이 배포의 대상 app인가"를 가른다(#21 identity 결박).
// ⚠️ [구현 검증]: docker가 {{.Config.Image}}로 digest 참조를 그대로 돌려주는지(vs 정규화·
// image ID)와 {{.State.Status}} 문자열 값은 리허설에서 재확인한다 — 불일치 시 실제 값이
// 판정·error에 그대로 드러난다. {{.Image}}(config ID)는 manifest digest와 다른 해시라
// 직접 대조에 쓸 수 없다.
func (e *Executor) inspectState(ctx context.Context, id string) (containerState, error) {
	argv := e.cfg.commandLine("docker", "inspect", "-f", inspectStateFormat, id)
	out, err := e.run(ctx, argv, nil, e.stdin())
	if err != nil {
		return containerState{}, fmt.Errorf("dispatch: 컨테이너 상태 조회 실패(inspect %s): %w", id, err)
	}
	st := containerState{id: id}
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) > 0 {
		st.status = f[0]
	}
	if len(f) > 1 {
		st.image = f[1]
	}
	if len(f) > 2 {
		st.service = f[2]
	}
	return st, nil
}

// targetStates는 컨테이너 ID들을 inspect해 **이 배포의 대상 서비스**의 것만 준다(#21).
// AppService가 비면 전부 준다 — 결박 없는 기존 전체 판정 그대로다(하위호환).
// 소속 판정은 composeServiceLabel 하나이며, 라벨이 없는 컨테이너는 대상이 아니다(결박이
// 켜졌는데 소속을 증명하지 못하는 컨테이너를 대상으로 세면 결박이 무의미해진다).
func (e *Executor) targetStates(ctx context.Context, ids []string) ([]containerState, error) {
	var out []containerState
	for _, id := range ids {
		st, err := e.inspectState(ctx, id)
		if err != nil {
			return nil, err
		}
		if e.cfg.AppService != "" && st.service != e.cfg.AppService {
			continue
		}
		out = append(out, st)
	}
	return out, nil
}

// VerifyImageDigest는 사후조건을 증명한다(DO-16 ⑶ — "기대 digest의 컨테이너가 돌고 있다").
// 판정 대상은 **이 배포의 대상 app 서비스 컨테이너**다(#21 identity 결박 — AppService가
// 설정된 경우). 프로젝트 전체가 아니라 대상 서비스만 보는 것이 두 결함의 근원을 함께 닫는다:
//   - H2(fail-open) 닫힘: 사이드카·orphan이 우연히 pinned digest를 실행 중이어도 그것이
//     app의 ≥1-match를 대신해 주지 못한다 — app 서비스가 :latest·env 오타로 틀린 이미지를
//     실행 중이면 실패한다(엉뚱한 이미지가 COMPLETED로 기록되던 경로).
//   - M1(오탐) 닫힘: 정상 종료하는 one-shot/init 컨테이너나 정지 orphan은 다른 서비스이므로
//     부분기동 판정에 들지 않는다 — 정상 배포를 미전환으로 오판하지 않는다.
//
// 갈래는 셋이다:
//   - ⑴ 이미지 대조: 대상 서비스의 **실행중** 컨테이너 중 ≥1개의 Config.Image가 pinned
//     digest 참조와 같아야 한다(app이 여러 replica면 하나만 맞아도 그 digest 실행이 증명된다).
//     일치 0개면 실패하며 기대 참조와 실제 값을 error에 담는다.
//   - ⑵ 부분기동 검출: 대상 서비스에 종료/실패(running이 아닌) 컨테이너가 있으면 실패한다 —
//     app이 up 직후 죽었는데 다른 replica·프로브만 살아 통과하는 silent COMPLETED를 막는다.
//   - ⑶ 대상 서비스 컨테이너가 0개면 실패한다 — 증명 불가는 통과가 아니다(기존 계약 유지).
//
// AppService가 비면(단일 경로 모드에서 미설정) 프로젝트 전체를 보던 기존 판정 그대로다 —
// 그 환경에는 위 H2·M1 잔여가 남는다(main이 기동 로그로 그 사실을 알린다).
func (e *Executor) VerifyImageDigest(ctx context.Context, imageRef string) error {
	ids, err := e.projectContainerIDs(ctx)
	if err != nil {
		return fmt.Errorf("dispatch: 이미지 대조 불가(컨테이너 조회 실패): %w", err)
	}
	if len(ids) == 0 {
		return fmt.Errorf("dispatch: green 컨테이너가 없다 — 사후조건으로 pinned digest(%s) 실행을 증명할 수 없다", imageRef)
	}
	states, err := e.targetStates(ctx, ids)
	if err != nil {
		return fmt.Errorf("dispatch: 이미지 대조 불가: %w", err)
	}
	// ⑶ 대상 서비스의 컨테이너가 하나도 없다 = 배포 대상이 뜨지 않았다(사이드카만 떠 있어도
	//    통과시키지 않는다 — 증명 불가는 실패다).
	if len(states) == 0 {
		return fmt.Errorf("dispatch: 대상 서비스(%s=%q)의 컨테이너가 프로젝트에 없다(프로젝트 컨테이너 %d개) — 사후조건으로 pinned digest(%s) 실행을 증명할 수 없다", composeServiceLabel, e.cfg.AppService, len(ids), imageRef)
	}
	var running []containerState
	var stopped []string
	for _, st := range states {
		if st.running() {
			running = append(running, st)
		} else {
			stopped = append(stopped, fmt.Sprintf("%s(%s)", st.id, st.status))
		}
	}
	// ⑵ 대상 서비스에 종료/실패 컨테이너가 있으면 부분기동 — 실패(silent COMPLETED 차단).
	if len(stopped) > 0 {
		return fmt.Errorf("dispatch: 부분기동 — 대상 서비스(%q)에 종료/실패 컨테이너가 있다(대상 서비스가 전부 running이어야 한다): %v", e.cfg.AppService, stopped)
	}
	// ⑴ 대상 서비스의 실행중 컨테이너 중 하나라도 pinned digest면 그 digest 실행이 증명된다.
	for _, st := range running {
		if st.image == imageRef {
			return nil
		}
	}
	var got []string
	for _, st := range running {
		got = append(got, st.image)
	}
	return fmt.Errorf("dispatch: 실행 이미지가 pinned digest와 불일치 — 대상 서비스(%q)의 실행중 컨테이너 중 기대=%q 일치 0개, 실제=%v", e.cfg.AppService, imageRef, got)
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
