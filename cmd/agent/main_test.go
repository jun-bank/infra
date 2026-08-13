// cmd/agent의 ROLE 분기 단위 테스트. 서버를 실제로 띄우지 않고 역할 해석만
// 검증한다 — ROLE 미설정·미지원이면 기동을 거부하는 fail-closed 방향이 핵심이다
// (ADR-027 DO-21).
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/dispatch"
)

// C5/C6·P3·P4: 배포 창 락 lease가 dispatch 전체 소요(phaseBudget + 헬스 deadline D +
// cleanup + slack)를 덮지 못하면 시동을 거부해야 한다(fail-closed) — lease=1s 같은 footgun을
// 기동 시 차단한다. dispatch 중 lease 갱신이 없으므로(CD-3 무갱신 모델), lease가 짧으면
// 실행 중 락이 만료돼 다른 주체가 stale 락을 회수하고, A의 cleanup down이 B의 green을 철거한다.
func TestLeaseCoversDispatch(t *testing.T) {
	phase := 120 * time.Second // pull+up 상한
	d := 60 * time.Second      // 헬스 deadline D
	min := phase + d + deploy.CleanupTimeout + dispatchLeaseSlack

	// 미달 — 거부.
	for _, lease := range []time.Duration{
		time.Second,           // footgun
		d,                     // D만으로는 부족
		phase + d,             // cleanup+slack 누락
		min - time.Nanosecond, // 경계 바로 아래
	} {
		if err := leaseCoversDispatch(lease, phase, d, 0); err == nil {
			t.Errorf("lease=%s < min=%s 인데 통과(fail-closed 위반)", lease, min)
		}
	}

	// 충분 — 통과.
	for _, lease := range []time.Duration{
		min,
		min + time.Second,
		10 * time.Minute,
	} {
		if err := leaseCoversDispatch(lease, phase, d, 0); err != nil {
			t.Errorf("lease=%s >= min=%s 인데 거부: %v", lease, min, err)
		}
	}
}

// BG-4: 전환(⑤⑥⑨)은 락 보유 단계이므로 lease 하한식에 그 예산이 들어가야 한다 — 전환 없이
// 통과하던 lease가 전환 예산이 붙으면 거부돼야 한다(그러지 않으면 드레인·구 slot 종료가 락
// 만료 뒤 실행돼, 다른 배포가 잡은 슬롯을 이 배포의 down이 철거할 수 있다).
func TestLeaseCoversDispatchIncludesCutover(t *testing.T) {
	phase, d := 120*time.Second, 60*time.Second
	base := phase + d + deploy.CleanupTimeout + dispatchLeaseSlack
	cutover, err := cutoverBudget(defaultGatewayTimeout, defaultDrainWait)
	if err != nil {
		t.Fatalf("기본값으로 전환 예산 산정 실패: %v", err)
	}
	if cutover <= 0 {
		t.Fatalf("전환 예산이 0 이하다: %s", cutover)
	}
	// 전환 없으면 딱 맞던 lease가, 전환 단계가 붙으면 미달이어야 한다.
	if err := leaseCoversDispatch(base, phase, d, 0); err != nil {
		t.Fatalf("전환 없음·경계 lease인데 거부: %v", err)
	}
	if err := leaseCoversDispatch(base, phase, d, cutover); err == nil {
		t.Fatalf("전환 예산(%s)이 붙었는데 같은 lease(%s)가 통과 — 전환이 락 밖으로 새어나간다(fail-open)", cutover, base)
	}
	if err := leaseCoversDispatch(base+cutover, phase, d, cutover); err != nil {
		t.Fatalf("lease가 전환 예산까지 덮는데 거부: %v", err)
	}
}

// 기본 설정끼리 자기정합해야 한다 — 기본 lease가 기본 phaseBudget+D+cleanup+(전환)+slack를
// 덮지 못하면, 아무 env도 안 준 운영자의 agent가 leaseCoversDispatch에서 fail-closed로
// 기동하지 못한다. 기본값을 바꿀 때 이 정합성이 깨지지 않게 막는다 — 게이트웨이 미설정
// (전환 예산 0)과 설정(기본 전환 예산) 양쪽 모두.
func TestDefaultConfigLeaseCoversDispatch(t *testing.T) {
	if err := leaseCoversDispatch(defaultDeployLease, defaultDispatchPhaseBudget, defaultHealthDeadline, 0); err != nil {
		t.Fatalf("기본 설정이 자기정합하지 않다(게이트웨이 미설정 · 기본값으로 기동 불가): %v", err)
	}
	cutover, err := cutoverBudget(defaultGatewayTimeout, defaultDrainWait)
	if err != nil {
		t.Fatalf("기본값으로 전환 예산 산정 실패: %v", err)
	}
	if err := leaseCoversDispatch(defaultDeployLease, defaultDispatchPhaseBudget, defaultHealthDeadline, cutover); err != nil {
		t.Fatalf("기본 설정이 자기정합하지 않다(블루-그린 · 기본값으로 기동 불가): %v", err)
	}
}

// S6: 전환 예산은 **합산 전에** 항별로 상한돼야 한다 — 거대 게이트웨이 타임아웃·드레인이
// 2*gatewayTimeout+drainWait을 int64 overflow로 음수(또는 작은 양수)로 접으면, 그 예산이
// leaseCoversDispatch의 [0, max] 검사를 통과해 하한식 전체가 fail-open이 된다.
func TestCutoverBudgetRejectsExtremeTerms(t *testing.T) {
	overflowing := []struct {
		name      string
		gw, drain time.Duration
	}{
		{"게이트웨이 타임아웃 0", 0, defaultDrainWait},
		{"드레인 0", defaultGatewayTimeout, 0},
		{"게이트웨이 타임아웃 음수", -time.Second, defaultDrainWait},
		{"게이트웨이 타임아웃 상한 초과", maxDispatchDuration + time.Second, defaultDrainWait},
		{"드레인 상한 초과", defaultGatewayTimeout, maxDispatchDuration + time.Second},
		// 합이 뒤집히는 값 — 항별 검증이 없으면 2*gw가 음수가 되어 작은 예산으로 위장한다.
		{"overflow 유발 타임아웃", time.Duration(1<<62) + time.Hour, defaultDrainWait},
		{"overflow 유발 드레인", defaultGatewayTimeout, time.Duration(1<<62) + time.Hour},
	}
	for _, c := range overflowing {
		t.Run(c.name, func(t *testing.T) {
			got, err := cutoverBudget(c.gw, c.drain)
			if err == nil {
				t.Fatalf("%s인데 통과(예산=%s) — 합산 전 항별 상한이 없다(fail-open)", c.name, got)
			}
		})
	}
	// 정상 범위는 그대로 합산된다(검사가 유효 범위를 좁히지 않는다).
	got, err := cutoverBudget(5*time.Second, 20*time.Second)
	if err != nil || got != 2*5*time.Second+20*time.Second+deploy.CleanupTimeout {
		t.Fatalf("정상 항: 예산=%s err=%v", got, err)
	}
}

// S6(연결): 극단 env가 들어오면 기동 자체가 거부돼야 한다 — 예산 산정이 조립 경로에 있으므로
// 런타임까지 숨지 않는다.
func TestBuildDispatcherRejectsExtremeCutoverEnv(t *testing.T) {
	cases := []struct{ name, key, val string }{
		{"거대 드레인", "DEPLOY_DRAIN_WAIT", "2562047h"},
		{"거대 게이트웨이 타임아웃", "DEPLOY_GATEWAY_TIMEOUT", "2562047h"},
		{"상한 초과 드레인", "DEPLOY_DRAIN_WAIT", "2h"},
		{"상한 초과 게이트웨이 타임아웃", "DEPLOY_GATEWAY_TIMEOUT", "90m"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setBlueGreenEnv(t)
			t.Setenv(c.key, c.val)
			if _, err := buildDispatcher(); err == nil {
				t.Fatalf("%s(%s=%q)인데 기동 통과 — 전환 예산 overflow 경로가 열린다", c.name, c.key, c.val)
			}
		})
	}
}

// H3: 거대 duration이 하한식 덧셈을 int64 overflow로 음수로 뒤집어 작은 lease가 검증을
// 통과(fail-open)하면 안 된다. 상한(maxDispatchDuration)을 넘는 phaseBudget·healthDeadline은
// 거부한다 — overflow 재현: 각각을 int64 최대의 절반 이상으로 두면 합이 음수가 된다.
func TestLeaseCoversDispatchRejectsOverflow(t *testing.T) {
	huge := time.Duration(1<<62) + time.Hour // maxDispatchDuration을 크게 넘고, 둘을 더하면 overflow
	// 작은 lease인데도 overflow로 통과해선 안 된다(fail-closed).
	if err := leaseCoversDispatch(time.Second, huge, huge, 0); err == nil {
		t.Fatalf("거대 phaseBudget·healthDeadline(overflow 유발)인데 작은 lease가 통과 — fail-open")
	}
	// 상한을 살짝 넘는 값도 거부.
	if err := leaseCoversDispatch(24*time.Hour, maxDispatchDuration+time.Second, defaultHealthDeadline, 0); err == nil {
		t.Fatalf("phaseBudget이 상한 초과인데 통과 — fail-closed 위반")
	}
	// 전환 예산도 같은 가드를 받는다(거대 드레인 값이 덧셈을 뒤집지 못한다).
	if err := leaseCoversDispatch(time.Second, defaultDispatchPhaseBudget, defaultHealthDeadline, huge); err == nil {
		t.Fatalf("거대 전환 예산(overflow 유발)인데 작은 lease가 통과 — fail-open")
	}
}

// P8: 헬스·phaseBudget env가 설정됐으나 파싱 불가·범위 위반이면 boot에서 거부해야 한다
// (fail-fast) — 조용히 기본값으로 삼켜 잘못된 튜닝이 런타임까지 숨는 것을 막는다.
func setRequiredDispatchEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOY_COMPOSE_FILE", "/x/compose.yml")
	t.Setenv("DEPLOY_COMPOSE_PROJECT", "core-green")
	t.Setenv("DEPLOY_HEALTH_URL", "http://127.0.0.1:8080/ready")
	t.Setenv("IMAGE_CORE", "registry.example/core")
	// 동봉이 기본이므로 CP-3의 호스트 값과 image 변수명은 기동 필수다(E-4).
	t.Setenv("DEPLOY_APP_SERVICE", "app")
	t.Setenv("DEPLOY_IMAGE_ENV", "CORE_IMAGE")
	setWorkspaceEnv(t)
}

// setWorkspaceEnv는 배타성 계약(절대경로·심볼릭 링크 없음·0700·현재 uid 소유)을 만족하는
// workspace를 만들어 배선한다. 신 agent의 기본이 동봉 필수(R7)라 이것 없이는 어떤 배포
// 배선도 조립되지 않는다 — 그 사실 자체가 기본값이 살아 있다는 증거다.
func setWorkspaceEnv(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "ws")
	if mkErr := os.Mkdir(root, 0o700); mkErr != nil {
		t.Fatal(mkErr)
	}
	t.Setenv("DEPLOY_WORKSPACE", root)
	return root
}

func TestBuildDispatcherRejectsInvalidHealthEnv(t *testing.T) {
	cases := []struct{ name, key, val string }{
		{"비정수 N", "DEPLOY_HEALTH_SUCCESS_THRESHOLD", "abc"},
		{"N<1", "DEPLOY_HEALTH_SUCCESS_THRESHOLD", "0"},
		{"비duration interval", "DEPLOY_HEALTH_INTERVAL", "3x"},
		{"음수 deadline", "DEPLOY_HEALTH_DEADLINE", "-1s"},
		{"0 timeout", "DEPLOY_HEALTH_TIMEOUT", "0s"},
		{"비duration phaseBudget", "DEPLOY_DISPATCH_PHASE_BUDGET", "nope"},
		{"음수 phaseBudget", "DEPLOY_DISPATCH_PHASE_BUDGET", "-5s"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setRequiredDispatchEnv(t)
			t.Setenv(c.key, c.val)
			if _, err := buildDispatcher(); err == nil {
				t.Fatalf("%s(%s=%q)인데 buildDispatcher 통과(boot fail-fast 위반)", c.name, c.key, c.val)
			}
		})
	}
}

func TestBuildDispatcherAcceptsValidEnv(t *testing.T) {
	setRequiredDispatchEnv(t)
	t.Setenv("DEPLOY_HEALTH_SUCCESS_THRESHOLD", "3")
	t.Setenv("DEPLOY_HEALTH_DEADLINE", "45s")
	t.Setenv("DEPLOY_DISPATCH_PHASE_BUDGET", "90s")
	b, err := buildDispatcher()
	if err != nil || b.healthDeadline != 45*time.Second || b.phaseBudget != 90*time.Second {
		t.Fatalf("정상 env: err=%v D=%s phaseBudget=%s, nil·45s·90s 기대", err, b.healthDeadline, b.phaseBudget)
	}
	// 게이트웨이 미설정 = 전환 단계 없음 = 전환 예산 0(기존 동작 그대로).
	if b.cutoverBudget != 0 {
		t.Fatalf("게이트웨이 미설정인데 전환 예산=%s, 0 기대", b.cutoverBudget)
	}
}

// setBlueGreenEnv는 블루-그린 모드의 슬롯별 필수 env를 채운다(단일 변수는 두지 않는다 —
// 게이트웨이 모드에서 단일 변수는 선택이다).
func setBlueGreenEnv(t *testing.T) {
	t.Helper()
	t.Setenv("IMAGE_CORE", "registry.example/core")
	t.Setenv("DEPLOY_GATEWAY_URL", "http://127.0.0.1:8090")
	t.Setenv("GATEWAY_INTERNAL_HMAC_KEY", "test-internal-key-not-a-secret") // R4 — gatewayURL 설정 시 필수
	t.Setenv("DEPLOY_APP_SERVICE", "app")                                   // #21 — 블루-그린 모드에서는 필수
	t.Setenv("DEPLOY_IMAGE_ENV", "CORE_IMAGE")                              // E-4 — 동봉 필수 배선에서는 기동 필수
	setWorkspaceEnv(t)
	t.Setenv("DEPLOY_HOST_PORT_BLUE", "18081")
	t.Setenv("DEPLOY_HOST_PORT_GREEN", "18082")

	t.Setenv("DEPLOY_COMPOSE_FILE_BLUE", "/x/blue.yml")
	t.Setenv("DEPLOY_COMPOSE_PROJECT_BLUE", "core-blue")
	t.Setenv("DEPLOY_HEALTH_URL_BLUE", "http://127.0.0.1:8081/ready")
	t.Setenv("DEPLOY_COMPOSE_FILE_GREEN", "/x/green.yml")
	t.Setenv("DEPLOY_COMPOSE_PROJECT_GREEN", "core-green")
	t.Setenv("DEPLOY_HEALTH_URL_GREEN", "http://127.0.0.1:8082/ready")
}

// 블루-그린 모드는 슬롯별 설정으로 조립되고 전환 예산이 lease 하한식에 실린다.
func TestBuildDispatcherBlueGreen(t *testing.T) {
	setBlueGreenEnv(t)
	t.Setenv("DEPLOY_DRAIN_WAIT", "20s")
	t.Setenv("DEPLOY_GATEWAY_TIMEOUT", "5s")
	b, err := buildDispatcher()
	if err != nil {
		t.Fatalf("블루-그린 정상 env인데 조립 실패: %v", err)
	}
	want, werr := cutoverBudget(5*time.Second, 20*time.Second)
	if werr != nil {
		t.Fatalf("전환 예산 산정 실패: %v", werr)
	}
	if b.cutoverBudget != want {
		t.Fatalf("전환 예산=%s, 기대 %s", b.cutoverBudget, want)
	}
	d, ok := b.disp.(deploy.LocalDispatcher)
	if !ok {
		t.Fatalf("dispatcher 타입=%T, LocalDispatcher 기대", b.disp)
	}
	if d.Gateway == nil || d.SlotExec[deploy.SlotBlue] == nil || d.SlotExec[deploy.SlotGreen] == nil ||
		d.SlotHealth[deploy.SlotBlue] == nil || d.SlotHealth[deploy.SlotGreen] == nil {
		t.Fatal("블루-그린 배선 누락(게이트웨이·슬롯별 실행기·프로버가 모두 있어야 한다)")
	}
	if d.DrainWait != 20*time.Second {
		t.Fatalf("드레인 대기=%s, 20s 기대", d.DrainWait)
	}
	// 단일 변수를 안 줬으므로 단일 경로(target=gateway 전용)는 배선되지 않는다 —
	// 그 배포는 실행 지점에서 요란하게 거절된다(조용한 성공 아님).
	if d.Exec != nil || d.Health != nil {
		t.Fatal("단일 변수 미설정인데 단일 경로가 배선됐다")
	}
}

// setSingleVars는 단일 경로(target=gateway 전용) 변수 셋을 채운다 — project 이름만 바꿔가며
// 프로젝트 유일성 검사를 두드리기 위한 헬퍼다.
func setSingleVars(t *testing.T, project string) {
	t.Helper()
	t.Setenv("DEPLOY_COMPOSE_FILE", "/x/compose.yml")
	t.Setenv("DEPLOY_COMPOSE_PROJECT", project)
	t.Setenv("DEPLOY_HEALTH_URL", "http://127.0.0.1:8080/ready")
	t.Setenv("DEPLOY_HOST_PORT", "18080")
}

// S9: compose project는 single·blue·green 3자 **쌍별로** 달라야 한다 — down이 프로젝트
// 단위라, 겹치면 한쪽의 종료·정리 down이 다른 쪽 컨테이너를 철거한다(게이트웨이 배포의
// down이 core 슬롯을 내리는 경로가 그것이다).
func TestBuildDispatcherRejectsDuplicateComposeProjects(t *testing.T) {
	dup := []struct{ name, single string }{
		{"단일 = blue", "core-blue"},
		{"단일 = green", "core-green"},
	}
	for _, c := range dup {
		t.Run(c.name, func(t *testing.T) {
			setBlueGreenEnv(t)
			setSingleVars(t, c.single)
			if _, err := buildDispatcher(); err == nil {
				t.Fatalf("%s(project=%q)인데 기동 통과 — 한쪽 down이 다른 쪽을 철거한다", c.name, c.single)
			}
		})
	}

	// 셋이 서로 다르면 정상 조립된다(검사가 정당한 설정을 막지 않는다).
	setBlueGreenEnv(t)
	setSingleVars(t, "core-single")
	if _, err := buildDispatcher(); err != nil {
		t.Fatalf("세 프로젝트가 서로 다른데 거부: %v", err)
	}
}

// 블루-그린 모드의 fail-closed 조립: 슬롯 설정 누락·두 슬롯 같은 프로젝트·잘못된 게이트웨이
// URL·0 드레인은 기동을 막아야 한다(런타임까지 숨지 않는다).
func TestBuildDispatcherBlueGreenFailClosed(t *testing.T) {
	cases := []struct {
		name string
		mut  func(t *testing.T)
	}{
		{"green 슬롯 compose 누락", func(t *testing.T) { t.Setenv("DEPLOY_COMPOSE_FILE_GREEN", "") }},
		{"blue 헬스 URL 누락", func(t *testing.T) { t.Setenv("DEPLOY_HEALTH_URL_BLUE", "") }},
		{"두 슬롯 같은 compose project", func(t *testing.T) { t.Setenv("DEPLOY_COMPOSE_PROJECT_GREEN", "core-blue") }},
		{"게이트웨이 URL이 절대 http URL 아님", func(t *testing.T) { t.Setenv("DEPLOY_GATEWAY_URL", "127.0.0.1:8090") }},
		{"드레인 0", func(t *testing.T) { t.Setenv("DEPLOY_DRAIN_WAIT", "0s") }},
		{"드레인 비duration", func(t *testing.T) { t.Setenv("DEPLOY_DRAIN_WAIT", "곧") }},
		{"게이트웨이 타임아웃 음수", func(t *testing.T) { t.Setenv("DEPLOY_GATEWAY_TIMEOUT", "-1s") }},
		{"단일 변수 일부만 설정", func(t *testing.T) { t.Setenv("DEPLOY_COMPOSE_FILE", "/x/compose.yml") }},
		// #21: 결박 대상 서비스 없이 블루-그린을 띄우면 사이드카/orphan이 pinned digest를
		// 실행 중일 때 app이 틀린 이미지여도 통과하고 그 위로 라우트가 전환된다(H2 fail-open).
		{"DEPLOY_APP_SERVICE 미설정", func(t *testing.T) { t.Setenv("DEPLOY_APP_SERVICE", "") }},
		{"DEPLOY_APP_SERVICE 공백뿐", func(t *testing.T) { t.Setenv("DEPLOY_APP_SERVICE", "   ") }},
		// R4: gatewayURL이 설정됐는데 /internal 서명 키가 없으면 agent가 무서명으로 전환을
		// 호출하게 된다 — 무서명 폴백을 제거했으므로 기동을 거부한다(fail-closed).
		{"GATEWAY_INTERNAL_HMAC_KEY 미설정", func(t *testing.T) { t.Setenv("GATEWAY_INTERNAL_HMAC_KEY", "") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setBlueGreenEnv(t)
			c.mut(t)
			if _, err := buildDispatcher(); err == nil {
				t.Fatalf("%s인데 buildDispatcher 통과(boot fail-closed 위반)", c.name)
			}
		})
	}
}

// #21: env → dispatch.Config 배선이 실제로 이어지는지 본다. 값을 읽고도 실행기에 넘기지
// 않는 것이 가장 조용한 실패다 — 그러면 기동 검증은 통과하는데 사후조건은 결박 없이 돌아
// H2 fail-open이 그대로 되돌아온다. 슬롯별 실행기와 단일 경로 실행기 모두 결박돼야 한다.
func TestBuildDispatcherBindsAppServiceToExecutors(t *testing.T) {
	setBlueGreenEnv(t)
	setSingleVars(t, "core-single") // 단일 경로(target=gateway 전용)도 함께 배선한다
	t.Setenv("DEPLOY_APP_SERVICE", "app")

	b, err := buildDispatcher()
	if err != nil {
		t.Fatalf("정상 env인데 조립 실패: %v", err)
	}
	d, ok := b.disp.(deploy.LocalDispatcher)
	if !ok {
		t.Fatalf("dispatcher 타입=%T, LocalDispatcher 기대", b.disp)
	}
	for name, ex := range map[string]deploy.HostExecutor{
		"blue": d.SlotExec[deploy.SlotBlue], "green": d.SlotExec[deploy.SlotGreen], "단일 경로": d.Exec,
	} {
		x, xok := ex.(*dispatch.Executor)
		if !xok {
			t.Fatalf("%s 실행기 타입=%T, *dispatch.Executor 기대", name, ex)
		}
		if x.AppService() != "app" {
			t.Fatalf("%s 실행기에 대상 서비스가 결박되지 않았다: %q (기대 %q)", name, x.AppService(), "app")
		}
	}
}

// 단일 경로 모드에서 DEPLOY_APP_SERVICE는 선택이다(하위호환) — 미설정이면 결박 없이
// 조립되고 프로젝트 전체 판정이 유지된다. 설정하면 결박이 켜진다.
func TestBuildDispatcherSinglePathAppServiceOptional(t *testing.T) {
	singleExec := func(t *testing.T) *dispatch.Executor {
		t.Helper()
		b, err := buildDispatcher()
		if err != nil {
			t.Fatalf("단일 경로 조립 실패: %v", err)
		}
		x, ok := b.disp.(deploy.LocalDispatcher).Exec.(*dispatch.Executor)
		if !ok {
			t.Fatal("단일 경로 실행기가 *dispatch.Executor가 아니다")
		}
		return x
	}

	// ⚠️ 전제 변경(리뷰 E-4): DEPLOY_APP_SERVICE가 선택인 것은 **과도기 배선에서뿐**이다.
	// 동봉이 필수인 기본 배선에서는 CP-3의 호스트 쪽 값이 없으면 대조할 상대가 없으므로
	// 기동이 거부된다 — 아래 두 케이스가 그 경계를 함께 못박는다.
	t.Run("동봉 필수 배선에서는 미설정이 기동 거부", func(t *testing.T) {
		setRequiredDispatchEnv(t)
		t.Setenv("DEPLOY_GATEWAY_URL", "")
		t.Setenv("DEPLOY_APP_SERVICE", "")
		if _, err := buildDispatcher(); err == nil {
			t.Fatal("동봉 필수인데 DEPLOY_APP_SERVICE 없이 조립됐다(CP-3 대조 상대 부재)")
		}
	})
	t.Run("과도기 배선에서는 미설정이면 결박 없음", func(t *testing.T) {
		setRequiredDispatchEnv(t)
		t.Setenv("DEPLOY_GATEWAY_URL", "")
		t.Setenv("DEPLOY_APP_SERVICE", "")
		t.Setenv("DEPLOY_ALLOW_LEGACY_COMPOSE", "1")
		if got := singleExec(t).AppService(); got != "" {
			t.Fatalf("미설정인데 결박=%q", got)
		}
	})
	t.Run("설정하면 결박", func(t *testing.T) {
		setRequiredDispatchEnv(t)
		t.Setenv("DEPLOY_GATEWAY_URL", "")
		t.Setenv("DEPLOY_APP_SERVICE", "app")
		if got := singleExec(t).AppService(); got != "app" {
			t.Fatalf("결박=%q, %q 기대", got, "app")
		}
	})
}

// TestResolveRole은 역할 해석의 fail-closed 계약을 다룬다: 유효 값은 통과하고,
// 빈 값·미지원 값은 오류가 되어 기동을 막는다.
func TestResolveRole(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    role
		wantErr bool
	}{
		{name: "main 통과", raw: "main", want: roleMain},
		{name: "agent 통과", raw: "agent", want: roleAgent},
		{name: "미설정 거부", raw: "", wantErr: true},
		{name: "미지원 값 거부", raw: "orchestrator", wantErr: true},
		{name: "대소문자 구분 — MAIN 거부", raw: "MAIN", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveRole(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Errorf("resolveRole(%q): 오류 기대했으나 nil (fail-closed 위반)", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveRole(%q): 예상치 못한 오류: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("resolveRole(%q) = %q, 기대 = %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestRunUnsetRoleFailsClosed는 run이 ROLE 미설정 시 서버를 띄우지 않고 오류로
// 되돌아오는지 확인한다(fail-closed — 리스너를 열지 않는다).
func TestRunUnsetRoleFailsClosed(t *testing.T) {
	if err := run(""); err == nil {
		t.Error("run(\"\"): 오류 기대했으나 nil — ROLE 없이 기동되면 안 된다")
	}
}

// TestLeaseCoversRemote는 C1②다: 원격 route 등록 시 lease가 RPC_TIMEOUT+slack보다 짧으면
// 거절하고 충분하면 통과함을 본다(coordinator가 락 보유 중 RPC_TIMEOUT까지 블로킹).
func TestLeaseCoversRemote(t *testing.T) {
	rpc := 4 * time.Minute
	min := resumeNetworkOps*rpc + dispatchLeaseSlack // 조각 C 재개 사이클(3×RPC_TIMEOUT + slack)
	// lease가 하한보다 1ns 부족 = 거절(음수 여유 방지).
	if err := leaseCoversRemote(min-time.Nanosecond, rpc); err == nil {
		t.Fatal("lease < 3×RPC_TIMEOUT + slack인데 통과(fail-closed 위반)")
	}
	// 정확히 하한 = 통과.
	if err := leaseCoversRemote(min, rpc); err != nil {
		t.Fatalf("lease = 3×RPC_TIMEOUT + slack인데 거절: %v", err)
	}
	// 조각 A 하한(1×RPC_TIMEOUT + slack)은 이제 재개 사이클을 못 덮으므로 거절돼야 한다(회귀 방지).
	if err := leaseCoversRemote(rpc+dispatchLeaseSlack, rpc); err == nil {
		t.Fatal("1×RPC_TIMEOUT + slack로는 재개 사이클을 못 덮는데 통과(R4 재유도 위반)")
	}
	// RPC_TIMEOUT이 overflow 범위면 거절.
	if err := leaseCoversRemote(time.Hour, 2*maxDispatchDuration); err == nil {
		t.Fatal("RPC_TIMEOUT이 상한 초과인데 통과(overflow 방어 위반)")
	}
}

// TestDefaultConfigLeaseCoversRemote는 기본 설정끼리 원격 하한을 만족함을 본다(기본 lease가
// 기본 RPC_TIMEOUT+slack을 덮는다 — 기본값 자기정합).
func TestDefaultConfigLeaseCoversRemote(t *testing.T) {
	if err := leaseCoversRemote(defaultDeployLease, defaultRPCTimeout); err != nil {
		t.Fatalf("기본 lease가 기본 RPC_TIMEOUT+slack을 덮지 못한다(기본값 부정합): %v", err)
	}
}

// TestBuildRoutingDispatcherRejectsOneSidedRemote는 위성 키·URL 중 한쪽만 설정하면 오설정으로
// 기동을 거부함을 본다(fail-closed). 둘 다 없으면 미등록으로 통과(라우터에서 fail-closed 거절).
func TestBuildRoutingDispatcherRejectsOneSidedRemote(t *testing.T) {
	local := deploy.StubDispatcher{}
	t.Setenv("AGENT_RPC_KEY_SETTLEMENT", "some-key")
	t.Setenv("AGENT_REMOTE_URL_SETTLEMENT", "") // 한쪽만 설정
	if _, _, _, err := buildRoutingDispatcher(local); err == nil {
		t.Fatal("위성 키만 있고 URL이 없는데 통과(오설정 fail-closed 위반)")
	}

	// 둘 다 미설정(ledger) + settlement도 정리 → 미등록으로 통과, remoteRegistered=false.
	t.Setenv("AGENT_RPC_KEY_SETTLEMENT", "")
	t.Setenv("AGENT_REMOTE_URL_SETTLEMENT", "")
	_, remoteReg, _, err := buildRoutingDispatcher(local)
	if err != nil {
		t.Fatalf("원격 미설정은 통과해야 한다(미등록): %v", err)
	}
	if remoteReg {
		t.Fatal("원격 미설정인데 remoteRegistered=true")
	}
}

// TestFenceBootConfigRejectsMisconfig는 C-B2 방어심층이다: 원격 위성 키가 있을 때 fence 리스너의
// boot 입력이 잘못되면 조용히 축소하지 않고 거부함을 본다(fenceBootConfig 순수 검증 — bind 없음).
func TestFenceBootConfigRejectsMisconfig(t *testing.T) {
	reject := []struct {
		name              string
		rawAddr, rawAllow string
	}{
		{"addr 미설정(loopback 조용한 축소 금지)", "", "10.0.0.158"},
		{"addr loopback", "127.0.0.1:9443", "10.0.0.158"},
		{"addr 공개 IP", "8.8.8.8:9443", "10.0.0.158"},
		{"allowlist 미설정", "10.0.0.9:9443", ""},
		{"allowlist 빈 파싱(콤마만)", "10.0.0.9:9443", ", ,"},
		{"allowlist 공개 IP", "10.0.0.9:9443", "8.8.8.8"},
		{"allowlist hostname", "10.0.0.9:9443", "sat.host"},
	}
	for _, c := range reject {
		if _, _, _, err := fenceBootConfig(c.rawAddr, true /*hasKeys*/, c.rawAllow); err == nil {
			t.Errorf("%s인데 fenceBootConfig 통과(boot fail-closed 위반)", c.name)
		}
	}

	// addr만 있고 위성 키 없음 = 검증할 위성 없는 오배선 → 거부.
	if _, _, _, err := fenceBootConfig("10.0.0.9:9443", false /*hasKeys*/, ""); err == nil {
		t.Error("위성 키 없이 fence addr만 설정됐는데 통과(오배선 fail-closed 위반)")
	}
}

// TestFenceBootConfigAcceptsValid는 올바른 배선(원격 위성 + non-loopback private addr + private
// allowlist)이 통과하고, 위성 키 없음은 fencing 미배선(enabled=false)으로 통과함을 본다.
func TestFenceBootConfigAcceptsValid(t *testing.T) {
	addr, allowed, enabled, err := fenceBootConfig("10.0.0.9:9443", true /*hasKeys*/, "10.0.0.158, 10.0.0.164")
	if err != nil || !enabled {
		t.Fatalf("올바른 배선은 통과·enabled여야 한다: enabled=%v err=%v", enabled, err)
	}
	if addr != "10.0.0.9:9443" {
		t.Fatalf("검증된 addr 기대: %q", addr)
	}
	if !allowed["10.0.0.158"] || !allowed["10.0.0.164"] {
		t.Fatalf("allowlist에 위성 IP가 있어야 한다: %v", allowed)
	}

	// 위성 키 없음 → fencing 미배선(enabled=false), 오류 없음.
	if _, _, enabled, err := fenceBootConfig("", false /*hasKeys*/, ""); err != nil || enabled {
		t.Fatalf("위성 키 없음은 fencing 미배선(enabled=false)으로 통과해야 한다: enabled=%v err=%v", enabled, err)
	}
}
