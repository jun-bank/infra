// cmd/agent의 ROLE 분기 단위 테스트. 서버를 실제로 띄우지 않고 역할 해석만
// 검증한다 — ROLE 미설정·미지원이면 기동을 거부하는 fail-closed 방향이 핵심이다
// (ADR-027 DO-21).
package main

import (
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
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
