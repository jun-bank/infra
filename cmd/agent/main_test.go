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
		if err := leaseCoversDispatch(lease, phase, d); err == nil {
			t.Errorf("lease=%s < min=%s 인데 통과(fail-closed 위반)", lease, min)
		}
	}

	// 충분 — 통과.
	for _, lease := range []time.Duration{
		min,
		min + time.Second,
		10 * time.Minute,
	} {
		if err := leaseCoversDispatch(lease, phase, d); err != nil {
			t.Errorf("lease=%s >= min=%s 인데 거부: %v", lease, min, err)
		}
	}
}

// 기본 설정끼리 자기정합해야 한다 — 기본 lease가 기본 phaseBudget+D+cleanup+slack를 덮지
// 못하면, 아무 env도 안 준 운영자의 agent가 leaseCoversDispatch에서 fail-closed로 기동하지
// 못한다. 기본값을 바꿀 때 이 정합성이 깨지지 않게 막는다.
func TestDefaultConfigLeaseCoversDispatch(t *testing.T) {
	if err := leaseCoversDispatch(defaultDeployLease, defaultDispatchPhaseBudget, defaultHealthDeadline); err != nil {
		t.Fatalf("기본 설정이 자기정합하지 않다(기본값으로 기동 불가): %v", err)
	}
}

// H3: 거대 duration이 하한식 덧셈을 int64 overflow로 음수로 뒤집어 작은 lease가 검증을
// 통과(fail-open)하면 안 된다. 상한(maxDispatchDuration)을 넘는 phaseBudget·healthDeadline은
// 거부한다 — overflow 재현: 각각을 int64 최대의 절반 이상으로 두면 합이 음수가 된다.
func TestLeaseCoversDispatchRejectsOverflow(t *testing.T) {
	huge := time.Duration(1<<62) + time.Hour // maxDispatchDuration을 크게 넘고, 둘을 더하면 overflow
	// 작은 lease인데도 overflow로 통과해선 안 된다(fail-closed).
	if err := leaseCoversDispatch(time.Second, huge, huge); err == nil {
		t.Fatalf("거대 phaseBudget·healthDeadline(overflow 유발)인데 작은 lease가 통과 — fail-open")
	}
	// 상한을 살짝 넘는 값도 거부.
	if err := leaseCoversDispatch(24*time.Hour, maxDispatchDuration+time.Second, defaultHealthDeadline); err == nil {
		t.Fatalf("phaseBudget이 상한 초과인데 통과 — fail-closed 위반")
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
			if _, _, _, err := buildDispatcher(); err == nil {
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
	if _, d, pb, err := buildDispatcher(); err != nil || d != 45*time.Second || pb != 90*time.Second {
		t.Fatalf("정상 env: err=%v D=%s phaseBudget=%s, nil·45s·90s 기대", err, d, pb)
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
