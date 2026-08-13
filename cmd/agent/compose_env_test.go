package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/dispatch"
)

// 동봉 결박의 호스트 배선 파싱(infra#19). 여기서 잡으려는 것은 **조용한 오설정**이다 —
// 오타 난 target에 등재한 키는 아무 대상에도 적용되지 않은 채 무시되고, 값 없는 등재 키는
// compose에서 빈 값으로 떠 앱이 기본값으로 잘못 기동한다. 둘 다 기동에서 닫는다.

// R7·G-12: legacy opt-in은 0|1만 받고, 그 밖은 변수명과 허용값을 담아 기동을 거부한다.
func TestParseAllowLegacyClosedValues(t *testing.T) {
	t.Run("미설정=동봉 필수", func(t *testing.T) {
		t.Setenv(envAllowLegacy, "")
		got, err := parseAllowLegacy()
		if err != nil || got {
			t.Fatalf("미설정: got=%v err=%v, false·nil 기대(기본 REQUIRE=1)", got, err)
		}
	})
	t.Run("1=명시 opt-in", func(t *testing.T) {
		t.Setenv(envAllowLegacy, "1")
		got, err := parseAllowLegacy()
		if err != nil || !got {
			t.Fatalf("1: got=%v err=%v", got, err)
		}
	})
	for _, bad := range []string{"true", "yes", "Y", "0 ", " 1", "01", "on", "TRUE"} {
		t.Run("거절 "+bad, func(t *testing.T) {
			t.Setenv(envAllowLegacy, bad)
			_, err := parseAllowLegacy()
			if err == nil {
				t.Fatalf("%q가 통과했다 — 관용 파싱은 켰다고 믿는 경로가 실은 꺼져 있게 만든다", bad)
			}
			if !strings.Contains(err.Error(), envAllowLegacy) || !strings.Contains(err.Error(), "0") {
				t.Fatalf("오류에 변수명·허용값이 없다(G-12): %v", err)
			}
		})
	}
}

// 등재 목록은 target별이다 — 전역 합집합이면 gateway가 등재한 키를 core의 compose가 끌어 쓴다.
func TestParseComposeEnvAllowPerTarget(t *testing.T) {
	got, err := parseComposeEnvAllow("core:CORE_BLUE_URI, core:CORE_GREEN_URI ,gateway:GW_UPSTREAM,")
	if err != nil {
		t.Fatalf("정상 형식이 거절됐다: %v", err)
	}
	if len(got[deploy.TargetCore]) != 2 || got[deploy.TargetCore][0] != "CORE_BLUE_URI" {
		t.Fatalf("core 등재=%v", got[deploy.TargetCore])
	}
	if len(got[deploy.TargetGateway]) != 1 {
		t.Fatalf("gateway 등재=%v", got[deploy.TargetGateway])
	}
	if len(got[deploy.TargetLedger]) != 0 {
		t.Fatalf("등재하지 않은 대상에 키가 생겼다: %v", got[deploy.TargetLedger])
	}

	for _, bad := range []string{"CORE_BLUE_URI", "oracle:X", "core:", ":X", "Core:X"} {
		t.Run("거절 "+bad, func(t *testing.T) {
			if _, err := parseComposeEnvAllow(bad); err == nil {
				t.Fatalf("%q가 통과했다", bad)
			}
		})
	}
}

// 볼륨은 프리픽스가 아니라 정확 튜플이다 — src·dst·mode 셋 다 못 박아야 "무엇이 어디에
// 어떤 권한으로 붙는가"가 서명 밖에서 정해지지 않는다.
func TestParseComposeVolumeAllowExactTuples(t *testing.T) {
	got, err := parseComposeVolumeAllow("core:/srv/jun-bank/data:/app/data:rw")
	if err != nil {
		t.Fatalf("정상 형식이 거절됐다: %v", err)
	}
	rules := got[deploy.TargetCore]
	if len(rules) != 1 || rules[0].Src != "/srv/jun-bank/data" || rules[0].Dst != "/app/data" || rules[0].Mode != "rw" {
		t.Fatalf("파싱 결과=%+v", rules)
	}

	for _, bad := range []string{
		"core:/srv/data:/app/data",      // mode 누락
		"core:/srv/data:/app/data:rwx",  // mode 밖
		"core:srv/data:/app/data:rw",    // 상대 src
		"core:/srv/data:app/data:rw",    // 상대 dst
		"core:/srv/../etc:/app/data:rw", // 비정규형
		"oracle:/srv/d:/app/d:rw",       // 닫힌 집합 밖 target
		"/srv/data:/app/data:rw",        // target 누락
		"core:/srv/d:/app/d:rw:extra",   // 칸 초과
		"core:/srv/d//x:/app/d:rw",      // 비정규형(중복 슬래시)
	} {
		t.Run("거절 "+bad, func(t *testing.T) {
			if _, err := parseComposeVolumeAllow(bad); err == nil {
				t.Fatalf("%q가 통과했다", bad)
			}
		})
	}
}

// 호스트 포트는 compose의 `${DEPLOY_HOST_PORT}` 자리에 그대로 들어간다 — 형식 검증이 없으면
// 임의 문자열이 포트 매핑 문법에 주입된다.
func TestHostPortRange(t *testing.T) {
	t.Setenv("DEPLOY_HOST_PORT", "18080")
	if got, err := hostPort("DEPLOY_HOST_PORT"); err != nil || got != "18080" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	for _, bad := range []string{"0", "65536", "-1", "8080;rm -rf /", "80 80", "abc", "1e3"} {
		t.Run("거절 "+bad, func(t *testing.T) {
			t.Setenv("DEPLOY_HOST_PORT", bad)
			if _, err := hostPort("DEPLOY_HOST_PORT"); err == nil {
				t.Fatalf("%q가 통과했다", bad)
			}
		})
	}
}

// CP-5 fail-closed — 등재한 키의 **값**이 호스트에 없으면 기동하지 않는다. 런타임까지 미루면
// pass-through가 없는 변수를 빈 값으로 넘겨 앱이 기본값으로 조용히 기동한다.
func TestBuildDispatcherRequiresRegisteredEnvValues(t *testing.T) {
	setRequiredDispatchEnv(t)
	t.Setenv("DEPLOY_COMPOSE_ENV_ALLOW", "core:CORE_BLUE_URI")
	t.Setenv("CORE_BLUE_URI", "")
	if _, err := buildDispatcher(); err == nil {
		t.Fatal("등재 키의 값이 없는데 기동 통과 — compose가 빈 값으로 뜬다")
	}
	t.Setenv("CORE_BLUE_URI", "http://127.0.0.1:18081")
	if _, err := buildDispatcher(); err != nil {
		t.Fatalf("값이 있는데 거부: %v", err)
	}
}

// workspace는 배타성 계약을 만족해야 하고, 없으면(동봉 필수 기본에서) 기동이 막힌다.
func TestBuildDispatcherWorkspaceContract(t *testing.T) {
	t.Run("미설정이면 기동 거부", func(t *testing.T) {
		setRequiredDispatchEnv(t)
		t.Setenv("DEPLOY_WORKSPACE", "")
		if _, err := buildDispatcher(); err == nil {
			t.Fatal("workspace 없이 조립됐다 — candidate를 기록할 곳이 없다")
		}
	})
	t.Run("0755면 기동 거부", func(t *testing.T) {
		setRequiredDispatchEnv(t)
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		loose := filepath.Join(base, "loose")
		if mkErr := os.Mkdir(loose, 0o755); mkErr != nil {
			t.Fatal(mkErr)
		}
		t.Setenv("DEPLOY_WORKSPACE", loose)
		if _, err := buildDispatcher(); err == nil {
			t.Fatal("0755 workspace로 조립됐다 — 다른 사용자가 candidate를 바꿀 수 있다")
		}
	})
	t.Run("미설정 + legacy opt-in이면 legacy 전용으로 조립", func(t *testing.T) {
		setRequiredDispatchEnv(t)
		t.Setenv("DEPLOY_WORKSPACE", "")
		t.Setenv(envAllowLegacy, "1")
		b, err := buildDispatcher()
		if err != nil {
			t.Fatalf("legacy opt-in인데 조립 실패: %v", err)
		}
		d := b.disp.(deploy.LocalDispatcher)
		if d.Compose == nil || !d.Compose.AllowLegacy || d.Compose.Workspace != nil {
			t.Fatalf("legacy 전용 배선이 아니다: %+v", d.Compose)
		}
	})
}

// 배선이 실제로 이어졌는지 본다 — 값을 읽고도 실행 지점에 넘기지 않는 것이 가장 조용한 실패다.
// 그러면 기동 검증은 통과하는데 배포는 결박 없이 돈다.
func TestBuildDispatcherWiresComposeRuntime(t *testing.T) {
	setBlueGreenEnv(t)
	t.Setenv("DEPLOY_COMPOSE_ENV_ALLOW", "core:CORE_BLUE_URI")
	t.Setenv("CORE_BLUE_URI", "http://127.0.0.1:18081")
	t.Setenv("DEPLOY_COMPOSE_VOLUME_ALLOW", "core:/srv/jun-bank/data:/app/data:rw")

	b, err := buildDispatcher()
	if err != nil {
		t.Fatalf("조립 실패: %v", err)
	}
	d := b.disp.(deploy.LocalDispatcher)
	rt := d.Compose
	if rt == nil || rt.Workspace == nil || rt.Bind == nil || rt.Policy == nil || rt.ConfigValue == nil {
		t.Fatalf("동봉 배선이 비었다: %+v", rt)
	}
	if rt.AllowLegacy {
		t.Fatal("기본이 legacy 허용으로 조립됐다(R7 위반)")
	}
	if rt.AppService != "app" {
		t.Fatalf("CP-3 호스트 쪽 값이 배선되지 않았다: %q", rt.AppService)
	}
	if rt.HostPort["blue"] != "18081" || rt.HostPort["green"] != "18082" {
		t.Fatalf("슬롯별 호스트 포트 배선=%v", rt.HostPort)
	}
	p := rt.Policy(deploy.TargetCore)
	if p.ImageEnvVar != dispatch.DefaultImageEnvVar {
		t.Fatalf("image 변수명=%q, 실행기 기본값과 같아야 한다", p.ImageEnvVar)
	}
	if len(p.EnvAllow) != 1 || p.EnvAllow[0] != "CORE_BLUE_URI" {
		t.Fatalf("등재 env 키=%v", p.EnvAllow)
	}
	if len(p.VolumeAllow) != 1 || p.VolumeAllow[0].Dst != "/app/data" {
		t.Fatalf("등재 볼륨=%v", p.VolumeAllow)
	}
	// 다른 대상의 정책은 비어 있어야 한다(합집합 약화 방지).
	if len(rt.Policy(deploy.TargetGateway).EnvAllow) != 0 {
		t.Fatal("등재가 대상을 넘어 새어나갔다")
	}

	// Bind는 슬롯의 정체성(-p)을 유지한 채 candidate에 결박한 실행기를 준다.
	execr, health, berr := rt.Bind("green", deploy.ComposeBinding{
		ComposeFile:      "/srv/ws/core/green/compose.sha256-abc.yml",
		ProjectDirectory: "/srv/ws/core/green",
		Injected:         []string{"CORE_BLUE_URI=http://127.0.0.1:18081"},
	})
	if berr != nil || execr == nil || health == nil {
		t.Fatalf("Bind 실패: err=%v exec=%v health=%v", berr, execr, health)
	}
	x, ok := execr.(*dispatch.Executor)
	if !ok {
		t.Fatalf("결박 실행기 타입=%T", execr)
	}
	if x.ComposeFile() != "/srv/ws/core/green/compose.sha256-abc.yml" || x.ProjectDirectory() != "/srv/ws/core/green" {
		t.Fatalf("결박이 이어지지 않았다: file=%q dir=%q", x.ComposeFile(), x.ProjectDirectory())
	}
	if x.AppService() != "app" {
		t.Fatalf("파생 실행기가 대상 서비스 결박을 잃었다: %q", x.AppService())
	}
	if _, _, uerr := rt.Bind("unknown-slot", deploy.ComposeBinding{ComposeFile: "/a/b.yml", ProjectDirectory: "/a"}); uerr == nil {
		t.Fatal("배선 없는 슬롯이 결박됐다")
	}
}
