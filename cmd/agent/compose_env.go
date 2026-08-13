package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jun-bank/infra/internal/compose"
	"github.com/jun-bank/infra/internal/deploy"
)

// 동봉 compose 결박의 호스트 배선을 환경에서 읽는다(infra#19 · ADR-030). 여기서 오는 값은
// 전부 **닫힌 목록**이다 — 동봉된 compose가 스스로 자기 허용 범위를 넓힐 수 없어야 allowlist다.
//
// 이 파일의 모든 파싱은 fail-closed다: 형식이 어긋나면 기본값으로 삼키지 않고 기동을 거부하며,
// 오류 메시지에는 **변수명과 허용값**을 담는다(G-12). 배포 호스트의 오설정은 런타임까지 숨으면
// "왜 배포가 이상하게 되는지"를 사람이 역추적해야 하는 종류의 실패가 된다.

const (
	// envWorkspace는 candidate·applied가 사는 agent 전용 디렉터리다(CP-2).
	envWorkspace = "DEPLOY_WORKSPACE"
	// envAllowLegacy는 무동봉(호스트 compose 파일) 배포를 허용하는 명시 opt-in이다(R7).
	envAllowLegacy = "DEPLOY_ALLOW_LEGACY_COMPOSE"
	// envComposeEnvAllow는 target별 environment pass-through 등재 키다(`target:KEY,…`).
	envComposeEnvAllow = "DEPLOY_COMPOSE_ENV_ALLOW"
	// envComposeVolumeAllow는 target별 볼륨 정확 튜플 등재다(`target:src:dst:mode,…`).
	envComposeVolumeAllow = "DEPLOY_COMPOSE_VOLUME_ALLOW"
	// envHostPort는 단일 경로(슬롯 없음)의 호스트 포트다.
	envHostPort = "DEPLOY_HOST_PORT"
	// envHostPortPrefix + 슬롯 대문자 = 슬롯별 호스트 포트(DEPLOY_HOST_PORT_BLUE/GREEN).
	envHostPortPrefix = "DEPLOY_HOST_PORT_"
)

// parseAllowLegacy는 legacy opt-in을 읽는다. 미설정은 0(동봉 필수)이고, 0|1 밖의 값은
// **기동 거부**다 — "yes"·"true"·"Y" 같은 값을 관용적으로 받으면, 오타 하나가 조용히
// 0으로 접혀 운영자가 켰다고 믿는 과도기 경로가 실은 꺼져 있게 된다(또는 그 반대).
func parseAllowLegacy() (bool, error) {
	switch raw := os.Getenv(envAllowLegacy); raw {
	case "", "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("%s 값은 0 또는 1이어야 한다(미설정=0=동봉 필수): %q", envAllowLegacy, raw)
	}
}

// parseComposeEnvAllow는 `target:KEY,target:KEY,…`를 target별 등재 키 목록으로 읽는다.
// 형식이 target별인 이유(rev.2 F18): 전역 합집합으로 두면 gateway가 등재한 키를 core의
// compose가 끌어 쓸 수 있어, 대상마다 닫아 둔 목록이 사실상 하나로 합쳐진다.
func parseComposeEnvAllow(raw string) (map[deploy.Target][]string, error) {
	out := map[deploy.Target][]string{}
	for _, item := range splitList(raw) {
		target, key, ok := strings.Cut(item, ":")
		if !ok {
			return nil, fmt.Errorf("%s 항목은 `target:KEY` 형식이어야 한다: %q", envComposeEnvAllow, item)
		}
		t, terr := validTarget(envComposeEnvAllow, target)
		if terr != nil {
			return nil, terr
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("%s 항목의 키가 비어 있다: %q", envComposeEnvAllow, item)
		}
		out[t] = append(out[t], key)
	}
	return out, nil
}

// parseComposeVolumeAllow는 `target:src:dst:mode,…`를 target별 정확 튜플로 읽는다.
// 프리픽스가 아니라 정확 튜플인 이유(rev.2 F-04): 프리픽스 허용은 그 아래 경로 전체를
// 여는 것과 같고, 컨테이너 쪽 경로와 mode도 함께 못 박아야 "무엇이 어디에 어떤 권한으로
// 붙는가"가 서명 밖에서 정해지지 않는다.
func parseComposeVolumeAllow(raw string) (map[deploy.Target][]compose.VolumeRule, error) {
	out := map[deploy.Target][]compose.VolumeRule{}
	for _, item := range splitList(raw) {
		parts := strings.Split(item, ":")
		if len(parts) != 4 {
			return nil, fmt.Errorf("%s 항목은 `target:src:dst:mode` 정확히 4칸이어야 한다: %q", envComposeVolumeAllow, item)
		}
		t, terr := validTarget(envComposeVolumeAllow, parts[0])
		if terr != nil {
			return nil, terr
		}
		src, dst, mode := strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), strings.TrimSpace(parts[3])
		if mode != "ro" && mode != "rw" {
			return nil, fmt.Errorf("%s 항목의 mode는 ro 또는 rw여야 한다: %q", envComposeVolumeAllow, item)
		}
		for _, p := range []struct{ name, val string }{{"src", src}, {"dst", dst}} {
			if !filepath.IsAbs(p.val) {
				return nil, fmt.Errorf("%s 항목의 %s는 절대경로여야 한다: %q", envComposeVolumeAllow, p.name, item)
			}
			if filepath.Clean(p.val) != p.val {
				return nil, fmt.Errorf("%s 항목의 %s가 정규형이 아니다(Clean 후 %q): %q", envComposeVolumeAllow, p.name, filepath.Clean(p.val), item)
			}
		}
		out[t] = append(out[t], compose.VolumeRule{Src: src, Dst: dst, Mode: mode})
	}
	return out, nil
}

// hostPort는 슬롯별 호스트 포트를 읽는다. 값은 1~65535 정수여야 하며, 그 밖은 기동 거부다 —
// compose의 `${DEPLOY_HOST_PORT}` 자리에 그대로 들어가므로 형식 검증이 여기 없으면
// 임의 문자열이 포트 매핑 문법에 주입된다.
func hostPort(key string) (string, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return "", nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%s 값은 1~65535 정수여야 한다: %q", key, raw)
	}
	return strconv.Itoa(n), nil
}

// splitList는 콤마 목록을 다듬어 나눈다(빈 항목은 버린다 — 후행 콤마 관용).
func splitList(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// validTarget은 등재 항목의 target이 닫힌 배포 집합에 속하는지 본다 — 오타 난 target에
// 등재한 키·볼륨은 아무 대상에도 적용되지 않은 채 조용히 무시되므로(설정한 사람은
// 적용됐다고 믿는다) 기동에서 잡는다.
func validTarget(envName, raw string) (deploy.Target, error) {
	t := deploy.Target(strings.TrimSpace(raw))
	if !t.Valid() {
		return "", fmt.Errorf("%s 항목의 target이 닫힌 집합 밖이다: %q(허용=%v)", envName, raw, deploy.ValidTargets())
	}
	return t, nil
}

// buildComposeRuntime은 동봉 실행 배선을 조립한다. workspace가 없으면 nil을 주며, 그때
// 동봉 manifest는 실행 지점에서 요란하게 거절된다(조용한 성공이 아니다). legacy opt-in은
// workspace 유무와 무관하게 항상 읽는다 — 그 값이 곧 REQUIRE 게이트이기 때문이다.
func buildComposeRuntime(appService, imageEnvVar string, hostPorts map[string]string, bind func(string, deploy.ComposeBinding) (deploy.HostExecutor, deploy.HealthChecker, error)) (*deploy.ComposeRuntime, error) {
	allowLegacy, err := parseAllowLegacy()
	if err != nil {
		return nil, err
	}

	// 호스트 포트가 하나도 배선되지 않았으면 한 줄 남긴다(리뷰 E-11). 기동을 막지는 않는다 —
	// ports를 선언하지 않는 compose도 유효하기 때문이다. 다만 ports를 쓰는 compose가 오면 그
	// 배포는 실패하므로, 그 실패를 배포 시점이 아니라 기동 로그에서 먼저 짐작할 수 있게 한다.
	if len(hostPorts) == 0 {
		fmt.Printf("경고: %s·%sBLUE/GREEN이 하나도 설정되지 않았다 — ports를 선언한 동봉 compose는 주입값 부재로 거절된다(ports 없는 compose만 배포한다면 무해)\n", envHostPort, envHostPortPrefix)
	}

	envAllow, err := parseComposeEnvAllow(os.Getenv(envComposeEnvAllow))
	if err != nil {
		return nil, err
	}
	volumeAllow, err := parseComposeVolumeAllow(os.Getenv(envComposeVolumeAllow))
	if err != nil {
		return nil, err
	}
	// CP-5 fail-closed — 등재한 키의 **값**이 이 호스트에 없으면 기동하지 않는다. 런타임까지
	// 미루면 그 키는 compose에서 빈 값으로 뜨고(pass-through는 없는 변수를 빈 값으로 넘긴다)
	// 앱이 기본값으로 조용히 잘못 기동한다.
	for target, keys := range envAllow {
		for _, k := range keys {
			if os.Getenv(k) == "" {
				return nil, fmt.Errorf("%s에 등재된 키 %q(target=%s)의 값이 이 호스트 환경에 없다 — 값의 소유는 호스트 .env다(CP-5 · fail-closed)", envComposeEnvAllow, k, target)
			}
		}
	}

	root := strings.TrimSpace(os.Getenv(envWorkspace))
	if root == "" {
		if !allowLegacy {
			return nil, fmt.Errorf("%s가 필요하다 — 신 agent의 기본은 동봉 compose 필수이며(R7) candidate를 기록할 곳이 없으면 배포를 수행할 수 없다(%s=1로 과도기 경로를 명시 허용하지 않는 한 fail-closed)", envWorkspace, envAllowLegacy)
		}
		fmt.Printf("경고: %s 미설정 · %s=1 — 이 agent는 무동봉(호스트 compose) 배포만 수행한다. 동봉 manifest가 오면 실행 지점에서 거절된다\n", envWorkspace, envAllowLegacy)
		return &deploy.ComposeRuntime{AllowLegacy: true}, nil
	}

	ws, err := compose.Open(root)
	if err != nil {
		return nil, fmt.Errorf("%s 배타성 계약 위반(절대경로·심볼릭 링크 없음·0700·현재 uid 소유 — fail-closed): %w", envWorkspace, err)
	}

	rt := &deploy.ComposeRuntime{
		Workspace:  ws,
		AppService: appService,
		HostPort:   hostPorts,
		Bind:       bind,
		Policy: func(target deploy.Target) compose.Policy {
			return compose.Policy{
				ImageEnvVar: imageEnvVar,
				EnvAllow:    envAllow[target],
				VolumeAllow: volumeAllow[target],
			}
		},
		// 값의 소유는 호스트 프로세스 env다(CP-5) — compose에는 키만 실린다.
		ConfigValue: func(key string) (string, bool) {
			v := os.Getenv(key)
			return v, v != ""
		},
		AllowLegacy: allowLegacy,
	}
	fmt.Printf("동봉 compose 결박: workspace=%s · 등재 env 키 %d대상 · 등재 볼륨 %d대상 · %s=%v\n",
		ws.Root(), len(envAllow), len(volumeAllow), envAllowLegacy, allowLegacy)
	return rt, nil
}
