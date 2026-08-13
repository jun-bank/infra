package deploy

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/jun-bank/infra/internal/compose"
)

// 동봉 compose 실행 배선(infra#19 · ADR-030 CP-1~7). 실행 지점이 소비하는 계약을 여기 모은다:
// 무엇을 검증하고(preflight — 부작용 0), 어디에 기록하며(candidate), 무엇을 주입하고(닫힌 집합),
// 언제 승격하는가(배포 성공 후).
//
// dispatch 패키지를 import하지 않기 위해 **결박 실행기 생성은 함수 필드**(Bind)로 받는다 —
// main이 dispatch 구현으로 그 자리를 채운다(IA-5 닫힌 import · 조립은 main의 몫).

var (
	// ErrComposePreflight는 동봉 compose가 실행 전 검증(구조·CP-3·주입값)을 통과하지 못한 것이다.
	// 요청 내용의 문제이므로 실행 계층 실패(502)가 아니라 manifest 거절(422)로 사상된다.
	ErrComposePreflight = errors.New("deploy: 동봉 compose 검증 실패")
	// ErrComposeStorage는 candidate 기록·재해시가 어긋난 것이다 — 요청은 옳았고 이 호스트의
	// 저장 계층이 잘못했다(G-14 · 500).
	ErrComposeStorage = errors.New("deploy: 동봉 compose 저장 무결성 장애")
	// ErrComposeWiring은 동봉 배포를 수행할 배선이 없는 것이다(workspace·binder 미설정).
	ErrComposeWiring = errors.New("deploy: 동봉 compose 실행 배선 없음")
)

// ComposeBinding은 이 배포가 실행할 compose의 좌표다 — Bind가 이 값으로 실행기·헬스를 만든다.
type ComposeBinding struct {
	// ComposeFile은 candidate 경로다(`-f`). 호스트 설정 파일이 아니라 이번 서명 바이트다.
	ComposeFile string
	// ProjectDirectory는 compose의 `--project-directory`다(candidate 디렉터리로 고정 —
	// 상대 경로·.env 해석 기준이 workspace 밖으로 새지 않게).
	ProjectDirectory string
	// Injected는 compose subprocess에 넣을 KEY=VALUE다(호스트 포트·등재 config 키의 값).
	// 이미지 참조는 여기 넣지 않는다 — up이 매 실행마다 pinned digest로 직접 주입한다.
	Injected []string
}

// ComposeRuntime은 동봉 실행에 필요한 호스트 배선이다. nil이면 이 agent는 동봉 배포를
// 수행할 수 없다(legacy 전용 과도기 호스트).
type ComposeRuntime struct {
	// Workspace는 candidate·applied의 저장소다(배타성이 이미 확인된 것).
	Workspace *compose.Workspace
	// Policy는 target별 닫힌 목록을 준다(등재 env 키·볼륨 튜플).
	Policy func(target Target) compose.Policy
	// AppService는 호스트 env DEPLOY_APP_SERVICE다 — CP-3 3자 일치의 호스트 쪽 한 자리.
	AppService string
	// HostPort는 슬롯별 호스트 포트 값이다(키: "blue"·"green"·compose.SlotSingle).
	HostPort map[string]string
	// ConfigValue는 등재 env 키의 호스트 값을 준다(agent 자기 프로세스 env — CP-5).
	// 값의 소유는 호스트 .env이고 compose에는 키만 실린다(리터럴 값 동봉 폐지 — rev.2.1 C2).
	ConfigValue func(key string) (string, bool)
	// Bind는 candidate에 결박된 실행기·헬스를 만든다(main이 주입).
	Bind func(slot string, b ComposeBinding) (HostExecutor, HealthChecker, error)
	// AllowLegacy는 무동봉 manifest를 수락할지다. **기본은 false = 동봉 필수**(R7) —
	// true는 명시 opt-in(DEPLOY_ALLOW_LEGACY_COMPOSE=1)이며 과도기 전용이다.
	AllowLegacy bool
}

// composePlan은 한 배포의 동봉 실행 계획이다(nil = legacy 경로). preflight가 만들고,
// 슬롯이 정해진 뒤 bind가 candidate를 기록하며, 성공 후 promote가 승격한다.
type composePlan struct {
	rt       *ComposeRuntime
	manifest Manifest
	content  []byte
	revHex   string
	spec     compose.Spec
}

// composePreflight는 **부작용이 생기기 전에** 동봉 결박을 전부 판정한다(B4' — preflight
// 실패는 파일을 하나도 남기지 않는다). 순서가 곧 계약이다:
//
//	REQUIRE 게이트 → 배선 확인 → 해시 선대조(manifest가 이미 마쳤다) → CP-3 3자 일치
//	→ 구조 allowlist(CP-7) → 주입값 존재 확인
//
// legacy(무동봉)는 여기서 nil 계획으로 빠져나가며, 수락됐다는 사실 자체가 WARN 로그로
// 남는다 — 조용한 폴백을 만들지 않기 위해서다(이력 표기는 coordinator가 detail code로 남긴다).
func (d LocalDispatcher) composePreflight(m Manifest) (*composePlan, error) {
	rt := d.Compose
	if !m.ComposeEmbedded() {
		if rt == nil || !rt.AllowLegacy {
			return nil, fmt.Errorf("%w: DEPLOY_ALLOW_LEGACY_COMPOSE=1로 명시 허용하지 않는 한 무동봉 배포는 거절한다(부작용 0 · 다운그레이드 차단 · R7)", ErrManifestComposeRequired)
		}
		log.Printf("경고: %s — 무동봉 manifest를 호스트 compose 파일 경로로 수락했다(target=%s requestId=%s). 과도기 전용이며 DEPLOY_ALLOW_LEGACY_COMPOSE 제거가 이관 완료 조건이다",
			ComposePathLegacy, m.Target, m.RequestID)
		return nil, nil
	}

	if rt == nil || rt.Workspace == nil || rt.Bind == nil || rt.Policy == nil {
		return nil, fmt.Errorf("%w: 동봉 manifest가 왔으나 workspace·binder가 배선되지 않았다(부작용 0 · fail-closed)", ErrComposeWiring)
	}

	// CP-1 — 해시 선대조는 manifest 층(EmbeddedCompose)이 소유한다. 여기서 다시 부르는 것은
	// 바이트를 층 사이로 들고 다니지 않기 위해서다(같은 순수 함수 · 같은 결과).
	content, revHex, err := m.EmbeddedCompose()
	if err != nil {
		return nil, err
	}

	// CP-3 — manifest.appService와 호스트 env가 먼저 맞아야 한다. 이 대조가 없으면 서명값이
	// 호스트의 사후조건 결박 대상과 다른 서비스를 가리켜도 배포가 진행된다(#21이 닫지 못한 축).
	if m.AppService != rt.AppService {
		return nil, fmt.Errorf("%w: manifest.appService=%q가 호스트 DEPLOY_APP_SERVICE=%q와 다르다(CP-3 상호 검증)", ErrComposePreflight, m.AppService, rt.AppService)
	}

	policy := rt.Policy(m.Target)
	policy.AppService = m.AppService
	spec, verr := compose.Validate(content, policy)
	if verr != nil {
		return nil, fmt.Errorf("%w[%s]: %v", ErrComposePreflight, compose.CodeOf(verr), verr)
	}

	plan := &composePlan{rt: rt, manifest: m, content: content, revHex: revHex, spec: spec}
	// 주입값이 하나라도 없으면 배포를 시작하지 않는다(CP-5 fail-closed) — compose가 요구하는
	// 키를 호스트가 갖고 있지 않으면 그 컨테이너는 빈 값으로 뜬다(조용한 오설정 기동).
	// 슬롯은 아직 모르므로 여기서는 config 키만 보고, 호스트 포트는 bind에서 본다.
	if _, _, ierr := plan.configValues(); ierr != nil {
		return nil, ierr
	}
	return plan, nil
}

// configValues는 compose가 pass-through로 요구한 등재 키의 **호스트 값**을 모은다.
func (p *composePlan) configValues() ([]string, map[string]string, error) {
	vals := map[string]string{}
	var kv []string
	for _, key := range p.spec.EnvKeys {
		v, ok := p.rt.ConfigValue(key)
		if !ok || v == "" {
			return nil, nil, fmt.Errorf("%w: compose가 요구하는 등재 키 %q의 값이 이 호스트에 없다(CP-5 — 값의 소유는 호스트 .env · fail-closed)", ErrComposePreflight, key)
		}
		vals[key] = v
		kv = append(kv, key+"="+v)
	}
	return kv, vals, nil
}

// injected는 이 슬롯의 subprocess에 넣을 닫힌 주입 집합을 만든다(B1” — 실효 설정 =
// 서명 바이트 + 이 집합). 이미지 참조는 여기 없다(up이 직접 주입한다).
func (p *composePlan) injected(slot string) ([]string, map[string]string, error) {
	kv, vals, err := p.configValues()
	if err != nil {
		return nil, nil, err
	}
	if p.spec.NeedsHostPort {
		port, ok := p.rt.HostPort[slot]
		if !ok || port == "" {
			return nil, nil, fmt.Errorf("%w: compose가 ports를 선언했는데 슬롯 %q의 호스트 포트(DEPLOY_HOST_PORT)가 배선되지 않았다(fail-closed)", ErrComposePreflight, slot)
		}
		vals[compose.HostPortVar] = port
		kv = append(kv, compose.HostPortVar+"="+port)
	}
	sort.Strings(kv) // 결정적 순서 — argv/env 비교가 실행마다 흔들리지 않게
	return kv, vals, nil
}

// bind는 이 슬롯의 candidate를 기록하고 그 경로에 결박된 실행기·헬스를 만든다.
// **여기서부터 부작용이 생긴다**(candidate 파일). 실패해도 승격은 없으므로 잔류 candidate는
// 무해하며 GC 대상이다(B4' 재기술).
func (p *composePlan) bind(slot string) (HostExecutor, HealthChecker, map[string]string, error) {
	kv, vals, err := p.injected(slot)
	if err != nil {
		return nil, nil, nil, err
	}
	target := string(p.manifest.Target)
	cand, werr := p.rt.Workspace.WriteCandidate(target, slot, p.revHex, p.content)
	if werr != nil {
		if compose.CodeOf(werr) == compose.CodeStorageIntegrity {
			return nil, nil, nil, fmt.Errorf("%w: %v", ErrComposeStorage, werr)
		}
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrComposePreflight, werr)
	}
	// 실행 직전 재확인 — 기록과 up 사이에 .env가 생기면 서명 밖 값이 보간에 섞인다.
	if eerr := p.rt.Workspace.CheckNoDotEnv(target, slot); eerr != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrComposePreflight, eerr)
	}
	exec, health, berr := p.rt.Bind(slot, ComposeBinding{
		ComposeFile:      cand.Path,
		ProjectDirectory: cand.ProjectDirectory,
		Injected:         kv,
	})
	if berr != nil {
		return nil, nil, nil, fmt.Errorf("%w: candidate 결박 실행기 조립 실패: %v", ErrComposeWiring, berr)
	}
	if exec == nil || health == nil {
		return nil, nil, nil, fmt.Errorf("%w: candidate 결박 실행기·헬스가 비었다", ErrComposeWiring)
	}
	return exec, health, vals, nil
}

// promote는 **배포가 성공한 뒤에만** 호출된다(B4'). 승격 실패는 배포 결과를 뒤집지 않는다:
// 컨테이너는 실제로 떴고 트래픽도 옮겨졌으므로 UNKNOWN으로 접으면 사람을 부르면서도 실상은
// "복원 재료 기록만 실패"다. 대신 요란하게 로그를 남긴다 — 다음 배포가 다시 기록한다.
func (p *composePlan) promote(slot string, injected map[string]string) {
	target := string(p.manifest.Target)
	rec := compose.AppliedRecord{
		Revision:    p.revHex,
		Slot:        slot,
		ImageDigest: p.manifest.ImageDigest,
		CommitSHA:   p.manifest.CommitSHA,
		RequestID:   p.manifest.RequestID,
		TS:          time.Now().UTC().Format(time.RFC3339),
		Injected:    injected,
		Status:      "applied",
	}
	if err := p.rt.Workspace.Promote(target, rec); err != nil {
		log.Printf("경고: 배포는 성공했으나 applied 인덱스 승격 실패(수동 복원 재료가 이번 배포를 담지 못한다 — 배포 결과는 뒤집지 않는다) target=%s rev=%s: %v", target, p.revHex[:12], err)
		return
	}
	// GC는 승격 뒤에만 돈다 — 승격 전에 돌리면 방금 쓴 candidate가 pin되기 전에 지워질 수 있다.
	pinned, perr := p.runningRevisions()
	if perr != nil {
		// pin 목록을 모르면 삭제하지 않는다(G-10 — 모르면 지우지 않는다).
		log.Printf("경고: 세대 GC 중단(pin 대상 확정 실패 — 삭제 0) target=%s: %v", target, perr)
		return
	}
	if err := p.rt.Workspace.GC(target, pinned); err != nil {
		log.Printf("경고: 세대 GC 실패(무해 — 다음 배포가 재시도한다) target=%s: %v", target, err)
	}
}

// runningRevisions는 GC가 무조건 pin해야 할 revision들을 준다: 이번 배포의 revision +
// applied 이력에서 **슬롯마다 가장 최근** 것(= 그 슬롯이 지금 돌리고 있을 정의).
// applied[0]·[1]은 workspace.GC가 자체적으로 pin하므로 여기서는 슬롯 축만 채운다.
func (p *composePlan) runningRevisions() ([]string, error) {
	applied, err := p.rt.Workspace.Applied(string(p.manifest.Target))
	if err != nil {
		return nil, err
	}
	pinned := []string{p.revHex}
	seenSlot := map[string]bool{}
	for _, rec := range applied {
		if rec.Slot == "" || seenSlot[rec.Slot] {
			continue
		}
		seenSlot[rec.Slot] = true
		pinned = append(pinned, rec.Revision)
	}
	return pinned, nil
}
