package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
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

	// 구조 allowlist(CP-7)를 CP-3 호스트 대조보다 **먼저** 본다(리뷰 E-8). 순서가 계약인
	// 이유: 두 위반이 겹친 입력(구조도 틀렸고 호스트 배선과도 다르다)에서 어느 코드가 나오는지가
	// 진단의 출발점을 정한다. 구조 위반은 "이 compose는 애초에 실행될 수 없다"이고 CP-3
	// 불일치는 "이 호스트가 배포할 대상이 아니다"라, 전자를 먼저 알려야 CI를 고치러 간다.
	// 여기서 쓰는 appService는 **manifest의 값**이다 — compose 정의와 서명값이 먼저 맞아야
	// 하고, 그 다음에 호스트 배선과 맞춘다(3자 일치를 두 단계로 닫는다).
	policy := rt.Policy(m.Target)
	policy.AppService = m.AppService
	spec, verr := compose.Validate(content, policy)
	if verr != nil {
		return nil, fmt.Errorf("%w[%s]: %v", ErrComposePreflight, compose.CodeOf(verr), verr)
	}

	// CP-3 마지막 한 자리 — 서명값과 호스트 env. 이 대조가 없으면 서명값이 호스트의 사후조건
	// 결박 대상과 다른 서비스를 가리켜도 배포가 진행된다(#21이 닫지 못한 축).
	if m.AppService != rt.AppService {
		return nil, fmt.Errorf("%w: manifest.appService=%q가 호스트 DEPLOY_APP_SERVICE=%q와 다르다(CP-3 상호 검증)", ErrComposePreflight, m.AppService, rt.AppService)
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
		// 분류가 갈리는 자리다(리뷰 E-11): revision 형식 위반은 **요청에서 온 값**이라 422이고,
		// 저장 무결성 장애는 이 호스트의 디스크 문제라 500이다. 뭉치면 CI가 자기 산출물 대신
		// 남의 디스크를 의심하거나 그 반대가 된다.
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

// ComposePromotionFailed는 배포는 성공했으나 applied 승격이 실패했음을 이력에 남기는
// 코드다(리뷰 E-2). 배포 결과를 뒤집지 않는 대신 **요청별로 이력에 드러난다** — 그러지
// 않으면 나중에 "이 배포의 복원 재료가 왜 없는가"를 되짚을 근거가 아무 데도 없다.
const ComposePromotionFailed = "APPLIED_INDEX_PROMOTION_FAILED"

// promote는 **배포가 성공한 뒤에만** 호출된다(B4'). 승격 실패는 배포 결과를 뒤집지 않는다:
// 컨테이너는 실제로 떴고 트래픽도 옮겨졌으므로 UNKNOWN으로 접으면 사람을 부르면서도 실상은
// "복원 재료 기록만 실패"다. 대신 WARN 로그 + 이력 detail 표기를 남긴다 — 다음 배포가
// 다시 기록하되, 이번에 남기지 못했다는 사실 자체는 사라지지 않는다.
func (p *composePlan) promote(ctx context.Context, slot string, injected map[string]string) {
	target := string(p.manifest.Target)
	rec := compose.AppliedRecord{
		Revision:    p.revHex,
		Slot:        slot,
		ImageDigest: p.manifest.ImageDigest,
		CommitSHA:   p.manifest.CommitSHA,
		RequestID:   p.manifest.RequestID,
		TS:          time.Now().UTC().Format(time.RFC3339),
		Injected:    injected,
		Status:      compose.StatusApplied,
	}
	if err := p.rt.Workspace.Promote(target, rec); err != nil {
		log.Printf("경고: %s — 배포는 성공했으나 applied 인덱스 승격 실패(수동 복원 재료가 이번 배포를 담지 못한다 · 배포 결과는 뒤집지 않는다) target=%s rev=%s: %v",
			ComposePromotionFailed, target, p.revHex[:12], err)
		addWarning(ctx, "composePromotion="+ComposePromotionFailed)
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

// bindActive는 **구 active 슬롯을 내릴 실행기**를 그 슬롯이 실제로 떠 있는 정의에 결박한다
// (리뷰 E-7). 결박 없이 기존 SlotExec로 down하면 `-f`가 이번 배포의 파일도, 그 슬롯이 뜰 때
// 쓴 파일도 아닌 **호스트의 옛 compose 파일**을 가리킨다 — compose는 프로젝트 라벨로 컨테이너를
// 찾지만 프로젝트 로드 자체가 그 파일 기준이라, 정의가 어긋나면 down이 무엇을 내리는지가
// 서명 밖에서 정해진다(동봉 필수 호스트에는 그 파일이 아예 없을 수도 있다).
//
// 정의의 출처는 applied 인덱스의 **그 슬롯 최근 record**다: 승격은 배포 성공 뒤에만 일어나므로
// 그 record가 곧 "그 슬롯이 지금 돌리고 있는 것"이다. injected·이미지 placeholder도 그 record의
// 문맥으로 넣는다(이번 배포의 주입값을 쓰면 남의 컨테이너를 우리 값으로 해석하게 된다).
//
// 호스트 compose 파일로의 폴백은 **legacy opt-in이 켜져 있을 때만** 허용한다. 그 경로가
// 필요한 상황은 하나뿐이다 — 이관 중 첫 동봉 배포에서 구 컨테이너가 아직 legacy로 떠 있는
// 때. 그 창을 opt-in으로 막지 않으면, 동봉 배포가 **서명되지 않은 호스트 파일로 down하는**
// fail-open이 상시로 열려 있게 된다(결박의 목적이 정확히 그것을 막는 것이다).
//
// 폴백하지 않는 경우가 셋이고 전부 fail-closed다:
//
//	applied 손상  — "record가 없다"가 아니라 "알 수 없다".
//	record 부재 + opt-in 없음 — 위 창 밖의 record 부재는 정상 상태가 아니다.
//	세대 파일 무결성 실패 — 아래 재해시 참조.
func (p *composePlan) bindActive(slot string, fallback HostExecutor) (HostExecutor, func(), error) {
	noCleanup := func() {}
	target := string(p.manifest.Target)
	applied, err := p.rt.Workspace.Applied(target)
	if err != nil {
		return nil, noCleanup, fmt.Errorf("%w: 구 active 슬롯(%s)의 실행 정의를 확정할 수 없다(applied 인덱스 손상 — legacy 파일로 폴백하지 않는다): %v", ErrComposeStorage, slot, err)
	}
	var found *compose.AppliedRecord
	for i := range applied {
		if applied[i].Slot == slot {
			found = &applied[i]
			break
		}
	}
	if found == nil {
		// 이 슬롯이 동봉 경로로 뜬 적이 없다. 이관 과도기(구 컨테이너가 legacy로 떠 있는
		// 첫 동봉 배포)에서만 기존 배선으로 내린다 — 그 밖에서는 거절이다.
		if !p.rt.AllowLegacy {
			return nil, noCleanup, fmt.Errorf("%w: 구 active 슬롯(%s)의 applied record가 없다 — 동봉 배포에서 서명되지 않은 호스트 compose 파일로 down하지 않는다(이관 과도기라면 %s=1로 명시 허용한다 · fail-closed)", ErrComposeStorage, slot, "DEPLOY_ALLOW_LEGACY_COMPOSE")
		}
		if fallback == nil {
			return nil, noCleanup, fmt.Errorf("%w: 구 active 슬롯(%s)의 실행 정의도, 기존 배선도 없다", ErrComposeWiring, slot)
		}
		log.Printf("경고: %s — 구 active 슬롯(%s)에 applied record가 없어 호스트 compose 파일로 내린다(이관 과도기 전용 · target=%s requestId=%s)",
			ComposePathLegacy, slot, target, p.manifest.RequestID)
		return fallback, noCleanup, nil
	}
	path := p.rt.Workspace.CandidatePath(target, slot, found.Revision)
	// 존재 확인만으로는 부족하다: 세대 파일은 파일명이 곧 내용 해시라는 계약 위에 서 있고,
	// 그 계약은 **파일을 실제로 읽어 재대조할 때만** 증명된다(WriteCandidate의 기존 파일
	// 재해시와 같은 수법). 변조·절단된 파일을 이름만 믿고 넘기면, 우리가 "그 슬롯이 돌리는
	// 정의"라고 부르는 것이 사실은 누군가 바꿔 놓은 것이 된다.
	body, rerr := os.ReadFile(path) //nolint:gosec // workspace 안에서 해시로 결정된 경로
	if rerr != nil {
		return nil, noCleanup, fmt.Errorf("%w: 구 active 슬롯(%s)의 세대 파일을 읽을 수 없다(rev=%s) — 무엇을 내리는지 증명할 수 없다: %v", ErrComposeStorage, slot, shortRev(found.Revision), rerr)
	}
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != found.Revision {
		return nil, noCleanup, fmt.Errorf("%w: 구 active 슬롯(%s)의 세대 파일이 기록된 revision과 다르다(기대=%s 실제=%s) — 변조·절단된 정의로 down하지 않는다(legacy 폴백도 하지 않는다)", ErrComposeStorage, slot, shortRev(found.Revision), shortRev(hex.EncodeToString(sum[:])))
	}

	// 잔재 회수(위생) — 프로세스가 down 도중 죽거나 삭제가 실패하면 tmp에 스냅샷이 남고,
	// GC는 이 디렉터리를 통째로 건너뛰므로(세대가 아니다) 아무도 치우지 않으면 영구 누적된다.
	// **이번 요청 파일을 만들기 전에** 돌려 이름 충돌 여지를 없앤다. 실패는 배포를 막지
	// 않는다 — 남은 파일은 어떤 판정에도 들지 않으므로 청소 실패가 무결성 문제가 아니다.
	if _, failed := p.rt.Workspace.SweepStaleSnapshots(target, snapshotSweepAge); failed > 0 {
		log.Printf("경고: 오래된 실행 스냅샷 %d건을 회수하지 못했다(누적만 남는다 · 배포는 진행) target=%s", failed, target)
	}

	// 검증한 **바이트 자체**를 실행 전용 스냅샷으로 굳혀 결박한다. 세대 파일 경로를 그대로
	// 넘기면 검증(지금)과 사용(전환·드레인 뒤의 down) 사이에 창이 남는데, 그 창에는 idle
	// 기동·헬스·라우트 전환·드레인이 통째로 들어간다 — 재검증을 뒤로 미루는 것으로는 좁아질
	// 뿐 없어지지 않는다. 스냅샷을 쓰면 원본이 그 뒤 어떻게 바뀌든 실행되는 내용은 검증된
	// 것 그대로다(불변 버퍼 결박).
	snapPath, serr := p.rt.Workspace.WriteSnapshot(target, downSnapshotName(slot, p.manifest.RequestID), body)
	if serr != nil {
		return nil, noCleanup, fmt.Errorf("%w: 구 active 슬롯(%s)의 실행 스냅샷을 만들 수 없다 — 검증한 바이트를 결박하지 못한 채 down하지 않는다: %v", ErrComposeStorage, slot, serr)
	}
	cleanup := func() { p.rt.Workspace.RemoveSnapshot(snapPath) }

	// 실행 기준 디렉터리가 tmp로 옮겨졌으므로 `.env` 부재도 그 자리에서 다시 본다 —
	// compose는 --project-directory의 .env를 자동으로 읽고, 그 값은 서명 밖이다. candidate
	// 디렉터리에서만 확인하고 여기를 빠뜨리면 결박이 한 조각 비어 있게 된다.
	if eerr := p.rt.Workspace.CheckNoDotEnv(target, compose.SnapshotDir); eerr != nil {
		cleanup()
		return nil, noCleanup, fmt.Errorf("%w: 구 active 슬롯(%s)의 실행 기준 디렉터리에 .env가 있다: %v", ErrComposeStorage, slot, eerr)
	}

	kv := make([]string, 0, len(found.Injected))
	for k, v := range found.Injected {
		kv = append(kv, k+"="+v)
	}
	sort.Strings(kv)
	exec, _, berr := p.rt.Bind(slot, ComposeBinding{
		ComposeFile: snapPath,
		// 실행 기준 디렉터리는 스냅샷이 있는 tmp다 — compose가 상대 경로·.env를 해석하는
		// 기준까지 스냅샷과 함께 움직여야 결박이 한 조각으로 성립한다.
		ProjectDirectory: filepath.Dir(snapPath),
		Injected:         kv,
	})
	if berr != nil {
		cleanup()
		return nil, noCleanup, fmt.Errorf("%w: 구 active 슬롯(%s) 실행기 결박 실패: %v", ErrComposeWiring, slot, berr)
	}
	return exec, cleanup, nil
}

// snapshotSweepAge는 잔재 스냅샷을 회수하기 시작하는 나이다. 배포 창 락 lease 기본값(6분)의
// 열 배로 둔다 — 지금 도는 배포(락 안에서 lease를 넘길 수 없다)의 파일을 절대 건드리지 않을
// 만큼 넉넉하면서, 죽은 프로세스가 남긴 것을 다음 배포가 치울 만큼은 짧다. 선언값이다.
const snapshotSweepAge = time.Hour

// downSnapshotName은 스냅샷 파일명을 만든다. requestId를 파일명에 그대로 쓰지 않는 이유:
// 그 값은 외부에서 오는 문자열이라 경로 구분자·`..`이 들어올 수 있다. 해시로 접으면 길이와
// 문자 집합이 고정되면서도 요청마다 갈려, 동시에 도는 다른 요청의 스냅샷과 섞이지 않는다.
func downSnapshotName(slot, requestID string) string {
	sum := sha256.Sum256([]byte(requestID))
	return "down-" + slot + "-" + hex.EncodeToString(sum[:])[:16] + ".yml"
}

// shortRev는 로그·오류 메시지용 축약 revision이다.
func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
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
