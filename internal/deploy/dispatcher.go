package deploy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jun-bank/infra/internal/compose"
	"github.com/jun-bank/infra/internal/store"
)

// CleanupTimeout은 실패 후 정리(down)에 쓰는 detached context의 상한이다. 정리 down은
// 요청 ctx가 취소·타임아웃됐어도 완주해야 net-0 복원(미전환)이 성립하므로, 요청 ctx와
// 분리한 context.WithoutCancel + 이 상한으로 실행한다(coordinator 락 해제와 같은 패턴).
// 전환 성공 후의 구 slot 종료(⑨)도 같은 상한을 쓴다 — 그 down도 요청 취소와 무관하게
// 완주해야 잔존 프로세스가 남지 않는다.
// exported — main이 배포 창 락 lease 하한식(lease ≥ phaseBudget + D + CleanupTimeout +
// 전환 예산 + slack)의 입력으로 읽는다(cleanup·전환이 락 안에서 완주하도록 보증 — P4).
// ⚠️ [구현 검증]: 실제 compose down 소요와 함께 튜닝한다.
const CleanupTimeout = 30 * time.Second

// 실행 지점(#15 S2-3 · #26 CD-4 ⑤⑥⑨) — 검증되고 락을 보유한 manifest를 자기 호스트에서
// 실제로 실행한다. 순서:
//
//	게이트웨이 미설정(단일 경로 · 하위호환): pull(②) → up(③) → 이미지 대조 → CD-1 헬스(④)
//	게이트웨이 설정 + target=core(블루-그린): active slot 조회 → idle slot에 ②③④ →
//	                                         라우트 전환(⑤) → 드레인(⑥) → 구 slot down(⑨)
//	게이트웨이 설정 + target=gateway:        단일 경로(자기 전환 불가 — 재기동 교체 DO-20 ⓐ)
//	게이트웨이 설정 + 그 밖의 대상:          거절(부작용 0) — 슬롯 배선은 core 라우트 전용이다
//
// 전문 채널 축(⑦ 수신 정지·⑧ listener 활성)은 이 범위 밖이다 — SCG를 지나지 않는 채널이라
// RL-3·CD-4 ⑦⑧이 따로 소유한다(ADR-031 BG-3 ⑴). 여기서 성립하는 드레인은 사람 채널뿐이다.
//
// 계약 출처(정본 — 재해석하지 않는다):
//   - ADR-027 DO-16  (원격/로컬 실행 3상태 — 아래 매핑)
//   - ADR-027 DO-18  (pull·up은 digest로 고정 · 이미지 참조 = <repo>@<digest>)
//   - ADR-027 DO-20  (배포 대상 넷 · 게이트웨이는 자기 전환 불가 = 재기동 교체 — ⓐ)
//   - ADR-031 BG-2   (CD-1 헬스를 통과한 뒤에만 라우트를 옮긴다)
//   - ADR-031 BG-3   (드레인 후 blue만 down · blue/green은 별개 compose project)
//   - ADR-031 BG-4   (전환은 락 보유 단계 · fencing token을 전환 요청에 동봉해
//     stale 실행자의 라우트 write를 sink-side에서 거절시킨다 — 허용 형태 ⓐ)
//   - operations/cicd.md CD-4 ②④ 및 부분 실패 전이
//     (⑤ 실패 = 미전환·green 정리 / ⑤ 이후 실패 = 락 유지·사람에게 = UNKNOWN)
//   - ADR-029 IA-5   (소비 지점 인터페이스 · 닫힌 import — HostExecutor·HealthChecker·
//     SlotGateway를 여기서 정의하고 internal/dispatch가 구현을 제공, main이 조립·주입한다)

// HostExecutor는 dispatch 모듈이 제공하는 특권 명령 실행 표면이다(IA-5 — 소비 지점
// 인터페이스). 열거된 명령만 노출한다: pull·up·down. status 계열 조회는 헬스 판정이
// 내부에서 쓴다. 블루-그린 모드에서는 슬롯마다 하나씩(각자의 compose file·project)
// 주입된다 — down이 프로젝트 단위라 blue만 끄려면 프로젝트가 갈려 있어야 한다(BG-3 ⑶).
type HostExecutor interface {
	// Pull은 digest 고정 참조(<repo>@sha256:...)를 pull한다.
	Pull(ctx context.Context, imageRef string) error
	// Up은 green 프로젝트를 compose up한다(digest 고정 참조 주입).
	Up(ctx context.Context, imageRef string) error
	// VerifyImageDigest는 up으로 실제 뜬 컨테이너들의 이미지가 pinned digest 참조와
	// 일치하는지 증명한다(DO-16 ⑶). 불일치·조회 불가·컨테이너 없음이면 오류.
	VerifyImageDigest(ctx context.Context, imageRef string) error
	// Down은 green 프로젝트만 compose down한다(이미지는 남긴다 — RL-5).
	Down(ctx context.Context) error
}

// HealthChecker는 CD-1 준비성 판정 표면이다. nil이면 healthy, error면 미통과다.
type HealthChecker interface {
	Check(ctx context.Context) error
}

// Slot은 블루-그린 슬롯 이름의 닫힌 집합이다. 어느 쪽이 "신 버전"인지는 고정이 아니다 —
// 배포는 늘 지금 트래픽을 받지 않는 쪽(idle)에 새 버전을 올리고, 전환 뒤 구 active를 접는다.
type Slot string

const (
	SlotBlue  Slot = "blue"
	SlotGreen Slot = "green"
)

// valid는 슬롯 이름이 닫힌 집합에 속하는지 본다(게이트웨이가 낯선 값을 주면 fail-closed).
func (s Slot) valid() bool { return s == SlotBlue || s == SlotGreen }

// other는 반대 슬롯이다(active의 반대 = 이번 배포가 올릴 idle).
func (s Slot) other() Slot {
	if s == SlotBlue {
		return SlotGreen
	}
	return SlotBlue
}

// SlotGateway는 라우트 전환 표면이다(ADR-031 BG-1 — SCG 라우트가 전환 수단이다).
// 소비 지점 인터페이스이며(IA-5) internal/dispatch가 HTTP 클라이언트로 구현한다.
// 슬롯·토큰을 문자열/정수로 받아 구현 쪽이 이 패키지를 import하지 않게 한다.
type SlotGateway interface {
	// ActiveSlot은 지금 트래픽을 받는 슬롯을 조회한다(부작용 없는 GET — 배포 시작 전에
	// 부른다). 조회 실패는 아직 아무것도 건드리지 않은 시점이므로 부작용 0이다.
	ActiveSlot(ctx context.Context) (string, error)
	// Switch는 라우트를 targetSlot으로 옮긴다(CD-4 ⑤). fencingToken은 이 배포가 보유한
	// 배포 창 락의 토큰이며, 게이트웨이가 stale 실행자의 write를 거절하는 근거다
	// (BG-4 ⓐ sink-side 조건부 갱신 — 재확인과 write 사이의 창을 sink에서 닫는다).
	Switch(ctx context.Context, targetSlot string, fencingToken uint64) error
}

// LocalDispatcher는 실 실행 지점이다. StubDispatcher를 대체해 Dispatcher를 만족한다.
type LocalDispatcher struct {
	// Exec·Health는 단일 경로(게이트웨이 미설정 · target=gateway)의 실행기·헬스다.
	Exec   HostExecutor
	Health HealthChecker
	// Repos는 Target별 이미지 repo다(env IMAGE_CORE/… 에서 조립). 이미지 참조는
	// Repos[target] + "@" + manifest.ImageDigest 로 고정한다(DO-18 ⑵).
	Repos map[Target]string
	// PhaseBudget은 pull+up 단계의 상한이다(P3). 상한 없는 pull/up이 배포 창 락 lease
	// 마진을 초과해 정상 배포 도중 락이 만료되는 것을 막는다 — 이 budget으로 pull·up을
	// 감싸 초과 시 취소·실패시킨다. main이 lease ≥ PhaseBudget + D + CleanupTimeout +
	// 전환 예산 + slack 을 시동 시 검증해 dispatch 전체가 락 안에 들어가도록 배선한다(P4).
	PhaseBudget time.Duration

	// --- 블루-그린 전환(CD-4 ⑤⑥⑨). Gateway가 nil이면 아래 넷은 쓰이지 않고 기존 단일
	// 경로가 그대로 돈다(하위호환 — 게이트웨이가 없는 환경의 동작을 바꾸지 않는다).

	// Gateway는 라우트 전환 표면이다. nil = 전환 단계 없음(④까지 = COMPLETED).
	Gateway SlotGateway
	// SlotExec는 슬롯별 특권 실행기다(각자 자기 compose file·project를 들고 있다).
	SlotExec map[Slot]HostExecutor
	// SlotHealth는 슬롯별 CD-1 프로버다(각자 자기 슬롯의 준비성 URL을 본다).
	SlotHealth map[Slot]HealthChecker
	// DrainWait은 전환 후 구 active slot의 in-flight 소진을 기다리는 시간이다(CD-4 ⑥).
	// ⚠️ [구현 검증] IV-17/CDV-2: BG-3 ⑵의 완료 판정은 "수신 차단이 선 뒤 처리 중 요청
	// 0건"이고, v1의 이 고정 대기는 그 판정의 **선언값 대체물**이다 — 무엇을 계수하나
	// (SCG 연결 수·앱 자기 신고)와 임계값이 정해지면 이 자리가 실관측으로 바뀐다.
	// 그때까지 이 값은 "이 시간이면 in-flight가 끝난다"는 가정이며, 가정이 틀리면
	// 진행 중 요청이 down에서 절단된다(대기값을 늘리는 것이 유일한 완화다).
	DrainWait time.Duration

	// Compose는 동봉 compose 실행 배선이다(infra#19). 설정되면 동봉 manifest는 검증→
	// candidate 기록→그 candidate로만 up 하고, 무동봉 manifest는 AllowLegacy일 때만
	// 기존 호스트 compose 경로로 흐른다. nil이면 동봉 배포를 수행할 수 없다(과도기 호스트).
	Compose *ComposeRuntime
}

// 컴파일 타임 계약 확인 — LocalDispatcher는 Dispatcher다.
var _ Dispatcher = LocalDispatcher{}

// Dispatch는 검증된 manifest를 실행하고 세 상태 중 하나를 낸다(DO-16). 상태 매핑:
//
//   - UNEXECUTED(+err): 부작용 순net 0이 증명됨 — repo 미설정·digest 형식 위반·배선 부재·
//     대상 불일치·토큰 범위 위반·active slot 조회 실패(전부 배포 시작 전)·pull 실패(CD-4 ②),
//     또는 up/헬스 실패, 그리고 게이트웨이가 미전환을 보증한 전환 실패(state=ROLLED_BACK)
//     뒤에 green을 성공적으로 down해 미전환(net 0)으로 되돌린 경우(CD-4 ④ · ⑤ 실패 전이).
//     갓 pull된 로컬 이미지는 위반 부작용이 아니다(RL-5가 보존을 요구 — Q5).
//   - COMPLETED: green up + CD-1 헬스 통과(게이트웨이 모드면 전환·드레인·구 slot 종료까지).
//   - UNKNOWN(+err): 변이 명령을 던진 뒤 정리(down)마저 실패·불명 = green이 떠 있을 수
//     있다. 또는 라우트 전환(⑤) 성공 후 드레인·구 slot 종료(⑨)가 실패해 신·구 두 프로세스가
//     남았을 수 있다. ⑤ 실패 중 미전환이 보증되지 않은 것(stale 409 = 소유권 상실 ·
//     INDETERMINATE · 전송 실패)도 여기다 — 정리하지 않고 올린 컨테이너를 남긴 채 사람에게
//     넘긴다. 스스로 재시도하지 않는다(Q4) — 락 유지·사람 개입은 coordinator가 한다.
//     ⚠️ 이 경로의 오류 메시지는 사람 개입의 유일한 단서다 — 어느 단계가 실패했는지 반드시
//     담는다(coordinator가 detail로 이력에 persist한다).
//
// mutate 명령(pull/up/down/switch)은 각각 정확히 1회만 실행한다 — 자체 재시도 루프를 돌리지
// 않는다(Q4). UNKNOWN 해소(status 조회→완료/재개/에스컬레이션)는 coordinator/replay 층
// (ClassifyReplay)이 소유한다.
func (d LocalDispatcher) Dispatch(ctx context.Context, m Manifest, token store.FencingToken) (RemoteState, error) {
	imageRef, err := d.imageRef(m)
	if err != nil {
		return StateUnexecuted, err
	}

	// 동봉 결박의 preflight(infra#19 · CP-1/CP-3/CP-7) — 해시 선대조·구조 allowlist·3자 일치·
	// 주입값 존재를 여기서 전부 본다. **파일을 하나도 쓰지 않는다**(부작용 0 거절 · B4').
	// legacy(무동봉)는 nil 계획으로 통과하며, 그 수락 자체가 REQUIRE 게이트를 지난 것이다.
	plan, err := d.composePreflight(m)
	if err != nil {
		return StateUnexecuted, err
	}

	switch {
	// 게이트웨이 미설정 = 전환 단계가 없는 기존 단일 경로 그대로다(하위호환) — 이 호스트의
	// 배포 대상이 무엇이든 자기 슬롯 없이 pull→up→대조→헬스로 끝난다.
	case d.Gateway == nil:
		return d.runSinglePath(ctx, imageRef, plan)

	// 블루-그린 전환은 **core 대상에만** 성립한다. 슬롯 배선(SlotExec·SlotHealth)과
	// 게이트웨이 라우트는 core 라우트 하나에 결박돼 있다 — 게이트웨이 클라이언트가 보는
	// 경로가 /internal/routes/core 고정이기 때문이다(BG-3 ⑴ — 사람 채널 앞단의 코어 라우트).
	// 그래서 대상을 보지 않고 이 경로로 들어오면 settlement/ledger 이미지가 core의 슬롯을
	// 덮어쓰고, 그 위에 core 라우트가 전환된다(대상 뒤바뀜 — 치명).
	case m.Target == TargetCore:
		return d.dispatchBlueGreen(ctx, imageRef, token, plan)

	// target=gateway는 단일 경로다 — 게이트웨이는 전환 수단의 소유자라 자기 블루-그린을
	// 자기가 전환할 수 없다(자기 참조). v1은 재기동 교체다(DO-20 ⓐ · 짧은 중단 수용).
	case m.Target == TargetGateway:
		return d.runSinglePath(ctx, imageRef, plan)

	// 나머지(settlement·ledger)는 이 호스트의 배포 대상이 아니다. 조용히 core 슬롯으로
	// 흘려보내지 않고 시작 전에 요란하게 거절한다(부작용 0 · fail-closed).
	default:
		return StateUnexecuted, fmt.Errorf("이 호스트에 해당 대상의 슬롯 배선이 없다 — target=%q는 블루-그린 슬롯(core 전용)도, 단일 경로 대상(gateway)도 아니다(부작용 0 · fail-closed · 대상 뒤바뀜 방지)", m.Target)
	}
}

// imageRef는 실행 대상 이미지 참조를 고정한다(DO-18 ⑵). repo 미설정·digest 형식 위반은
// 부작용 이전이므로 호출자가 UNEXECUTED로 접는다.
func (d LocalDispatcher) imageRef(m Manifest) (string, error) {
	repo, ok := d.Repos[m.Target]
	if !ok || repo == "" {
		return "", fmt.Errorf("대상 %q의 이미지 repo 미설정 — 부작용 0", m.Target)
	}
	// 방어적 재확인(coordinator의 VerifyManifest가 이미 봤지만, 특권 실행 직전 한 번 더 —
	// 태그·오타가 digest로 위장해 실행 대상 고정이 무너지는 것을 막는다).
	if !validSHA256Digest(m.ImageDigest) {
		return "", fmt.Errorf("image digest가 sha256: 고정 형식이 아니다(부작용 0): %q", m.ImageDigest)
	}
	return repo + "@" + m.ImageDigest, nil
}

// runSinglePath는 전환 단계가 없는 경로(게이트웨이 미설정 · target=gateway)를 수행한다.
// 동봉 계획이 있으면 실행기·헬스를 **이번 서명 바이트로 만든 candidate에 결박**해 새로
// 만들고, 성공 후 승격까지 마친다. 계획이 없으면(legacy) 기존 배선 그대로다.
func (d LocalDispatcher) runSinglePath(ctx context.Context, imageRef string, plan *composePlan) (RemoteState, error) {
	exec, health := d.Exec, d.Health
	var injected map[string]string
	if plan != nil {
		var err error
		exec, health, injected, err = plan.bind(compose.SlotSingle)
		if err != nil {
			return StateUnexecuted, err
		}
	}
	st, err := d.runGreenPhases(ctx, imageRef, exec, health)
	if st == StateCompleted && plan != nil {
		plan.promote(ctx, compose.SlotSingle, injected)
	}
	return st, err
}

// runGreenPhases는 새 버전을 올리는 ②③④를 한 실행기·한 헬스 대상으로 수행한다:
// pull → up → 이미지 무결성 대조 → CD-1 헬스. 통과면 COMPLETED, 실패면 green을 정리해
// 미전환(UNEXECUTED)으로 되돌리고 정리마저 실패하면 UNKNOWN이다.
//
// compose 결박(P2 · DO-18 ⑴ 갭)은 #19가 닫았다: 동봉 경로에서 exec·health는 이번 서명
// 바이트로 만든 candidate에 결박된 것이 넘어오므로, 호스트 compose 파일이 낡거나 변조돼
// 있어도 실행에 닿지 않는다. **legacy 경로(DEPLOY_ALLOW_LEGACY_COMPOSE=1)에는 그 갭이
// 그대로 남는다** — 호스트 compose 파일이 여전히 신뢰 설정이며, 그래서 그 경로는 명시
// opt-in이고 요청마다 이력에 표기된다.
//
// ⚠️ 남은 갭: ConfigVersion(DO-18 ⑸)은 아직 실행에 결박되지 않는다 — 애플리케이션 설정
// 스키마 버전을 무엇과 대조할지가 미정이다(후속).
func (d LocalDispatcher) runGreenPhases(ctx context.Context, imageRef string, exec HostExecutor, health HealthChecker) (RemoteState, error) {
	// 배선 부재는 실행 전이므로 부작용 0이다 — 조용히 건너뛰지 않고 요란하게 거절한다
	// (예: 게이트웨이 모드에서 target=gateway가 왔는데 단일 경로 설정이 없는 경우).
	if exec == nil || health == nil {
		return StateUnexecuted, fmt.Errorf("실행기·헬스 배선 없음 — 이 대상을 실행할 수 없다(부작용 0 · fail-closed)")
	}

	// pull+up+무결성대조 단계를 phase budget으로 감싼다(P3·H1) — 상한 없는 pull/up/inspect가
	// lease 마진을 초과해 정상 배포 도중 락이 만료되는 것을 막는다. 초과 시 그 단계가 취소돼
	// 실패로 접힌다. ⚠️ VerifyImageDigest도 이 예산 안에서 돌려야(⑶) 하한식이 조건부가 아니라
	// 구조적으로 성립한다 — 그러지 않으면 느린 docker inspect가 slack을 넘어 cleanup이 락
	// 만료 뒤 실행될 여지가 생긴다(H1). 헬스는 자체 Deadline D로 상한된다.
	phaseCtx, cancel := context.WithTimeout(ctx, d.PhaseBudget)
	defer cancel()

	// 1. 이미지 pull(digest 고정 — CD-4 ②). 실패 = 부작용 0(compose 미접촉) = UNEXECUTED.
	if err := exec.Pull(phaseCtx, imageRef); err != nil {
		return StateUnexecuted, fmt.Errorf("이미지 pull 실패(부작용 0 · CD-4 ②): %w", err)
	}

	// 2. green 기동(compose up · CD-4 ③). 실패 시(phase budget 초과 포함) 부분 기동이 남을 수
	//    있으므로 down으로 net-0 복원을 시도한다 — down 성공=미전환(UNEXECUTED), down 실패=
	//    green 잔존 가능(UNKNOWN). cleanup은 요청 ctx로 넘겨 phase budget 취소와 무관하게
	//    detached로 완주시킨다(아래 cleanupAfterFailure의 WithoutCancel).
	if err := exec.Up(phaseCtx, imageRef); err != nil {
		return cleanupAfterFailure(ctx, exec, "compose up 실패", err)
	}

	// 3. 이미지 무결성 대조(DO-16 ⑶ 사후조건). up이 env 주입 없이 :latest·오타 이미지를
	//    띄웠는데 헬스만 통과하면 엉뚱한 이미지가 COMPLETED로 위장한다 — 헬스 전에 실제 뜬
	//    이미지가 pinned digest인지 증명한다. 불일치·조회 불가면 green을 정리하고 미전환.
	//    phaseCtx로 상한해(H1) inspect 지연이 lease를 넘지 않게 한다 — 정리(cleanup)는 여전히
	//    요청 ctx 기반 detached이므로 phase 취소와 무관하게 완주한다.
	if err := exec.VerifyImageDigest(phaseCtx, imageRef); err != nil {
		return cleanupAfterFailure(ctx, exec, "이미지 무결성 대조 실패", err)
	}

	// 4. CD-1 헬스(CD-4 ④ · BG-2 전환 판정의 정본). 실패 → green 종료·blue 유지 = 미전환
	//    (롤백 아님). down 성공=UNEXECUTED(net-0), down 실패=green 잔존 가능(UNKNOWN).
	if err := health.Check(ctx); err != nil {
		return cleanupAfterFailure(ctx, exec, "CD-1 헬스 실패", err)
	}

	return StateCompleted, nil
}

// dispatchBlueGreen은 게이트웨이가 설정된 환경의 전 시퀀스다: active slot 조회 →
// idle slot에 ②③④ → 라우트 전환(⑤) → 드레인(⑥) → 구 active slot 종료(⑨).
//
// 실패 전이(cicd.md CD-4 부분 실패 전이 표 그대로):
//   - 조회·배선 실패 = 배포 시작 전이므로 부작용 0 = UNEXECUTED(fail-closed).
//   - ②③④ 실패 = green 정리 후 미전환(UNEXECUTED) · 정리 실패면 UNKNOWN.
//   - ⑤ 실패 = 게이트웨이가 준 **보증**으로 셋으로 갈린다(handleSwitchFailure 참조):
//     stale(409) = 정리 없이 UNKNOWN / ROLLED_BACK = green 정리 후 UNEXECUTED /
//     그 밖(INDETERMINATE·전송 실패·보증 없음) = 정리 없이 UNKNOWN.
//   - ⑤ 성공 후 ⑥⑨ 실패 = 라우트는 이미 옮겨졌다 = UNKNOWN(락 유지·사람) + 단계 명시.
//
// 동봉 계획(plan)이 있으면 idle 슬롯의 실행기·헬스는 **그 슬롯의 candidate에 결박된 것**으로
// 새로 만든다(active 슬롯의 실행기는 down에만 쓰이므로 기존 배선 그대로다 — 이미 떠 있는
// 프로젝트를 끄는 데 새 compose 파일이 필요하지 않고, 오히려 새 정의로 끄면 이번 배포의
// 정의로 남의 컨테이너를 다루게 된다).
func (d LocalDispatcher) dispatchBlueGreen(ctx context.Context, imageRef string, token store.FencingToken, plan *composePlan) (RemoteState, error) {
	// 0. 배선·설정 확인(실행 전 — 부작용 0). DrainWait이 0 이하면 드레인이 실질적으로
	//    사라져 in-flight를 절단한다 — 조용히 0으로 돌지 않고 거절한다(무음 축소 금지).
	if d.DrainWait <= 0 {
		return StateUnexecuted, fmt.Errorf("드레인 대기(CD-4 ⑥)가 %s로 설정돼 있다 — >0 이어야 한다(부작용 0 · fail-closed)", d.DrainWait)
	}
	// fencing token은 계약상 int64 양수(≥1)다 — 범위를 벗어난 토큰은 전환 요청에 실을 수
	// 없으므로, 이미지를 올린 뒤 전환 단계에서 애매하게 실패하지 않도록 시작 전에 거절한다
	// (부작용 0 · fail-closed).
	if token == 0 || uint64(token) > maxFencingToken {
		return StateUnexecuted, fmt.Errorf("fencing token이 계약 범위를 벗어났다(1..%d의 int64 양수여야 한다) — 배포 미시작(부작용 0 · fail-closed): token=%d", uint64(maxFencingToken), uint64(token))
	}

	// 1. 지금 트래픽을 받는 슬롯을 게이트웨이에 묻는다(부작용 없는 GET). 실패·미응답·낯선
	//    값이면 어느 슬롯이 idle인지 모른 채 배포하는 셈이라 아무것도 시작하지 않는다 —
	//    시작 전이므로 부작용 0(UNEXECUTED · fail-closed).
	raw, err := d.Gateway.ActiveSlot(ctx)
	if err != nil {
		return StateUnexecuted, fmt.Errorf("게이트웨이 active slot 조회 실패 — 배포 미시작(부작용 0 · fail-closed): %w", err)
	}
	active := Slot(raw)
	if !active.valid() {
		return StateUnexecuted, fmt.Errorf("게이트웨이가 낯선 active slot을 보고했다: %q (blue|green 이어야 한다 · 부작용 0 · fail-closed)", raw)
	}
	idle := active.other()

	idleExec, idleHealth := d.SlotExec[idle], d.SlotHealth[idle]
	activeExec := d.SlotExec[active]
	if idleExec == nil || idleHealth == nil {
		return StateUnexecuted, fmt.Errorf("슬롯 배선 부재(active=%s idle=%s) — compose file·project·헬스 URL이 슬롯마다 있어야 한다(부작용 0 · fail-closed)", active, idle)
	}

	// 1-b. 동봉 경로라면 여기서 두 슬롯의 실행기를 각자의 정의에 결박한다. 슬롯이 정해진
	//      뒤에야 할 수 있으므로 preflight와 갈라져 있다.
	//        idle   — 이번 서명 바이트로 만든 candidate(기록이 여기서 일어난다).
	//        active — applied 인덱스의 그 슬롯 최근 record = 지금 떠 있는 정의(E-7).
	//      idle 결박이 실패해도 승격은 없으므로 잔류 candidate는 무해하다(GC 대상 · B4').
	var injected map[string]string
	if plan != nil {
		aexec, releaseSnapshot, aerr := plan.bindActive(string(active), activeExec)
		// 스냅샷 정리는 **이 함수를 벗어날 때** 한다(성공·실패·UNKNOWN 무관) — down이
		// ⑨까지 가야 쓰이므로, 그 전에 지우면 결박한 파일이 실행 시점에 사라진다.
		defer releaseSnapshot()
		if aerr != nil {
			return StateUnexecuted, aerr
		}
		activeExec = aexec

		var berr error
		idleExec, idleHealth, injected, berr = plan.bind(string(idle))
		if berr != nil {
			return StateUnexecuted, berr
		}
	}
	if activeExec == nil {
		return StateUnexecuted, fmt.Errorf("구 active 슬롯(%s)의 실행기 배선이 없다 — 전환 후 그 슬롯을 내릴 수 없다(부작용 0 · fail-closed)", active)
	}

	// 2. ②③④ — 새 버전을 idle slot에 올리고 CD-1 헬스까지 통과시킨다. 여기까지의 실패는
	//    라우트를 건드리기 전이라 기존 전이(미전환·정리) 그대로다.
	if st, perr := d.runGreenPhases(ctx, imageRef, idleExec, idleHealth); st != StateCompleted {
		return st, fmt.Errorf("idle slot(%s) 기동·검증 실패(라우트 미접촉): %w", idle, perr)
	}

	// 3. ⑤ 라우트 전환(BG-2 — CD-1 통과 뒤에만 여기 온다). fencing token을 동봉해
	//    게이트웨이가 stale 실행자의 write를 거절하게 한다(BG-4 ⓐ). 실패 처리는
	//    handleSwitchFailure가 게이트웨이의 보증에 따라 셋으로 가른다.
	//    ⚠️ 잔여 ⑴: 단계 직전 락 보유 재확인(BG-4 · CD-3 — ⑤ 앞과 ⑨ 앞)은 여기서 하지
	//    않는다 — dispatch는 락 표면을 들고 있지 않고, coordinator가 dispatch 직전 1회
	//    확인한다. ⑤의 창은 sink-side 토큰 검증(위)이 덮지만, ⑨(구 slot down)은 그 결박
	//    밖이다(락을 잃은 실행자의 down이 남는다 — 락 표면을 dispatch까지 내려야 닫힌다).
	if err := d.Gateway.Switch(ctx, string(idle), uint64(token)); err != nil {
		return handleSwitchFailure(ctx, idleExec, active, idle, err)
	}

	// 4. ⑥ 드레인 + ⑨ 구 active slot 종료. 여기부터는 라우트가 이미 옮겨졌으므로 요청 ctx가
	//    취소돼도 완주해야 한다 — 중간에 손을 떼면 구 slot이 그대로 남아 잔존 프로세스가
	//    된다(DB 커넥션·배치 스레드를 계속 잡는다). cleanup과 같은 detached 패턴을 쓴다.
	post := context.WithoutCancel(ctx)
	drainWait(d.DrainWait)

	// ⑨ 구 active slot만 down한다(BG-3 ⑶ — 별개 compose project라 새 slot을 끄지 않는다).
	//    이미지는 남긴다(RL-5 — 로컬 되돌림이 성립해야 한다).
	downCtx, cancel := context.WithTimeout(post, CleanupTimeout)
	defer cancel()
	if err := activeExec.Down(downCtx); err != nil {
		return StateUnknown, fmt.Errorf("⑨ 구 active slot(%s) compose down 실패 — ⑤ 라우트 전환은 성공했다(라우트=%s) · 신·구 두 프로세스 생존 가능(잔존 프로세스 · UNKNOWN · 락 유지·사람 개입): %w", active, idle, err)
	}

	// BG 완주 후에만 승격한다(B4') — 여기 도달했다는 것은 헬스·전환·드레인·구 slot 종료가
	// 전부 끝났다는 뜻이고, 그때의 정의만이 "마지막 정상본"으로 복원 재료가 될 자격이 있다.
	if plan != nil {
		plan.promote(ctx, string(idle), injected)
	}
	return StateCompleted, nil
}

// drainWait은 전환 후 구 slot의 in-flight 소진을 기다린다(CD-4 ⑥ · BG-3). 라우트가 이미
// 옮겨진 뒤이므로 드레인은 **완주가 계약**이다 — 요청 ctx가 취소돼도 중간에 손을 떼면 아직
// 처리 중인 요청 위로 down이 떨어진다. 그래서 취소 축이 없는 단순 sleep이다(이전의
// select+ctx.Done()은 호출자가 넘기던 WithoutCancel ctx의 Done()이 nil이라 영원히 선택되지
// 않는 죽은 가지였다 — 취소를 지원하는 것처럼 보이던 겉모습만 걷어냈다).
// ⚠️ [구현 검증] IV-17/CDV-2 — v1은 관측이 아니라 고정 대기다(위 DrainWait 주석 참조).
func drainWait(wait time.Duration) { time.Sleep(wait) }

// maxFencingToken은 전환 요청에 실을 수 있는 fencing token의 상한이다 — 계약상 토큰은
// int64 양수(≥1)이며(store는 uint64로 들고 다닌다), 상위 절반 값은 sink 쪽에서 음수로
// 접히거나 거절된다. 범위 밖이면 배포를 시작하지 않는다(부작용 0).
const maxFencingToken = uint64(math.MaxInt64)

// switchStateRolledBack은 전환 실패 응답이 싣는 state 중 **정리를 허가하는 유일한 값**이다
// (게이트웨이 계약 — internal/dispatch의 클라이언트가 파싱해 오류에 싣는다): 전환을 시도했으나
// 되돌렸다 = 라우트는 구 slot 그대로 = 미전환 보증. 나머지 값(NOT_ATTEMPTED는 409 갈래가
// 먼저 가져가고, INDETERMINATE·부재)은 여기서 보증으로 쓰지 않는다 — 이 패키지는 문자열
// 값만 알면 되고 구현 패키지를 import하지 않는다.
const switchStateRolledBack = "ROLLED_BACK"

// switchFailure는 ⑤ 전환 실패 오류가 실을 수 있는 구조화 정보다(소비 지점 인터페이스 —
// 구현 패키지가 이 패키지를 import하지 않도록 메서드 시그니처만 계약이다 · IA-5).
// 문자열 매칭으로 갈래를 읽지 않는 것이 요점이다 — 메시지가 바뀌면 조용히 오분류된다.
type switchFailure interface {
	// SwitchState는 게이트웨이가 보증한 실상태다("" = 보증 없음).
	SwitchState() string
	// StaleToken은 fencing token 거절(409 — 소유권 상실)인지다.
	StaleToken() bool
}

// classifySwitchFailure는 전환 오류에서 보증을 읽는다. 구조화 정보가 없는 오류(평범한
// error)는 "보증 없음"이다 — 모르면 정리하지 않는 쪽으로 접힌다(fail-closed).
func classifySwitchFailure(err error) (stale bool, state string) {
	var f switchFailure
	if errors.As(err, &f) {
		return f.StaleToken(), f.SwitchState()
	}
	return false, ""
}

// handleSwitchFailure는 ⑤ 실패를 게이트웨이의 **보증**에 따라 셋으로 가른다. 핵심은
// "정리(down)는 미전환이 보증됐을 때만 한다"이다 — 실상태를 모르는데 내리면 트래픽이 가는
// 쪽을 끊는다(별도 재조회로 대신하지 않는다: 게이트웨이 GET도 registry 기준이라 실상태
// 보증이 아니고, 보증은 전환 응답의 state가 소유한다).
//
//   - stale(409): 이 실행자는 소유권을 잃었다(다른 배포가 진행 중). 승자가 같은 idle 슬롯을
//     자기 green으로 쓰거나 이미 그쪽으로 라우트를 옮겼을 수 있으므로 **아무것도 건드리지
//     않는다** — 정리 down이 승자의 라이브 슬롯을 절단하는 것이 여기서 막는 치명 경합이다.
//     올린 컨테이너가 남으므로 net-0이 아니다 = UNKNOWN.
//   - ROLLED_BACK: 라우트가 구 slot 그대로임이 보증됐다 = 올린 slot을 정리해 net-0 복원.
//   - 그 밖(INDETERMINATE·전송 실패·타임아웃·state 파싱 불가): 실상태 불명 = 정리 금지·UNKNOWN.
func handleSwitchFailure(ctx context.Context, idleExec HostExecutor, active, idle Slot, err error) (RemoteState, error) {
	stale, state := classifySwitchFailure(err)
	switch {
	case stale:
		return StateUnknown, fmt.Errorf("⑤ 라우트 전환이 fencing token 거절(409)로 실패했다 — 소유권 상실(다른 배포가 진행 중이다) · 승자의 슬롯을 건드리지 않는다(정리 down 생략 — 이 배포가 %s에 올린 컨테이너는 그대로 남는다 · net-0 아님) · UNKNOWN(락 유지·사람 개입): %w", idle, err)
	case state == switchStateRolledBack:
		return cleanupAfterFailure(ctx, idleExec, fmt.Sprintf("⑤ 라우트 전환 실패(게이트웨이가 미전환을 보증했다 state=%s · 라우트는 %s 그대로)", switchStateRolledBack, active), err)
	default:
		return StateUnknown, fmt.Errorf("⑤ 라우트 전환 실패 — 게이트웨이가 미전환을 보증하지 않았다(state=%q · INDETERMINATE·전송 실패·타임아웃·응답 파싱 불가가 여기 온다) · 라우트가 이미 %s로 옮겨졌을 수 있어 정리(down)를 하지 않는다(내리면 트래픽이 가는 쪽을 끊는다) · UNKNOWN(락 유지·사람 개입): %w", state, idle, err)
	}
}

// cleanupAfterFailure는 up 이후 실패(up 부분 기동·이미지 불일치·헬스 실패·전환 실패) 후
// 새로 올린 slot을 down으로 정리해 net-0(미전환)으로 되돌린다. 정리 down은 요청 ctx가
// 취소·타임아웃됐어도 완주해야 하므로 context.WithoutCancel + 짧은 상한으로 실행한다(요청
// 취소와 무관하게 복원 성립 — coordinator 락 해제와 같은 detached 패턴). down 성공=
// UNEXECUTED(net-0), down 실패=green 잔존 가능(UNKNOWN).
func cleanupAfterFailure(ctx context.Context, exec HostExecutor, stage string, cause error) (RemoteState, error) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), CleanupTimeout)
	defer cancel()
	if derr := exec.Down(cctx); derr != nil {
		return StateUnknown, fmt.Errorf("%s 후 정리(down)도 실패 — green 잔존 가능(UNKNOWN): 원인=%v · down=%v", stage, cause, derr)
	}
	return StateUnexecuted, fmt.Errorf("%s·green 정리 완료(미전환·net-0): %w", stage, cause)
}
