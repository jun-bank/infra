package deploy

import (
	"context"
	"fmt"
	"time"

	"github.com/jun-bank/infra/internal/store"
)

// CleanupTimeout은 실패 후 정리(down)에 쓰는 detached context의 상한이다. 정리 down은
// 요청 ctx가 취소·타임아웃됐어도 완주해야 net-0 복원(미전환)이 성립하므로, 요청 ctx와
// 분리한 context.WithoutCancel + 이 상한으로 실행한다(coordinator 락 해제와 같은 패턴).
// exported — main이 배포 창 락 lease 하한식(lease ≥ phaseBudget + D + CleanupTimeout +
// slack)의 입력으로 읽는다(cleanup이 락 안에서 완주하도록 보증 — P4).
// ⚠️ [구현 검증]: 실제 compose down 소요와 함께 튜닝한다.
const CleanupTimeout = 30 * time.Second

// 실행 지점(#15 S2-3) — 검증되고 락을 보유한 manifest를 자기 호스트에서 실제로 실행한다.
// 순서: 이미지 pull(digest 고정) → compose up(green) → CD-1 헬스 → RemoteState. 블루-그린
// 전환(⑤~⑨)은 이 범위 밖이다(잔여-6 · DO-20 ⑶ [구현 검증]).
//
// 계약 출처(정본 — 재해석하지 않는다):
//   - ADR-027 DO-16  (원격/로컬 실행 3상태 — 아래 매핑)
//   - ADR-027 DO-18  (pull·up은 digest로 고정 · 이미지 참조 = <repo>@<digest>)
//   - operations/cicd.md CD-4 ②④ (pull 실패 = 거절·락 해제 · 헬스 실패 = green 종료·blue 유지 = 미전환)
//   - ADR-029 IA-5   (소비 지점 인터페이스 · 닫힌 import — HostExecutor·HealthChecker를
//     여기서 정의하고 internal/dispatch가 구현을 제공, main이 조립·주입한다)

// HostExecutor는 dispatch 모듈이 제공하는 특권 명령 실행 표면이다(IA-5 — 소비 지점
// 인터페이스). 열거된 명령만 노출한다: pull·up·down. status 계열 조회는 헬스 판정이
// 내부에서 쓴다.
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

// LocalDispatcher는 실 실행 지점이다. StubDispatcher를 대체해 Dispatcher를 만족한다.
type LocalDispatcher struct {
	Exec   HostExecutor
	Health HealthChecker
	// Repos는 Target별 이미지 repo다(env IMAGE_CORE/… 에서 조립). 이미지 참조는
	// Repos[target] + "@" + manifest.ImageDigest 로 고정한다(DO-18 ⑵).
	Repos map[Target]string
	// PhaseBudget은 pull+up 단계의 상한이다(P3). 상한 없는 pull/up이 배포 창 락 lease
	// 마진을 초과해 정상 배포 도중 락이 만료되는 것을 막는다 — 이 budget으로 pull·up을
	// 감싸 초과 시 취소·실패시킨다. main이 lease ≥ PhaseBudget + D + CleanupTimeout +
	// slack 을 시동 시 검증해 dispatch 전체가 락 안에 들어가도록 배선한다(P4).
	PhaseBudget time.Duration
}

// 컴파일 타임 계약 확인 — LocalDispatcher는 Dispatcher다.
var _ Dispatcher = LocalDispatcher{}

// Dispatch는 검증된 manifest를 실행하고 세 상태 중 하나를 낸다(DO-16). 상태 매핑:
//
//   - UNEXECUTED(+err): 부작용 순net 0이 증명됨 — repo 미설정·digest 형식 위반·pull 실패
//     (CD-4 ②), 또는 up/헬스 실패 후 green을 성공적으로 down해 미전환(net 0)으로 되돌린
//     경우(CD-4 ④). 갓 pull된 로컬 이미지는 위반 부작용이 아니다(RL-5가 보존을 요구 — Q5).
//   - COMPLETED: green up + CD-1 헬스 통과(이 범위의 종단 성공 · nil err).
//   - UNKNOWN(+err): 변이 명령을 던진 뒤 정리(down)마저 실패·불명 = green이 떠 있을 수
//     있다. 스스로 재시도하지 않는다(Q4) — 락 유지·사람 개입은 coordinator가 처리한다.
//
// mutate 명령(pull/up/down)은 각각 정확히 1회만 실행한다 — 자체 재시도 루프를 돌리지
// 않는다(Q4). UNKNOWN 해소(status 조회→완료/재개/에스컬레이션)는 coordinator/replay 층
// (ClassifyReplay)이 소유한다.
func (d LocalDispatcher) Dispatch(ctx context.Context, m Manifest, _ store.FencingToken) (RemoteState, error) {
	// 이미지 참조 고정(DO-18 ⑵). repo 미설정·digest 형식 위반은 부작용 이전이므로 UNEXECUTED.
	repo, ok := d.Repos[m.Target]
	if !ok || repo == "" {
		return StateUnexecuted, fmt.Errorf("대상 %q의 이미지 repo 미설정 — 부작용 0", m.Target)
	}
	// 방어적 재확인(coordinator의 VerifyManifest가 이미 봤지만, 특권 실행 직전 한 번 더 —
	// 태그·오타가 digest로 위장해 실행 대상 고정이 무너지는 것을 막는다).
	if !validSHA256Digest(m.ImageDigest) {
		return StateUnexecuted, fmt.Errorf("image digest가 sha256: 고정 형식이 아니다(부작용 0): %q", m.ImageDigest)
	}
	imageRef := repo + "@" + m.ImageDigest

	// ⚠️ [구현 검증]/후속 — P2(DO-18 ⑴⑶ 갭): manifest의 ComposeRevision·ConfigVersion이
	// 서명됐지만 아직 실행에 결박되지 않는다. 호스트의 compose 파일이 낡거나 변조된 revision
	// 이어도 이미지 digest만 맞으면 COMPLETED가 난다("이미지만 되돌리면 되돌린 것이 아니다").
	// 이번에 닫지 않는다(잔여-6 · DO-20 ⑶ — 호스트 compose provisioning·버전관리 방식이
	// upstream 미확정). 그 방식이 확정되면 up 전에 호스트 compose가 m.ComposeRevision·
	// m.ConfigVersion과 일치하는지 결박한다. 그 전까지 호스트 compose 파일은 신뢰 설정으로
	// 취급된다(후속 이슈는 메인이 연다).

	// pull+up+무결성대조 단계를 phase budget으로 감싼다(P3·H1) — 상한 없는 pull/up/inspect가
	// lease 마진을 초과해 정상 배포 도중 락이 만료되는 것을 막는다. 초과 시 그 단계가 취소돼
	// 실패로 접힌다. ⚠️ VerifyImageDigest도 이 예산 안에서 돌려야(⑶) 하한식이 조건부가 아니라
	// 구조적으로 성립한다 — 그러지 않으면 느린 docker inspect가 slack을 넘어 cleanup이 락
	// 만료 뒤 실행될 여지가 생긴다(H1). 헬스는 자체 Deadline D로 상한된다.
	phaseCtx, cancel := context.WithTimeout(ctx, d.PhaseBudget)
	defer cancel()

	// 1. 이미지 pull(digest 고정 — CD-4 ②). 실패 = 부작용 0(compose 미접촉) = UNEXECUTED.
	if err := d.Exec.Pull(phaseCtx, imageRef); err != nil {
		return StateUnexecuted, fmt.Errorf("이미지 pull 실패(부작용 0 · CD-4 ②): %w", err)
	}

	// 2. green 기동(compose up · CD-4 ③). 실패 시(phase budget 초과 포함) 부분 기동이 남을 수
	//    있으므로 down으로 net-0 복원을 시도한다 — down 성공=미전환(UNEXECUTED), down 실패=
	//    green 잔존 가능(UNKNOWN). cleanup은 요청 ctx로 넘겨 phase budget 취소와 무관하게
	//    detached로 완주시킨다(아래 cleanupAfterFailure의 WithoutCancel).
	if err := d.Exec.Up(phaseCtx, imageRef); err != nil {
		return d.cleanupAfterFailure(ctx, "compose up 실패", err)
	}

	// 3. 이미지 무결성 대조(DO-16 ⑶ 사후조건). up이 env 주입 없이 :latest·오타 이미지를
	//    띄웠는데 헬스만 통과하면 엉뚱한 이미지가 COMPLETED로 위장한다 — 헬스 전에 실제 뜬
	//    이미지가 pinned digest인지 증명한다. 불일치·조회 불가면 green을 정리하고 미전환.
	//    phaseCtx로 상한해(H1) inspect 지연이 lease를 넘지 않게 한다 — 정리(cleanup)는 여전히
	//    요청 ctx 기반 detached이므로 phase 취소와 무관하게 완주한다.
	if err := d.Exec.VerifyImageDigest(phaseCtx, imageRef); err != nil {
		return d.cleanupAfterFailure(ctx, "이미지 무결성 대조 실패", err)
	}

	// 4. CD-1 헬스(CD-4 ④). 실패 → green 종료·blue 유지 = 미전환(롤백 아님). down 성공=
	//    UNEXECUTED(net-0), down 실패=green 잔존 가능(UNKNOWN).
	if err := d.Health.Check(ctx); err != nil {
		return d.cleanupAfterFailure(ctx, "CD-1 헬스 실패", err)
	}

	// 5. green up + 이미지 대조 + 헬스 통과 = 종단 성공. 전환(⑤~⑨)은 범위 밖이다.
	return StateCompleted, nil
}

// cleanupAfterFailure는 up 이후 실패(up 부분 기동·이미지 불일치·헬스 실패) 후 green을
// down으로 정리해 net-0(미전환)으로 되돌린다. 정리 down은 요청 ctx가 취소·타임아웃됐어도
// 완주해야 하므로 context.WithoutCancel + 짧은 상한으로 실행한다(요청 취소와 무관하게
// 복원 성립 — coordinator 락 해제와 같은 detached 패턴). down 성공=UNEXECUTED(net-0),
// down 실패=green 잔존 가능(UNKNOWN).
func (d LocalDispatcher) cleanupAfterFailure(ctx context.Context, stage string, cause error) (RemoteState, error) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), CleanupTimeout)
	defer cancel()
	if derr := d.Exec.Down(cctx); derr != nil {
		return StateUnknown, fmt.Errorf("%s 후 정리(down)도 실패 — green 잔존 가능(UNKNOWN): 원인=%v · down=%v", stage, cause, derr)
	}
	return StateUnexecuted, fmt.Errorf("%s·green 정리 완료(미전환·net-0): %w", stage, cause)
}
