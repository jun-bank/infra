package deploy

import (
	"context"
	"time"

	"github.com/jun-bank/infra/internal/store"
)

// 배포 창 락 프리미티브 — CD-3(배포 ↔ 배치 상호 배제)의 오케스트레이션 측 배선.
//
// CD-4 순서에서 락은 ① 획득하고, 불가역 단계 직전마다 보유를 재확인(fencing)하며,
// ⑩ 이력 기록 뒤 해제한다. 이 파일은 그 세 프리미티브만 노출한다 — 정상 경로(#13).
// 실제 불가역 단계(⑤ 전환·⑦ 전문 정지·⑧ listener·⑨ blue 종료) 배선은 S2-2/S2-3이고,
// override 핸드셰이크(preempt/ack/override/debt — ADR-024 §2.4)는 S3다.
//
// 계약 출처(정본 — 재해석하지 않는다):
//   - operations/cicd.md CD-3 (조건부 UPDATE 원자 획득 · 양방향 · fencing 단조 · lease ·
//     불가역 단계 직전 보유 재확인 · stale 회수)
//   - ADR-022 DT-9~DT-12    (락 단일 행 · 일곱 전이 프로시저 · deploy-agent 계정)
//   - ADR-024 §2.4          (이번 범위는 정상 획득/해제까지 — override는 S3)

// WindowLock은 정상 경로 오케스트레이션이 락 store에서 소비하는 조각이다: 획득 ·
// 보유 재확인(fencing) · 해제. 소비 지점 인터페이스로 두어 deploy가 store 구체 타입에
// 묶이지 않게 한다(mode.go의 ModeReader와 같은 관용구) — store.SQLStore가 이를 만족한다.
// 핸드셰이크 전이(preempt/ack/override/debt)는 의도적으로 여기 없다: 정상 경로는
// 선점하지도, 선점당하지도 않는다.
type WindowLock interface {
	Acquire(ctx context.Context, kind store.HolderKind, holderID string, lease time.Duration) (store.FencingToken, bool, error)
	Renew(ctx context.Context, kind store.HolderKind, holderID string, token store.FencingToken, lease time.Duration) (bool, error)
	Release(ctx context.Context, kind store.HolderKind, holderID string, token store.FencingToken) (bool, error)
}

// Hold는 지금 이 agent가 보유한 배포 창 락을 나타낸다(CD-3). 이후 모든 상태 변경이
// 재확인해야 하는 fencing 토큰을 지니며, 이 값은 배포 이력에도 남는다(CD-4 ⑸).
type Hold struct {
	lock     WindowLock
	holderID string
	lease    time.Duration
	token    store.FencingToken
}

// Token은 이 보유가 부여받은 fencing 토큰이다(단조 증가 — CD-3).
func (h *Hold) Token() store.FencingToken { return h.token }

// AcquireWindow는 배포 창 락을 agent로서 잡는다(CD-4 ①). 같은 단일 행을 배치·커트오프
// 스케줄러가 경합한다(양방향 — CD-3): 배치·커트오프가 유효 lease로 점유 중이거나 다른
// 배포가 진행 중이면 held=false다 — 이것은 기록할 거절이지 오류가 아니다(RL-4). 직전
// 점유의 lease가 만료돼 있으면 획득 프로시저가 그 자리에서 회수한다(stale 회수 — CD-3);
// 호출자는 새 토큰을 관측하는 것 말고 특별히 할 일이 없다.
func AcquireWindow(ctx context.Context, l WindowLock, holderID string, lease time.Duration) (h *Hold, held bool, err error) {
	// S2-1 결함2: 최소 lease를 오케스트레이션 경계에서 먼저 강제한다(store·프로시저와
	// 같은 규칙 — 계층 이중 강제). sub-second/0/음수 lease는 무보호 락(ok=true인데 Confirm
	// 직후 탈취)을 만들 수 있으므로 획득을 시도하지 않고 fail-closed로 거절한다.
	if err := store.ValidateLease(lease); err != nil {
		return nil, false, err
	}
	token, ok, err := l.Acquire(ctx, store.HolderAgent, holderID, lease)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	return &Hold{lock: l, holderID: holderID, lease: lease, token: token}, true, nil
}

// Confirm은 불가역 단계 직전에 이 보유를 재확인한다(CD-3 「보유 재확인」). 내 fencing
// 토큰이 그 행에 그대로일 때만 lease를 연장하며 held=true를 준다. held=false는 lease가
// 만료돼 다른 점유자가 진입했다는 뜻이므로, 호출자는 그 단계를 시작해서는 안 된다
// (좀비 차단 — 만료 뒤 살아난 옛 agent는 토큰 불일치로 이후 단계가 전부 거부된다).
// 이것은 프리미티브이며, 실제 불가역 단계는 S2-2/S2-3이 전환 직전에 이를 호출한다.
func (h *Hold) Confirm(ctx context.Context) (held bool, err error) {
	return h.lock.Renew(ctx, store.HolderAgent, h.holderID, h.token, h.lease)
}

// Release는 우리가 여전히 보유 중일 때만(같은 holder+token) 락을 해제한다(CD-4 ⑩ 뒤).
// released=false는 이미 보유하지 않음(만료 회수됨)을 뜻한다 — 해제 실패는 치명적이지
// 않다: lease 만료가 어차피 그 행을 회수한다(CD-3). 잡은 주체가 해제한다.
func (h *Hold) Release(ctx context.Context) (released bool, err error) {
	return h.lock.Release(ctx, store.HolderAgent, h.holderID, h.token)
}
