package agentrpc

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jun-bank/infra/internal/deploy"
)

// 위성 fencing guard — 각 mutation(compose up·down) 직전에 fence 확인을 삽입하는 decorator와
// dispatch별 sticky 세션(infra#37 조각 B · G-2 · G-3 · B3). 위성 실행 로직(LocalDispatcher)은
// 그대로 두고, HostExecutor를 guard로 감싸 exec 직전에만 확인을 끼운다(로컬 dispatch 불변 — G1).
//
// 이 파일은 **위성 조립에만** 쓰인다 — main 로컬 dispatch 로직은 이 decorator를 거치지 않으며
// 무변경이다(G-3). guard가 세션을 못 찾으면 fail-closed로 deny한다(guard context 누락 방어).
//
// ⚠️ TOCTOU — 완화이지 sink-side fencing이 아니다(B4 · design 문면): fence-confirm은 DB 판정
// 시점까지 stale인 실행자가 **새** compose mutation을 시작하는 확률·시간을 줄인다. 판정 직후의
// lease 상실과 **이미 시작된** compose 명령은 차단하지 못하며, docker는 fencing-aware sink가
// 아니다(전달된 명령을 토큰으로 되돌리지 않는다). 그래서 이것은 게이트웨이 SCG의 sink-side
// 조건부 갱신(ADR-031 BG-4)과 **동급이 아니다** — 그 등급으로 표기하지 않는다. 남는 창은
// 로컬 down 잔여(coordinator.go ⑨)와 같은 등급의 "완화"다.

// FenceConfirmer는 GuardSession·위성 Server가 소비하는 역방향 확인 표면이다(FenceClient가
// 구현). 인터페이스로 두어 테스트가 실제 HTTP 없이 확인 로직을 관측할 수 있게 한다.
type FenceConfirmer interface {
	Confirm(ctx context.Context, target deploy.Target, requestID string, token uint64) error
}

// errGuardMissing은 decorate된 실행기가 ctx에서 GuardSession을 찾지 못했을 때의 오류다(G-2
// fail-closed). 위성 조립은 항상 세션을 주입하므로 정상 경로에서는 나오지 않는다 — 배선이
// 어긋나면 mutation을 여는 대신 요란하게 막는다.
var errGuardMissing = errors.New("agentrpc: fence GuardSession이 실행 ctx에 없다 — mutation을 여는 대신 fail-closed로 거절(guard context 누락)")

// GuardSession은 **한 dispatch**의 fence 상태다(G-2 sticky). 첫 fence 실패·stale 순간 영구
// denied로 고정되며, 그 뒤 모든 Up·Down은 RPC도 mutation도 하지 않고 같은 오류를 반환한다.
//
// 왜 sticky인가(치명 G-2): 단순 wrapper라면 각 exec가 독립적으로 확인해, up 확인은 실패했는데
// cleanup의 down 확인이 (경합·시점 차로) 성공하면 **미실행 up 뒤 기존 프로젝트 down**이 일어난다.
// dispatch 하나가 한 번 fence를 잃으면 그 dispatch의 어떤 mutation도(특히 cleanup down도) 더
// 실행돼선 안 되므로, 상태를 dispatch 단위로 고정한다. cleanupAfterFailure는 요청 ctx의
// WithoutCancel 파생을 쓰는데 그 파생은 **값(이 세션)을 보존**하므로, cleanup down도 같은 세션을
// 만나 차단된다.
type GuardSession struct {
	confirmer FenceConfirmer
	target    deploy.Target
	requestID string
	token     uint64

	mu     sync.Mutex
	denied error // 한 번 non-nil이 되면 영구 고정 — 이후 guard는 RPC 없이 이 오류를 반환
}

// NewGuardSession은 한 dispatch의 세션을 만든다(위성 handleDeploy가 mutation마다 공유할 하나).
func NewGuardSession(confirmer FenceConfirmer, target deploy.Target, requestID string, token uint64) *GuardSession {
	return &GuardSession{confirmer: confirmer, target: target, requestID: requestID, token: token}
}

// guard는 한 mutation 직전의 확인이다(G-2). 이미 denied면 RPC 없이 즉시 그 오류를 낸다. 아직
// 아니면 confirmId 새로 만들어 역방향 확인을 하고, 실패하면 그 순간 denied로 **영구 고정**한다.
func (g *GuardSession) guard(ctx context.Context, op string) error {
	g.mu.Lock()
	if g.denied != nil {
		err := g.denied
		g.mu.Unlock()
		return err // 이미 잃은 fence — RPC도 mutation도 하지 않는다(sticky)
	}
	g.mu.Unlock()

	cerr := g.confirmer.Confirm(ctx, g.target, g.requestID, g.token)
	if cerr == nil {
		return nil // HELD — 이 mutation 진행 허가
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.denied == nil {
		g.denied = fmt.Errorf("agentrpc: fence 확인 실패로 이 배포를 영구 차단(op=%s · 이후 모든 up/down 거절 · UNKNOWN): %w", op, cerr)
	}
	return g.denied
}

// guardSessionKey는 execCtx에 GuardSession을 싣는 ctx 키다(비공개 타입 — 충돌 없음).
type guardSessionKey struct{}

// withGuardSession은 dispatch 실행 ctx에 세션을 싣는다(위성 handleDeploy가 Dispatch 직전 호출).
func withGuardSession(ctx context.Context, g *GuardSession) context.Context {
	return context.WithValue(ctx, guardSessionKey{}, g)
}

// guardFromCtx는 decorate된 실행기가 mutation 직전에 세션을 꺼내 확인한다. 세션이 없으면
// fail-closed(G-2 guard context 누락 = deny).
func guardFromCtx(ctx context.Context, op string) error {
	g, ok := ctx.Value(guardSessionKey{}).(*GuardSession)
	if !ok || g == nil {
		return errGuardMissing
	}
	return g.guard(ctx, op)
}

// guardedExecutor는 HostExecutor를 감싸 **Up·Down 직전에만** fence 확인을 끼운다(B3 · G-2).
// Pull·VerifyImageDigest는 통과시킨다: pull은 로컬 이미지 회수일 뿐 배포 상태를 바꾸지 않고
// (RL-5 — 갓 pull된 이미지는 위반 부작용이 아니다), VerifyImageDigest는 조회(inspect)다. 확인
// 대상은 "기존 상태를 바꾸는 compose 명령"인 up과 down뿐이다.
type guardedExecutor struct {
	inner deploy.HostExecutor
}

// 컴파일 타임 계약 확인 — guardedExecutor는 deploy.HostExecutor다.
var _ deploy.HostExecutor = guardedExecutor{}

func (e guardedExecutor) Pull(ctx context.Context, imageRef string) error {
	return e.inner.Pull(ctx, imageRef) // 로컬 이미지 회수 — mutation 아님(RL-5)
}

func (e guardedExecutor) Up(ctx context.Context, imageRef string) error {
	if err := guardFromCtx(ctx, "up"); err != nil {
		return err // fence 실패 = up 미실행(부작용 0 — inner.Up을 부르지 않는다)
	}
	return e.inner.Up(ctx, imageRef)
}

func (e guardedExecutor) VerifyImageDigest(ctx context.Context, imageRef string) error {
	return e.inner.VerifyImageDigest(ctx, imageRef) // 조회(inspect) — mutation 아님
}

func (e guardedExecutor) Down(ctx context.Context) error {
	if err := guardFromCtx(ctx, "down"); err != nil {
		return err // sticky denied면 여기서 막힌다 — 미실행 up 뒤 기존 프로젝트 down 방지(G-2)
	}
	return e.inner.Down(ctx)
}

// GuardLocalDispatcher는 위성 로컬 dispatcher의 실행기 표면을 **전부** guard로 감싼다(G-3
// 동적 binder decoration). 정적 Exec만 감싸면 동봉 배포의 plan.bind()·bindActive()가 실행
// 중 만드는 새 실행기가 무방비로 남으므로, 다음 넷을 모두 decorate한다:
//
//   - LocalDispatcher.Exec        — 단일 경로의 정적 실행기.
//   - LocalDispatcher.SlotExec[*] — 블루-그린 슬롯별 정적 실행기(위성은 단일 경로라 보통 비어
//     있으나, 존재하면 감싼다 — 누락 없는 decoration).
//   - Compose.Bind 반환 실행기    — plan.bind()가 candidate에 결박해 **실행 중** 만드는 실행기.
//   - bindActive 구 슬롯 down 실행기 — bindActive도 내부에서 Compose.Bind를 부르므로, Bind를
//     감싸면 이 경로의 실행기까지 함께 decorate된다(별도 hook 불필요).
//
// **위성 조립에만** 적용한다 — 반환된 LocalDispatcher를 위성 Server에 주입하고, main 로컬
// dispatch는 이 함수를 거치지 않아 무변경이다(G-3). Compose는 포인터라, 원본을 얕은 복사한 뒤
// Bind만 바꿔 원본 runtime을 오염시키지 않는다.
func GuardLocalDispatcher(d deploy.LocalDispatcher) deploy.LocalDispatcher {
	if d.Exec != nil {
		d.Exec = guardedExecutor{inner: d.Exec}
	}
	if len(d.SlotExec) > 0 {
		wrapped := make(map[deploy.Slot]deploy.HostExecutor, len(d.SlotExec))
		for slot, ex := range d.SlotExec {
			if ex != nil {
				wrapped[slot] = guardedExecutor{inner: ex}
			}
		}
		d.SlotExec = wrapped
	}
	if d.Compose != nil && d.Compose.Bind != nil {
		rtCopy := *d.Compose // 얕은 복사 — 원본 runtime의 Bind를 건드리지 않는다
		inner := rtCopy.Bind
		rtCopy.Bind = func(slot string, b deploy.ComposeBinding) (deploy.HostExecutor, deploy.HealthChecker, error) {
			exec, health, err := inner(slot, b)
			if err != nil {
				return nil, nil, err
			}
			if exec != nil {
				exec = guardedExecutor{inner: exec}
			}
			return exec, health, nil
		}
		d.Compose = &rtCopy
	}
	return d
}
