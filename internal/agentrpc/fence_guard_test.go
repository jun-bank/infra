package agentrpc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
)

// guardFakeExec는 HostExecutor 페이크다 — **실제** up/down이 불렸는지 세어, guard가 부작용을
// 막았는지(inner를 부르지 않았는지)를 관측한다.
type guardFakeExec struct {
	mu                          sync.Mutex
	pulls, ups, verifies, downs int
	upErr, downErr              error
}

func (f *guardFakeExec) Pull(context.Context, string) error {
	f.mu.Lock()
	f.pulls++
	f.mu.Unlock()
	return nil
}
func (f *guardFakeExec) Up(context.Context, string) error {
	f.mu.Lock()
	f.ups++
	err := f.upErr
	f.mu.Unlock()
	return err
}
func (f *guardFakeExec) VerifyImageDigest(context.Context, string) error {
	f.mu.Lock()
	f.verifies++
	f.mu.Unlock()
	return nil
}
func (f *guardFakeExec) Down(context.Context) error {
	f.mu.Lock()
	f.downs++
	err := f.downErr
	f.mu.Unlock()
	return err
}

type guardFakeHealth struct{ err error }

func (h guardFakeHealth) Check(context.Context) error { return h.err }

// fakeConfirmer는 FenceConfirmer 페이크다 — 정책대로 실패시키고 호출 횟수를 센다.
type fakeConfirmer struct {
	mu        sync.Mutex
	calls     int
	failFirst bool // 첫 확인만 실패하고 이후는 성공(sticky 판별자 — sticky면 이후 확인 자체가 안 온다)
	failAll   bool
}

func (c *fakeConfirmer) Confirm(context.Context, deploy.Target, string, uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.failAll || (c.failFirst && c.calls == 1) {
		return errors.New("fence stale")
	}
	return nil
}

func (c *fakeConfirmer) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// legacyGuardedDispatcher는 legacy(무동봉) 단일 경로 LocalDispatcher를 만든다 — Exec을 guard로
// 감싸고, Compose는 AllowLegacy로 두어 composePreflight가 nil 계획으로 통과하게 한다.
func legacyGuardedDispatcher(exec deploy.HostExecutor, health deploy.HealthChecker) deploy.LocalDispatcher {
	return deploy.LocalDispatcher{
		Exec:        guardedExecutor{inner: exec},
		Health:      health,
		Repos:       map[deploy.Target]string{deploy.TargetSettlement: "repo.example/app"},
		PhaseBudget: 5 * time.Second,
		Compose:     &deploy.ComposeRuntime{AllowLegacy: true},
	}
}

// TestGuardSessionStickyBlocksCleanupDown은 G-2의 핵이다: up의 fence 확인이 실패하면 그 dispatch가
// 영구 denied로 고정돼, cleanupAfterFailure의 down이 **RPC도 mutation도 없이** 막힌다 — 미실행
// up 뒤 기존 프로젝트 down이 일어나지 않는다. confirmer는 첫 확인만 실패하고 이후는 성공하도록
// 두어(failFirst), sticky가 아니라면 down 확인이 성공해 down이 실행될 조건을 만든다 — sticky면
// down은 확인을 아예 하지 않으므로 confirmer 호출은 1회다(sticky 제거 시 이 단언이 깨진다).
func TestGuardSessionStickyBlocksCleanupDown(t *testing.T) {
	exec := &guardFakeExec{}
	d := legacyGuardedDispatcher(exec, guardFakeHealth{})
	conf := &fakeConfirmer{failFirst: true}
	session := NewGuardSession(conf, deploy.TargetSettlement, "req-1", 7)
	ctx := withGuardSession(context.Background(), session)

	st, err := d.Dispatch(ctx, testManifest(deploy.TargetSettlement, "req-1"), 7)
	if st != deploy.StateUnknown || err == nil {
		t.Fatalf("up fence 실패 + cleanup down 차단 = UNKNOWN이어야 한다: st=%q err=%v", st, err)
	}
	if exec.ups != 0 {
		t.Fatalf("fence 실패인데 실제 up이 실행됐다(부작용): ups=%d", exec.ups)
	}
	if exec.downs != 0 {
		t.Fatalf("sticky인데 cleanup down이 실행됐다(미실행 up 뒤 기존 프로젝트 down): downs=%d", exec.downs)
	}
	if conf.callCount() != 1 {
		t.Fatalf("sticky면 down은 fence RPC를 하지 않는다(confirm 정확히 1회): calls=%d", conf.callCount())
	}
	if exec.pulls != 1 {
		t.Fatalf("pull은 gate 대상이 아니다(1회 기대 — 로컬 이미지 회수): pulls=%d", exec.pulls)
	}
}

// TestGuardSessionAllowsMutationWhenHeld는 HELD면 up이 실제로 실행돼 정상 COMPLETED로 감을 본다
// (guard가 정상 배포를 막지 않는다). 단일 경로 성공은 down이 없으므로 확인은 up 1회다.
func TestGuardSessionAllowsMutationWhenHeld(t *testing.T) {
	exec := &guardFakeExec{}
	d := legacyGuardedDispatcher(exec, guardFakeHealth{})
	conf := &fakeConfirmer{} // 늘 HELD
	session := NewGuardSession(conf, deploy.TargetSettlement, "req-1", 7)
	ctx := withGuardSession(context.Background(), session)

	st, err := d.Dispatch(ctx, testManifest(deploy.TargetSettlement, "req-1"), 7)
	if st != deploy.StateCompleted || err != nil {
		t.Fatalf("HELD면 정상 COMPLETED여야 한다: st=%q err=%v", st, err)
	}
	if exec.ups != 1 || exec.verifies != 1 || exec.downs != 0 {
		t.Fatalf("HELD 단일 경로: up1·verify1·down0 기대: ups=%d verifies=%d downs=%d", exec.ups, exec.verifies, exec.downs)
	}
	if conf.callCount() != 1 {
		t.Fatalf("단일 경로 성공은 up 확인 1회여야 한다: calls=%d", conf.callCount())
	}
}

// TestGuardContextMissingFailClosed는 guard 세션이 ctx에 없으면(decorate됐는데 위성 조립이
// 세션을 안 실은 배선 오류) up·down이 fail-closed로 막힘을 본다(G-2 guard context 누락).
func TestGuardContextMissingFailClosed(t *testing.T) {
	exec := &guardFakeExec{}
	ex := guardedExecutor{inner: exec}
	if err := ex.Up(context.Background(), "ref"); !errors.Is(err, errGuardMissing) {
		t.Fatalf("세션 없는 up은 errGuardMissing이어야 한다: %v", err)
	}
	if err := ex.Down(context.Background()); !errors.Is(err, errGuardMissing) {
		t.Fatalf("세션 없는 down은 errGuardMissing이어야 한다: %v", err)
	}
	if exec.ups != 0 || exec.downs != 0 {
		t.Fatalf("guard 누락인데 inner가 실행됐다: ups=%d downs=%d", exec.ups, exec.downs)
	}
}

// TestGuardLocalDispatcherDecoratesBindExecutor는 G-3 동적 binder decoration이다: Compose.Bind가
// 실행 중 만드는 실행기까지 guard가 감싸짐을 본다. 정적 Exec만 감싸면 이 executor가 무방비로
// 남는다 — decoration 누락을 되돌리면 이 테스트가 실패한다(뮤테이션). 원본 runtime의 Bind는
// 얕은 복사로 보존돼 오염되지 않음도 함께 본다.
func TestGuardLocalDispatcherDecoratesBindExecutor(t *testing.T) {
	inner := &guardFakeExec{}
	rt := &deploy.ComposeRuntime{
		Bind: func(string, deploy.ComposeBinding) (deploy.HostExecutor, deploy.HealthChecker, error) {
			return inner, guardFakeHealth{}, nil
		},
	}
	d := deploy.LocalDispatcher{Compose: rt}
	guarded := GuardLocalDispatcher(d)

	ex, _, err := guarded.Compose.Bind("single", deploy.ComposeBinding{})
	if err != nil {
		t.Fatalf("guarded Bind: %v", err)
	}
	// Bind 반환 실행기가 guard된다: 세션 없는 up은 fail-closed(inner 미실행).
	if err := ex.Up(context.Background(), "ref"); !errors.Is(err, errGuardMissing) {
		t.Fatalf("Bind 반환 실행기의 up이 guard되지 않았다(fail-closed 아님): %v", err)
	}
	if inner.ups != 0 {
		t.Fatalf("guard 누락인데 inner up 실행됨: %d", inner.ups)
	}
	// denied 세션이면 RPC 없이 막힌다.
	session := NewGuardSession(&fakeConfirmer{failAll: true}, deploy.TargetSettlement, "r", 1)
	if err := ex.Up(withGuardSession(context.Background(), session), "ref"); err == nil {
		t.Fatal("denied 세션의 up은 막혀야 한다")
	}
	if inner.ups != 0 {
		t.Fatalf("denied인데 inner up 실행됨: %d", inner.ups)
	}
	// 원본 runtime.Bind는 오염되지 않았다(얕은 복사) — raw 실행기는 guarded가 아니다.
	rawEx, _, _ := rt.Bind("single", deploy.ComposeBinding{})
	if _, isGuarded := rawEx.(guardedExecutor); isGuarded {
		t.Fatal("원본 ComposeRuntime.Bind가 오염됐다(얕은 복사 실패 — main 무접촉 위반)")
	}
}

// TestGuardWithRealClientStaleDeniesMutation은 실 FenceClient→main(stale)→GuardSession→
// guardedExecutor를 한 줄로 엮어, stale lease가 up을 막고(변이 금지) sticky가 이후 down까지
// 막으며 store가 정확히 1회만 읽힘을 본다(전체 왕복의 mutation 차단 실증).
func TestGuardWithRealClientStaleDeniesMutation(t *testing.T) {
	key := []byte("sat")
	lease := &fakeLease{held: false} // stale
	srv := newFenceTestServer(t, map[deploy.Target][]byte{deploy.TargetSettlement: key}, lease, "main-1")
	fc, _ := NewFenceClient(srv.URL, key, 5*time.Second)

	inner := &guardFakeExec{}
	ex := guardedExecutor{inner: inner}
	session := NewGuardSession(fc, deploy.TargetSettlement, "req-1", 7)
	ctx := withGuardSession(context.Background(), session)

	if err := ex.Up(ctx, "ref"); err == nil {
		t.Fatal("stale lease면 up이 막혀야 한다(변이 금지)")
	}
	if inner.ups != 0 {
		t.Fatalf("stale인데 실제 up이 실행됐다: %d", inner.ups)
	}
	if err := ex.Down(ctx); err == nil {
		t.Fatal("sticky denied면 down도 막혀야 한다")
	}
	if inner.downs != 0 {
		t.Fatalf("sticky인데 down이 실행됐다: %d", inner.downs)
	}
	if lease.callCount() != 1 {
		t.Fatalf("sticky면 store는 1회만 읽혀야 한다(down은 RPC 안 함): calls=%d", lease.calls)
	}
}
