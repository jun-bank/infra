// 배포 창 락 프리미티브의 단위 테스트(CD-3). 거절/안전 경로를 우선 밟는다 — 경합을
// 획득으로 오인하거나(양방향 상호 배제가 깨진다) 보유 상실을 못 보고 불가역 단계를
// 시작하는 것(좀비)이 이 프리미티브의 치명적 실패이기 때문이다. WindowLock은 인메모리
// 페이크로 대체한다 — 프리미티브 자체는 순수 배선이며, fencing·단조·양방향의 실 SQL
// 계약은 store 통합 테스트가 진다.
package deploy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/store"
)

// fakeLock은 고정된 결과를 돌려주며 인자를 포착하는 인메모리 WindowLock이다.
type fakeLock struct {
	acquireTok store.FencingToken
	acquireOK  bool
	acquireErr error
	renewOK    bool
	renewErr   error
	releaseOK  bool

	// 마지막 호출에서 포착한 인자.
	gotKind  store.HolderKind
	gotID    string
	gotToken store.FencingToken
	gotLease time.Duration
}

func (f *fakeLock) Acquire(_ context.Context, kind store.HolderKind, id string, lease time.Duration) (store.FencingToken, bool, error) {
	f.gotKind, f.gotID, f.gotLease = kind, id, lease
	return f.acquireTok, f.acquireOK, f.acquireErr
}

func (f *fakeLock) Renew(_ context.Context, kind store.HolderKind, id string, token store.FencingToken, lease time.Duration) (bool, error) {
	f.gotKind, f.gotID, f.gotToken, f.gotLease = kind, id, token, lease
	return f.renewOK, f.renewErr
}

func (f *fakeLock) Release(_ context.Context, kind store.HolderKind, id string, token store.FencingToken) (bool, error) {
	f.gotKind, f.gotID, f.gotToken = kind, id, token
	return f.releaseOK, nil
}

// 획득 성공: agent kind로 잡고, 부여받은 토큰을 Hold가 지닌다.
func TestAcquireWindow_Success(t *testing.T) {
	l := &fakeLock{acquireTok: 7, acquireOK: true}
	h, held, err := AcquireWindow(context.Background(), l, "deploy-1", 60*time.Second)
	if err != nil || !held {
		t.Fatalf("획득 성공 기대: held=%v err=%v", held, err)
	}
	if l.gotKind != store.HolderAgent {
		t.Fatalf("획득 kind = %q, HolderAgent 기대 (배포는 항상 agent로 잡는다)", l.gotKind)
	}
	if l.gotID != "deploy-1" || l.gotLease != 60*time.Second {
		t.Fatalf("획득 인자 전달 오류: id=%q lease=%v", l.gotID, l.gotLease)
	}
	if h == nil || h.Token() != 7 {
		t.Fatalf("Hold가 fencing 토큰을 지녀야 한다: %+v", h)
	}
}

// 경합(배치·다른 배포 점유 중)은 held=false·hold nil이며 오류가 아니다 — 기록할 거절이다.
func TestAcquireWindow_Contended(t *testing.T) {
	l := &fakeLock{acquireOK: false}
	h, held, err := AcquireWindow(context.Background(), l, "deploy-1", 60*time.Second)
	if err != nil {
		t.Fatalf("경합은 오류가 아니라 거절: err=%v", err)
	}
	if held || h != nil {
		t.Fatalf("경합 시 held=false·hold nil 기대: held=%v hold=%v", held, h)
	}
}

// 연결·권한 오류는 그대로 올라오고 held=false다 — 조용히 삼키지 않는다.
func TestAcquireWindow_Error(t *testing.T) {
	sentinel := errors.New("db 접근 불가")
	l := &fakeLock{acquireErr: sentinel}
	h, held, err := AcquireWindow(context.Background(), l, "deploy-1", 60*time.Second)
	if !errors.Is(err, sentinel) || held || h != nil {
		t.Fatalf("오류 전파 기대: held=%v hold=%v err=%v", held, h, err)
	}
}

// Confirm 성공: 내 토큰이 그 행에 그대로 → 재확인이 통과(불가역 단계 진행 허용). 포착된
// 인자가 Hold의 (agent, id, token, lease)와 일치해야 한다 — fencing이 실려야 한다.
func TestHold_Confirm_StillHeld(t *testing.T) {
	l := &fakeLock{acquireTok: 5, acquireOK: true, renewOK: true}
	h, _, _ := AcquireWindow(context.Background(), l, "deploy-1", 30*time.Second)
	held, err := h.Confirm(context.Background())
	if err != nil || !held {
		t.Fatalf("보유 유지 시 Confirm=true 기대: held=%v err=%v", held, err)
	}
	if l.gotKind != store.HolderAgent || l.gotID != "deploy-1" || l.gotToken != 5 {
		t.Fatalf("Confirm이 fencing 토큰을 재확인에 실어야 한다: kind=%q id=%q token=%d", l.gotKind, l.gotID, l.gotToken)
	}
}

// Confirm 실패(토큰 불일치 = 만료 뒤 인계됨): 호출자는 불가역 단계를 시작하면 안 된다.
func TestHold_Confirm_Lost(t *testing.T) {
	l := &fakeLock{acquireTok: 5, acquireOK: true, renewOK: false}
	h, _, _ := AcquireWindow(context.Background(), l, "deploy-1", 30*time.Second)
	held, err := h.Confirm(context.Background())
	if err != nil {
		t.Fatalf("보유 상실은 오류가 아니라 held=false: err=%v", err)
	}
	if held {
		t.Fatal("보유 상실 시 Confirm=false 기대 (좀비 차단) — true는 만료 뒤 단계 진행을 허용한다")
	}
}

// Release는 Hold의 (agent, id, token)으로 해제를 시도한다.
func TestHold_Release(t *testing.T) {
	l := &fakeLock{acquireTok: 9, acquireOK: true, releaseOK: true}
	h, _, _ := AcquireWindow(context.Background(), l, "deploy-1", 30*time.Second)
	released, err := h.Release(context.Background())
	if err != nil || !released {
		t.Fatalf("해제 성공 기대: released=%v err=%v", released, err)
	}
	if l.gotKind != store.HolderAgent || l.gotID != "deploy-1" || l.gotToken != 9 {
		t.Fatalf("Release가 holder+token으로 해제해야 한다: kind=%q id=%q token=%d", l.gotKind, l.gotID, l.gotToken)
	}
}
