package deploy

import (
	"context"
	"errors"
	"testing"

	"github.com/jun-bank/infra/internal/store"
)

// recordingDispatcher는 호출 여부·인자를 포착하고 설정된 상태를 내는 Dispatcher 페이크다.
type recordingDispatcher struct {
	name   string
	state  RemoteState
	err    error
	calls  int
	target Target
}

func (r *recordingDispatcher) Dispatch(_ context.Context, m Manifest, _ store.FencingToken) (RemoteState, error) {
	r.calls++
	r.target = m.Target
	return r.state, r.err
}

// TestRoutingDispatchesByTarget는 core→로컬·settlement→원격으로 갈리고 서로를 부르지 않음을 본다.
func TestRoutingDispatchesByTarget(t *testing.T) {
	local := &recordingDispatcher{name: "local", state: StateCompleted}
	remote := &recordingDispatcher{name: "remote", state: StateCompleted}
	rd, err := NewRoutingDispatcher(map[Target]Dispatcher{
		TargetCore:       local,
		TargetGateway:    local,
		TargetSettlement: remote,
		TargetLedger:     remote,
	})
	if err != nil {
		t.Fatalf("NewRoutingDispatcher: %v", err)
	}

	if _, err := rd.Dispatch(context.Background(), Manifest{Target: TargetCore}, 1); err != nil {
		t.Fatalf("core dispatch: %v", err)
	}
	if local.calls != 1 || remote.calls != 0 {
		t.Fatalf("core는 로컬로 가야 한다: local.calls=%d remote.calls=%d", local.calls, remote.calls)
	}

	if _, err := rd.Dispatch(context.Background(), Manifest{Target: TargetSettlement}, 1); err != nil {
		t.Fatalf("settlement dispatch: %v", err)
	}
	if remote.calls != 1 || local.calls != 1 {
		t.Fatalf("settlement는 원격으로 가야 한다: local.calls=%d remote.calls=%d", local.calls, remote.calls)
	}
}

// TestRoutingUnregisteredFailsClosed는 미등록 target이 부작용 0으로 거절됨을 본다(어떤 dispatcher도
// 부르지 않고 StateUnexecuted+오류).
func TestRoutingUnregisteredFailsClosed(t *testing.T) {
	local := &recordingDispatcher{state: StateCompleted}
	rd, err := NewRoutingDispatcher(map[Target]Dispatcher{TargetCore: local})
	if err != nil {
		t.Fatalf("NewRoutingDispatcher: %v", err)
	}
	st, err := rd.Dispatch(context.Background(), Manifest{Target: TargetSettlement}, 1)
	if err == nil {
		t.Fatal("미등록 target인데 오류 없음(fail-closed 위반)")
	}
	if st != StateUnexecuted {
		t.Fatalf("미등록 target은 부작용 0(StateUnexecuted)이어야 한다: %q", st)
	}
	if local.calls != 0 {
		t.Fatalf("미등록 target인데 다른 dispatcher가 불렸다(부작용 발생): calls=%d", local.calls)
	}
}

// TestRoutingRejectsBadConstruction는 nil dispatcher·닫힌 집합 밖 target·빈 표를 조립 시점에
// 거절함을 본다(fail-closed 기동).
func TestRoutingRejectsBadConstruction(t *testing.T) {
	if _, err := NewRoutingDispatcher(map[Target]Dispatcher{}); err == nil {
		t.Error("빈 라우트 표인데 통과(fail-closed 위반)")
	}
	if _, err := NewRoutingDispatcher(map[Target]Dispatcher{TargetCore: nil}); err == nil {
		t.Error("nil dispatcher인데 통과(fail-closed 위반)")
	}
	if _, err := NewRoutingDispatcher(map[Target]Dispatcher{Target("bogus"): &recordingDispatcher{}}); err == nil {
		t.Error("닫힌 집합 밖 target인데 통과(fail-closed 위반)")
	}
}

// TestRoutingPropagatesRemoteError는 위임된 dispatcher의 (state, err)를 그대로 전달함을 본다
// (라우터가 상태를 재해석하지 않는다 — 대칭 계약 유지).
func TestRoutingPropagatesRemoteError(t *testing.T) {
	wantErr := errors.New("원격 UNKNOWN")
	remote := &recordingDispatcher{state: StateUnknown, err: wantErr}
	rd, _ := NewRoutingDispatcher(map[Target]Dispatcher{TargetLedger: remote})
	st, err := rd.Dispatch(context.Background(), Manifest{Target: TargetLedger}, 1)
	if st != StateUnknown || !errors.Is(err, wantErr) {
		t.Fatalf("위임 결과가 그대로 전달돼야 한다: st=%q err=%v", st, err)
	}
}
