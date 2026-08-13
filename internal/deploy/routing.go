package deploy

import (
	"context"
	"fmt"

	"github.com/jun-bank/infra/internal/store"
)

// RoutingDispatcher는 coordinator 앞에 놓이는 target별 라우팅 dispatcher다(design D1 · G1).
// coordinator는 Dispatcher 하나만 알고, 그 하나가 target에 따라 로컬(core·gateway = .9 자기
// 배포)과 원격(settlement·ledger = 위성 HTTP+HMAC)으로 위임한다.
//
// coordinator·락·모드·이력·fencing 재확인은 **무접촉**이다 — 인터페이스가 로컬/원격 대칭이라
// (RemoteState, error) 계약을 그대로 만족하는 dispatcher를 끼우는 것만으로 라우팅이 성립한다(B5).
//
// 미등록 target은 **fail-closed**다: 등록된 dispatcher가 없으면 아무것도 호출하지 않고 부작용
// 0으로 거절한다(StateUnexecuted + 오류). 조용히 로컬로 흘리거나 통과시키지 않는다.
type RoutingDispatcher struct {
	routes map[Target]Dispatcher
}

// 컴파일 타임 계약 확인 — RoutingDispatcher는 Dispatcher다.
var _ Dispatcher = (*RoutingDispatcher)(nil)

// NewRoutingDispatcher는 target→dispatcher 표로 라우터를 만든다. 표는 복사한다(호출자가 나중에
// 원본 맵을 바꿔도 라우팅이 흔들리지 않게). 닫힌 집합 밖 target·nil dispatcher는 조립 시점에
// 거절한다(fail-closed 기동 — 배선 오류를 런타임 fail-open으로 흘리지 않는다).
func NewRoutingDispatcher(routes map[Target]Dispatcher) (*RoutingDispatcher, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("deploy: RoutingDispatcher에 등록된 라우트가 없다(fail-closed)")
	}
	cp := make(map[Target]Dispatcher, len(routes))
	for t, d := range routes {
		if !t.Valid() {
			return nil, fmt.Errorf("deploy: RoutingDispatcher 라우트 target이 닫힌 집합 밖이다: %q", t)
		}
		if d == nil {
			return nil, fmt.Errorf("deploy: RoutingDispatcher 라우트 dispatcher가 nil이다: target=%q", t)
		}
		cp[t] = d
	}
	return &RoutingDispatcher{routes: cp}, nil
}

// Dispatch는 manifest.target으로 dispatcher를 골라 위임한다. 미등록이면 부작용 0으로 거절한다
// (fail-closed) — coordinator는 이 (StateUnexecuted, err)를 실행 실패로 받아 락을 해제한다
// (부작용이 없으므로 락을 유지할 이유가 없다).
func (r *RoutingDispatcher) Dispatch(ctx context.Context, m Manifest, token store.FencingToken) (RemoteState, error) {
	d, ok := r.routes[m.Target]
	if !ok {
		return StateUnexecuted, fmt.Errorf("deploy: 라우팅 실패 — 대상 %q에 등록된 dispatcher가 없다(fail-closed · 부작용0)", m.Target)
	}
	return d.Dispatch(ctx, m, token)
}
