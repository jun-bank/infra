package agentrpc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/store"
)

// fakeLease는 LeaseChecker 페이크다 — held/err를 설정으로 내고 호출 인자·횟수를 포착한다.
// "키 검증 전 store read 금지"(G-5)를 calls로 관측한다: 인증 실패 케이스는 calls==0이어야 한다.
type fakeLease struct {
	mu         sync.Mutex
	held       bool
	err        error
	calls      int
	lastHolder string
	lastToken  store.FencingToken
}

func (f *fakeLease) FencingLeaseHeld(_ context.Context, holderID string, token store.FencingToken) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastHolder = holderID
	f.lastToken = token
	return f.held, f.err
}

func (f *fakeLease) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newFenceTestServer는 FenceHandler를 httptest 서버로 띄운다(넉넉한 skew).
func newFenceTestServer(t *testing.T, keys map[deploy.Target][]byte, lease LeaseChecker, holderID string) *httptest.Server {
	t.Helper()
	h, err := NewFenceHandler(FenceHandlerConfig{Keys: keys, Lease: lease, HolderID: holderID, Skew: 60 * time.Second})
	if err != nil {
		t.Fatalf("NewFenceHandler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// TestFenceConfirmValidHeld는 유효 서명 왕복이 HELD(nil)를 내고, main이 자기 holderID·요청
// token으로 store를 정확히 1회 읽음을 본다.
func TestFenceConfirmValidHeld(t *testing.T) {
	key := []byte("settlement-key")
	lease := &fakeLease{held: true}
	srv := newFenceTestServer(t, map[deploy.Target][]byte{deploy.TargetSettlement: key}, lease, "main-1")

	fc, err := NewFenceClient(srv.URL, key, 5*time.Second)
	if err != nil {
		t.Fatalf("NewFenceClient: %v", err)
	}
	if err := fc.Confirm(context.Background(), deploy.TargetSettlement, "req-1", 7); err != nil {
		t.Fatalf("lease 살아있으면 HELD(nil)여야 한다: %v", err)
	}
	if lease.callCount() != 1 || lease.lastHolder != "main-1" || lease.lastToken != 7 {
		t.Fatalf("store를 (main-1,7)로 1회 읽어야 한다: calls=%d holder=%q token=%d", lease.calls, lease.lastHolder, lease.lastToken)
	}
}

// TestFenceConfirmStaleDenied는 lease가 살아있지 않으면(held=false — token 불일치·lease 만료·
// holder 다름이 DB EXISTS에서 전부 false로 접힌다) 위성이 deny(오류)로 받음을 본다. store는
// 읽혔다(인증 통과 뒤 판정).
func TestFenceConfirmStaleDenied(t *testing.T) {
	key := []byte("k")
	lease := &fakeLease{held: false}
	srv := newFenceTestServer(t, map[deploy.Target][]byte{deploy.TargetSettlement: key}, lease, "main-1")
	fc, _ := NewFenceClient(srv.URL, key, 5*time.Second)

	if err := fc.Confirm(context.Background(), deploy.TargetSettlement, "req-1", 7); err == nil {
		t.Fatal("stale(held=false)은 deny(오류)여야 한다 — mutation 금지")
	}
	if lease.callCount() != 1 {
		t.Fatalf("인증 통과 요청은 store를 읽어야 한다: calls=%d", lease.calls)
	}
}

// TestFenceConfirmStoreErrorDenied는 store 판정 오류가 STALE로 서명돼(fail-closed) 위성이
// deny로 받음을 본다 — 판정 불가를 HELD로 열지 않는다.
func TestFenceConfirmStoreErrorDenied(t *testing.T) {
	key := []byte("k")
	lease := &fakeLease{err: context.DeadlineExceeded}
	srv := newFenceTestServer(t, map[deploy.Target][]byte{deploy.TargetSettlement: key}, lease, "main-1")
	fc, _ := NewFenceClient(srv.URL, key, 5*time.Second)

	if err := fc.Confirm(context.Background(), deploy.TargetSettlement, "req-1", 7); err == nil {
		t.Fatal("store 오류는 fail-closed deny여야 한다")
	}
}

// TestFenceConfirmWrongKeyNoStoreRead는 위성 키 불일치를 main이 401로 거절하고 **store를 읽지
// 않음**을 본다(G-5 — 키 검증 전 store read 금지). 위성은 deny로 받는다.
func TestFenceConfirmWrongKeyNoStoreRead(t *testing.T) {
	lease := &fakeLease{held: true}
	srv := newFenceTestServer(t, map[deploy.Target][]byte{deploy.TargetSettlement: []byte("real-key")}, lease, "main-1")
	fc, _ := NewFenceClient(srv.URL, []byte("wrong-key"), 5*time.Second)

	if err := fc.Confirm(context.Background(), deploy.TargetSettlement, "req-1", 7); err == nil {
		t.Fatal("키 불일치는 deny여야 한다")
	}
	if lease.callCount() != 0 {
		t.Fatalf("서명 검증 실패인데 store를 읽었다(키 검증 전 store read 금지 위반): calls=%d", lease.calls)
	}
}

// TestFenceConfirmUnknownTargetNoStoreRead는 target에 키가 없으면(미등록 위성) 검증 불가로
// 거절하고 store를 읽지 않음을 본다(target으로 키 결정 · 키 없으면 store 접근 없음).
func TestFenceConfirmUnknownTargetNoStoreRead(t *testing.T) {
	key := []byte("k")
	lease := &fakeLease{held: true}
	// 서버는 settlement 키만 안다. 위성이 ledger로 확인을 시도한다.
	srv := newFenceTestServer(t, map[deploy.Target][]byte{deploy.TargetSettlement: key}, lease, "main-1")
	fc, _ := NewFenceClient(srv.URL, key, 5*time.Second)

	if err := fc.Confirm(context.Background(), deploy.TargetLedger, "req-1", 7); err == nil {
		t.Fatal("미등록 target은 deny여야 한다")
	}
	if lease.callCount() != 0 {
		t.Fatalf("키 없는 target인데 store를 읽었다: calls=%d", lease.calls)
	}
}

// TestFenceConfirmStaleTimestampNoStoreRead는 서명은 유효하나 issuedAt이 신선도 창 밖이면
// 거절하고 store를 읽지 않음을 본다(가로챈 유효 요청의 락 만료 후 재생 완화).
func TestFenceConfirmStaleTimestampNoStoreRead(t *testing.T) {
	key := []byte("k")
	lease := &fakeLease{held: true}
	srv := newFenceTestServer(t, map[deploy.Target][]byte{deploy.TargetSettlement: key}, lease, "main-1")
	fc, _ := NewFenceClient(srv.URL, key, 5*time.Second)
	// 클라이언트 시계를 한 시간 전으로 고정 → issuedAt이 창 밖.
	fc.now = func() time.Time { return time.Now().Add(-time.Hour) }

	if err := fc.Confirm(context.Background(), deploy.TargetSettlement, "req-1", 7); err == nil {
		t.Fatal("stale timestamp는 deny여야 한다")
	}
	if lease.callCount() != 0 {
		t.Fatalf("신선도 창 밖인데 store를 읽었다: calls=%d", lease.calls)
	}
}

// TestFenceConfirmReplayRejected는 G-1 replay 방어다: main이 **직전 확인의 HELD 응답을 그대로
// 재생**해도 위성이 거절함을 본다. 클라이언트 시계를 고정해 issuedAt·target·token·requestId가
// 두 요청에서 동일하게 두면, 두 요청을 가르는 것은 **매번 새로 만드는 confirmId** 하나뿐이다.
// 그래서 과거 응답(과거 confirmId·과거 요청digest에 서명)은 새 요청(새 confirmId)의 canonical과
// 어긋나 검증에 실패한다 — confirmId를 고정으로 되돌리면 이 테스트가 실패한다(뮤테이션).
func TestFenceConfirmReplayRejected(t *testing.T) {
	key := []byte("k")

	var mu sync.Mutex
	var firstSig string
	var firstBody []byte
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		n++
		if n == 1 {
			// 1차 — 이 요청에 정직하게 HELD를 서명한다. 응답을 통째로 보관한다.
			body, _ := readAllFence(r)
			var req fenceRequest
			_ = json.Unmarshal(body, &req)
			reqDigest := BodyDigest(body)
			sig := Sign(key, FenceResponseCanonicalV1(reqDigest, req.ConfirmID, FenceVerdictHeld))
			respBody, _ := json.Marshal(fenceResponse{RequestID: req.RequestID, ConfirmID: req.ConfirmID, Verdict: FenceVerdictHeld})
			firstSig, firstBody = sig, respBody
			w.Header().Set(HeaderSignature, sig)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBody)
			return
		}
		// 2차 — 1차 응답을 **그대로 재생**한다(과거 confirmId·과거 서명). replay 시도.
		w.Header().Set(HeaderSignature, firstSig)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(firstBody)
	}))
	t.Cleanup(srv.Close)

	fc, _ := NewFenceClient(srv.URL, key, 5*time.Second)
	fixed := time.Unix(1_700_000_000, 0)
	fc.now = func() time.Time { return fixed } // issuedAt 고정 — confirmId만이 두 요청을 가른다

	if err := fc.Confirm(context.Background(), deploy.TargetSettlement, "req-1", 7); err != nil {
		t.Fatalf("1차 정직한 HELD는 통과해야 한다: %v", err)
	}
	if err := fc.Confirm(context.Background(), deploy.TargetSettlement, "req-1", 7); err == nil {
		t.Fatal("재생된 과거 HELD 응답은 거절돼야 한다(G-1 replay 방어 — confirmId 결박)")
	}
}

// readAllFence는 테스트 핸들러에서 body를 다 읽는다.
func readAllFence(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}
