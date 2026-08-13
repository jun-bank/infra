package agentrpc

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/store"
)

// fakeLocalDispatcher는 위성 로컬 실행 지점(deploy.LocalDispatcher 자리)의 페이크다 —
// 호출 횟수·인자를 포착하고 설정된 상태를 낸다. 실제 docker를 돌리지 않는다.
type fakeLocalDispatcher struct {
	mu         sync.Mutex
	state      deploy.RemoteState
	err        error
	calls      int
	lastTarget deploy.Target
}

func (f *fakeLocalDispatcher) Dispatch(_ context.Context, m deploy.Manifest, _ store.FencingToken) (deploy.RemoteState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastTarget = m.Target
	return f.state, f.err
}

func (f *fakeLocalDispatcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func testManifest(target deploy.Target, requestID string) deploy.Manifest {
	return deploy.Manifest{
		Target:          target,
		CommitSHA:       "commitabc",
		ImageDigest:     "sha256:" + strings.Repeat("a", 64),
		ComposeRevision: "rev1",
		ConfigVersion:   "cfg1",
		RequestID:       requestID,
	}
}

// newTestSatellite는 페이크 dispatcher를 붙인 위성 Handler를 httptest 서버로 띄우고, /agent/status
// 호출 횟수를 세는 카운터를 함께 준다(자동 재개 없음 실증용).
func newTestSatellite(t *testing.T, target deploy.Target, key []byte, disp deploy.Dispatcher) (*httptest.Server, *int32) {
	t.Helper()
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "ledger.journal"))
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	h, err := Handler(ServerConfig{Target: target, Key: key, Dispatcher: disp, Ledger: ledger, ExecBudget: 10 * time.Second})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	var statusHits int32
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathStatus {
			atomic.AddInt32(&statusHits, 1)
		}
		h.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)
	return srv, &statusHits
}

// TestRoundtripValidCompleted는 유효 서명 왕복이 COMPLETED를 만들고 위성이 정확히 1회 실행함을
// 본다(execute 1회).
func TestRoundtripValidCompleted(t *testing.T) {
	key := []byte("settlement-key")
	fake := &fakeLocalDispatcher{state: deploy.StateCompleted}
	srv, statusHits := newTestSatellite(t, deploy.TargetSettlement, key, fake)

	rd, err := NewRemoteDispatcher(srv.URL, key, 5*time.Second, deploy.TargetSettlement)
	if err != nil {
		t.Fatalf("NewRemoteDispatcher: %v", err)
	}
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 7)
	if st != deploy.StateCompleted || err != nil {
		t.Fatalf("유효 왕복은 COMPLETED여야 한다: st=%q err=%v", st, err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("위성은 정확히 1회 실행해야 한다: calls=%d", fake.callCount())
	}
	if *statusHits != 0 {
		t.Fatalf("성공 경로에서 status 조회가 있으면 안 된다: hits=%d", *statusHits)
	}
}

// TestRoundtripWrongKeyIsUnknown은 위성별 키 불일치 요청을 위성이 401로 거절하고, main이 이를
// UNKNOWN으로(검증 불가 응답) 접으며 부작용이 없음을 본다(위성 미실행).
func TestRoundtripWrongKeyIsUnknown(t *testing.T) {
	fake := &fakeLocalDispatcher{state: deploy.StateCompleted}
	srv, _ := newTestSatellite(t, deploy.TargetSettlement, []byte("real-key"), fake)

	rd, _ := NewRemoteDispatcher(srv.URL, []byte("wrong-key"), 5*time.Second, deploy.TargetSettlement)
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateUnknown || err == nil {
		t.Fatalf("키 불일치는 UNKNOWN이어야 한다: st=%q err=%v", st, err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("서명 실패인데 위성이 실행했다(부작용 발생): calls=%d", fake.callCount())
	}
}

// TestRoundtripForgedResponseIsUnknown은 위조된 응답 서명을 main이 UNKNOWN으로 거절함을 본다(R1).
func TestRoundtripForgedResponseIsUnknown(t *testing.T) {
	// 위성을 사칭하는 서버: 구조는 맞지만 서명이 엉터리인 응답을 낸다.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderSignature, "deadbeef") // 유효하지 않은 서명
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(deployResponse{
			RequestID: r.Header.Get(HeaderRequestID),
			Action:    ActionDeploy,
			State:     string(deploy.StateCompleted), // 가짜 완료 주장
		})
	}))
	t.Cleanup(srv.Close)

	rd, _ := NewRemoteDispatcher(srv.URL, []byte("k"), 5*time.Second, deploy.TargetSettlement)
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateUnknown || err == nil {
		t.Fatalf("위조 응답 서명은 UNKNOWN이어야 한다(가짜 완료 신뢰 금지): st=%q err=%v", st, err)
	}
}

// TestRoundtripConnectionRefusedIsUnexecuted는 R2 경계다: dial **전** 실패(연결 거부)는 미실행
// (부작용 0)이다 — 요청 바이트가 나가지 않았다.
func TestRoundtripConnectionRefusedIsUnexecuted(t *testing.T) {
	// 리스너를 열어 주소를 얻고 즉시 닫아 "연결 거부" 주소를 만든다.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	rd, _ := NewRemoteDispatcher("http://"+addr, []byte("k"), 2*time.Second, deploy.TargetSettlement)
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateUnexecuted || err == nil {
		t.Fatalf("연결 거부는 미실행(UNEXECUTED · 부작용0)이어야 한다: st=%q err=%v", st, err)
	}
}

// TestRoundtripDialThenCutIsUnknown은 R2 경계다: dial **후** 응답 단절(연결 hijack 후 close)은
// UNKNOWN이다 — 요청이 도달했을 수 있어 미실행으로 접으면 중복 배포 위험이다.
func TestRoundtripDialThenCutIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("hijack 불가")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		_ = conn.Close() // 응답 없이 연결 단절(dial은 성공했다)
	}))
	t.Cleanup(srv.Close)

	rd, _ := NewRemoteDispatcher(srv.URL, []byte("k"), 5*time.Second, deploy.TargetSettlement)
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateUnknown || err == nil {
		t.Fatalf("dial 후 응답 단절은 UNKNOWN이어야 한다: st=%q err=%v", st, err)
	}
}

// TestRoundtripUnknownNoAutoResume는 위성이 UNKNOWN을 내면 main이 그대로 반환하고 **자동 status
// 조회·재개를 하지 않음**을 본다(조각 A 경계 — 재개는 조각 C). 위성 실행도 정확히 1회다.
func TestRoundtripUnknownNoAutoResume(t *testing.T) {
	fake := &fakeLocalDispatcher{state: deploy.StateUnknown}
	srv, statusHits := newTestSatellite(t, deploy.TargetSettlement, []byte("k"), fake)

	rd, _ := NewRemoteDispatcher(srv.URL, []byte("k"), 5*time.Second, deploy.TargetSettlement)
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateUnknown || err == nil {
		t.Fatalf("위성 UNKNOWN은 UNKNOWN으로 반환돼야 한다: st=%q err=%v", st, err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("execute 1회여야 한다(자동 재실행 없음): calls=%d", fake.callCount())
	}
	if *statusHits != 0 {
		t.Fatalf("UNKNOWN 뒤 자동 status 조회가 있으면 안 된다(재개는 조각 C): hits=%d", *statusHits)
	}
}

// TestRoundtripTargetMismatchRejected는 R5다: manifest.target이 AGENT_TARGET과 다르면 위성이
// 부작용 전에 거절하고(서명된 UNEXECUTED) 로컬 실행을 부르지 않음을 본다(오배선 방어).
func TestRoundtripTargetMismatchRejected(t *testing.T) {
	fake := &fakeLocalDispatcher{state: deploy.StateCompleted}
	// 위성은 settlement인데 ledger 배포가 온다.
	srv, _ := newTestSatellite(t, deploy.TargetSettlement, []byte("k"), fake)

	rd, _ := NewRemoteDispatcher(srv.URL, []byte("k"), 5*time.Second, deploy.TargetSettlement)
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetLedger, "req-1"), 1)
	if st != deploy.StateUnexecuted {
		t.Fatalf("target 불일치는 미실행(UNEXECUTED · 부작용0)이어야 한다: st=%q err=%v", st, err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("target 불일치인데 로컬 실행이 불렸다(오배선 방어 실패): calls=%d", fake.callCount())
	}
}

// TestRoundtripIdempotentReplay는 같은 requestId·command 재전송이 재실행 없이 기존 상태를
// 보고함을 본다(멱등 · execute 1회).
func TestRoundtripIdempotentReplay(t *testing.T) {
	fake := &fakeLocalDispatcher{state: deploy.StateCompleted}
	srv, _ := newTestSatellite(t, deploy.TargetSettlement, []byte("k"), fake)

	rd, _ := NewRemoteDispatcher(srv.URL, []byte("k"), 5*time.Second, deploy.TargetSettlement)
	m := testManifest(deploy.TargetSettlement, "req-1")
	if st, err := rd.Dispatch(context.Background(), m, 1); st != deploy.StateCompleted || err != nil {
		t.Fatalf("1차 배포 COMPLETED 기대: st=%q err=%v", st, err)
	}
	if st, err := rd.Dispatch(context.Background(), m, 1); st != deploy.StateCompleted || err != nil {
		t.Fatalf("재전송도 COMPLETED 보고여야 한다: st=%q err=%v", st, err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("재전송은 재실행하지 않아야 한다(멱등): calls=%d", fake.callCount())
	}
}
