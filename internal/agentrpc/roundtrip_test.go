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

// newTestLedger는 journal·lock을 temp 디렉터리에 두고 원장을 연다.
func newTestLedger(t *testing.T) *Ledger {
	t.Helper()
	dir := t.TempDir()
	l, err := OpenLedger(filepath.Join(dir, "journal"), filepath.Join(dir, "lock"))
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// newTestSatellite는 페이크 dispatcher를 붙인 위성 Server를 httptest 서버로 띄우고, /agent/status
// 호출 횟수를 세는 카운터를 함께 준다(자동 재개 없음 실증용).
func newTestSatellite(t *testing.T, target deploy.Target, key []byte, disp deploy.Dispatcher) (*httptest.Server, *int32) {
	t.Helper()
	s := newTestServer(t, target, key, disp, newTestLedger(t))
	var statusHits int32
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathStatus {
			atomic.AddInt32(&statusHits, 1)
		}
		s.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)
	return srv, &statusHits
}

// newTestServer는 표준 테스트 ServerConfig로 위성 Server를 만든다(넉넉한 skew·exec budget).
func newTestServer(t *testing.T, target deploy.Target, key []byte, disp deploy.Dispatcher, ledger *Ledger) *Server {
	t.Helper()
	s, err := NewServer(ServerConfig{
		Target: target, Key: key, Dispatcher: disp, Ledger: ledger,
		ExecBudget: 10 * time.Second, Skew: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
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

// TestRoundtripUnknownStatusButNoResumeWhenNotUnexecuted는 조각 C 재개의 경계다(조각 A re-baseline):
// 위성이 UNKNOWN을 동기 응답하면 main은 status를 **1회 조회**하지만(조각 C — UNKNOWN에 status 조회
// 추가), status가 durable UNEXECUTED가 **아니면**(여기선 UNKNOWN) 재개 없이 UNKNOWN으로 접는다.
// 조각 A의 "UNKNOWN=사람" 계약이 유지된다 — status 조회는 추가됐으나 UNEXECUTED만 재개 대상이다.
func TestRoundtripUnknownStatusButNoResumeWhenNotUnexecuted(t *testing.T) {
	fake := &fakeLocalDispatcher{state: deploy.StateUnknown}
	srv, statusHits := newTestSatellite(t, deploy.TargetSettlement, []byte("k"), fake)

	rd, _ := NewRemoteDispatcher(srv.URL, []byte("k"), 5*time.Second, deploy.TargetSettlement)
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateUnknown || err == nil {
		t.Fatalf("위성 UNKNOWN은 UNKNOWN으로 반환돼야 한다: st=%q err=%v", st, err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("execute 1회여야 한다(status가 UNEXECUTED 아니라 재개 없음): calls=%d", fake.callCount())
	}
	if *statusHits != 1 {
		t.Fatalf("UNKNOWN 뒤 status 조회는 정확히 1회여야 한다(조각 C 해소 사이클): hits=%d", *statusHits)
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

// --- 조각 C 해소 사이클 (R3 · 1회 제한 자동 재개) ---

// ixAction은 프록시 위성이 한 요청을 어떻게 다룰지다(해소 사이클 유도).
type ixAction int

const (
	ixPass           ixAction = iota // 실서버로 그대로 전달
	ixCutBefore                      // 서버를 건드리기 전에 연결 끊기 → 위성 미도달(ABSENT)
	ixProcessThenCut                 // 실서버가 처리(원장 갱신)한 뒤 응답만 끊기 → main은 dial-후 UNKNOWN
)

// resumeCounters는 프록시가 본 deploy/status 호출 수다(op 수·1회 제한 관측).
type resumeCounters struct {
	mu          sync.Mutex
	deployCalls int
	statusHits  int
}

func (c *resumeCounters) snapshot() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deployCalls, c.statusHits
}

// seqDispatcher는 호출마다 미리 정한 상태를 순서대로 낸다(재개-전/후 상태 분기). 소진되면 마지막
// 상태를 유지한다. 위성이 실제로 dispatch를 몇 번 돌렸는지 calls로 센다.
type seqDispatcher struct {
	mu     sync.Mutex
	states []deploy.RemoteState
	i      int
	calls  int
}

func (d *seqDispatcher) Dispatch(_ context.Context, _ deploy.Manifest, _ store.FencingToken) (deploy.RemoteState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.states[d.i]
	if d.i < len(d.states)-1 {
		d.i++
	}
	d.calls++
	return st, nil
}

func (d *seqDispatcher) callCount() int { d.mu.Lock(); defer d.mu.Unlock(); return d.calls }

// hijackClose는 응답 없이 연결을 끊는다(main 관점 dial-후 단절 → UNKNOWN).
func hijackClose(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	hj, ok := w.(http.Hijacker)
	if !ok {
		t.Error("hijack 불가")
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = conn.Close()
}

// newResumeSatellite는 해소 사이클을 유도하는 프록시 위성이다: deploy 호출 순번(deployIdx)·status
// 호출을 세고, decide(path, deployIdx)가 정한 대로 통과/절단한다. ixProcessThenCut은 실서버를
// recorder로 돌려 **원장을 갱신한 뒤** 응답만 끊어, "위성은 처리했는데 응답이 유실된" UNKNOWN을
// 만든다 — durable UNEXECUTED가 원장에 남고 그 뒤 status·재개가 이어진다.
func newResumeSatellite(t *testing.T, key []byte, disp deploy.Dispatcher, decide func(path string, deployIdx int) ixAction) (*httptest.Server, *resumeCounters) {
	t.Helper()
	inner := newTestServer(t, deploy.TargetSettlement, key, disp, newTestLedger(t))
	c := &resumeCounters{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		deployIdx := 0
		switch r.URL.Path {
		case PathDeploy:
			c.deployCalls++
			deployIdx = c.deployCalls
		case PathStatus:
			c.statusHits++
		}
		c.mu.Unlock()
		switch decide(r.URL.Path, deployIdx) {
		case ixPass:
			inner.ServeHTTP(w, r)
		case ixCutBefore:
			hijackClose(t, w)
		case ixProcessThenCut:
			inner.ServeHTTP(httptest.NewRecorder(), r) // 원장 갱신(응답은 버림)
			hijackClose(t, w)
		}
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, c
}

// TestRoundtripResumeSucceedsOnDurableUnexecuted는 R3 성공 경로다: execute#1이 UNKNOWN(응답 유실)
// 이지만 위성이 durable UNEXECUTED를 기록했고, status가 그것을 확인해 재개 execute#2가 COMPLETED로
// 성공함을 본다(transient 회복 — R5의 좁은 실익 창). op = deploy 2 + status 1 = 3.
func TestRoundtripResumeSucceedsOnDurableUnexecuted(t *testing.T) {
	key := []byte("k")
	disp := &seqDispatcher{states: []deploy.RemoteState{deploy.StateUnexecuted, deploy.StateCompleted}}
	srv, c := newResumeSatellite(t, key, disp, func(path string, deployIdx int) ixAction {
		if path == PathDeploy && deployIdx == 1 {
			return ixProcessThenCut // execute#1: 위성 처리(UNEXECUTED@1) 후 응답 절단 → main UNKNOWN
		}
		return ixPass // status·재개 execute#2는 정상 통과
	})

	rd, _ := NewRemoteDispatcher(srv.URL, key, 5*time.Second, deploy.TargetSettlement)
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateCompleted || err != nil {
		t.Fatalf("재개 성공은 COMPLETED여야 한다: st=%q err=%v", st, err)
	}
	dep, stat := c.snapshot()
	if dep != 2 || stat != 1 {
		t.Fatalf("op은 deploy 2 + status 1이어야 한다(op≤3): deploy=%d status=%d", dep, stat)
	}
	if disp.callCount() != 2 {
		t.Fatalf("위성은 execute#1·재개 execute#2로 2회 dispatch해야 한다: calls=%d", disp.callCount())
	}
}

// TestRoundtripResumeStaysUnexecuted는 R5의 결정론적 거절 경로다: durable UNEXECUTED가 재개돼도
// 같은 거절(UNEXECUTED)을 재현함을 본다(재실행 무익 · 무한 아님). op≤3.
func TestRoundtripResumeStaysUnexecuted(t *testing.T) {
	key := []byte("k")
	disp := &seqDispatcher{states: []deploy.RemoteState{deploy.StateUnexecuted, deploy.StateUnexecuted}}
	srv, c := newResumeSatellite(t, key, disp, func(path string, deployIdx int) ixAction {
		if path == PathDeploy && deployIdx == 1 {
			return ixProcessThenCut
		}
		return ixPass
	})

	rd, _ := NewRemoteDispatcher(srv.URL, key, 5*time.Second, deploy.TargetSettlement)
	st, _ := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateUnexecuted {
		t.Fatalf("결정론적 거절은 재개해도 UNEXECUTED여야 한다: st=%q", st)
	}
	if dep, stat := c.snapshot(); dep != 2 || stat != 1 {
		t.Fatalf("op≤3(deploy 2 + status 1): deploy=%d status=%d", dep, stat)
	}
}

// TestRoundtripNoResumeOnAbsent는 B2 핵심이다: execute#1이 위성에 미도달(status가 ABSENT)이면
// **재개하지 않고** UNKNOWN으로 접는다 — ABSENT는 미도달 증명이 아니라 조회가 execute보다 먼저
// 처리된 것일 수 있어(중복 배포 위험) durable UNEXECUTED와 구분해 재개 근거로 쓰지 않는다.
func TestRoundtripNoResumeOnAbsent(t *testing.T) {
	key := []byte("k")
	disp := &seqDispatcher{states: []deploy.RemoteState{deploy.StateCompleted}} // 호출되면 안 됨
	srv, c := newResumeSatellite(t, key, disp, func(path string, deployIdx int) ixAction {
		if path == PathDeploy && deployIdx == 1 {
			return ixCutBefore // execute#1: 위성 미도달(원장에 아무것도 안 남음 → status ABSENT)
		}
		return ixPass
	})

	rd, _ := NewRemoteDispatcher(srv.URL, key, 5*time.Second, deploy.TargetSettlement)
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateUnknown || err == nil {
		t.Fatalf("ABSENT는 재개 없이 UNKNOWN이어야 한다: st=%q err=%v", st, err)
	}
	dep, stat := c.snapshot()
	if dep != 1 || stat != 1 {
		t.Fatalf("ABSENT면 재개 execute를 보내지 않는다(deploy 1 + status 1): deploy=%d status=%d", dep, stat)
	}
	if disp.callCount() != 0 {
		t.Fatalf("위성 미도달이면 dispatch가 한 번도 안 돌아야 한다: calls=%d", disp.callCount())
	}
}

// TestRoundtripResumeCappedAtOnce는 M2(1회 제한)다: 재개 execute#2가 또 UNKNOWN이면 main은 **즉시**
// UNKNOWN을 반환하고 status를 **다시 조회하지 않는다**(루프 없음). status 조회가 정확히 1회임을
// 검증해 무한 재조회·재개가 없음을 못박는다.
func TestRoundtripResumeCappedAtOnce(t *testing.T) {
	key := []byte("k")
	disp := &seqDispatcher{states: []deploy.RemoteState{deploy.StateUnexecuted, deploy.StateUnexecuted}}
	srv, c := newResumeSatellite(t, key, disp, func(path string, deployIdx int) ixAction {
		if path == PathDeploy {
			return ixProcessThenCut // execute#1·재개 execute#2 둘 다 처리 후 응답 절단 → 둘 다 main UNKNOWN
		}
		return ixPass // status만 통과(UNEXECUTED 확인)
	})

	rd, _ := NewRemoteDispatcher(srv.URL, key, 5*time.Second, deploy.TargetSettlement)
	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateUnknown || err == nil {
		t.Fatalf("재개 후 재차 UNKNOWN은 UNKNOWN이어야 한다: st=%q err=%v", st, err)
	}
	dep, stat := c.snapshot()
	if stat != 1 {
		t.Fatalf("재개 후 UNKNOWN이면 status를 다시 조회하지 않는다(1회 제한): status=%d", stat)
	}
	if dep != 2 {
		t.Fatalf("deploy는 execute#1 + 재개 execute#2 = 2회에서 멈춰야 한다(무한 아님): deploy=%d", dep)
	}
}
