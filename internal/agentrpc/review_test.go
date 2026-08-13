package agentrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/store"
)

// signedDeployReq는 지정 requestID·timestamp로 서명된 배포 요청(httptest.NewRequest)을 만든다.
func signedDeployReq(key []byte, requestID string, tsUnix int64, m deploy.Manifest, token uint64) *http.Request {
	mb, _ := json.Marshal(m)
	body, _ := json.Marshal(deployRequest{Manifest: mb, FencingToken: token})
	ts := strconv.FormatInt(tsUnix, 10)
	sig := Sign(key, RequestCanonical(http.MethodPost, PathDeploy, BodyDigest(body), requestID, ts))
	req := httptest.NewRequest(http.MethodPost, PathDeploy, bytes.NewReader(body))
	req.Header.Set(HeaderRequestID, requestID)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, sig)
	return req
}

// signedStatusReq는 서명된 상태 조회 요청(GET)을 만든다.
func signedStatusReq(key []byte, requestID string, tsUnix int64) *http.Request {
	ts := strconv.FormatInt(tsUnix, 10)
	sig := Sign(key, RequestCanonical(http.MethodGet, PathStatus, BodyDigest(nil), requestID, ts))
	req := httptest.NewRequest(http.MethodGet, PathStatus, nil)
	req.Header.Set(HeaderRequestID, requestID)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, sig)
	return req
}

func decodeResp(t *testing.T, rec *httptest.ResponseRecorder) deployResponse {
	t.Helper()
	var r deployResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("응답 파싱 불가(code=%d body=%q): %v", rec.Code, rec.Body.String(), err)
	}
	return r
}

// --- C1① — 종료 시 ACCEPTED 실행 소유(WaitInFlight) ---

// blockingDispatcher는 Dispatch 진입을 알리고 release까지 블록한다(수명주기 관측용).
type blockingDispatcher struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	state   deploy.RemoteState
}

func (d *blockingDispatcher) Dispatch(_ context.Context, _ deploy.Manifest, _ store.FencingToken) (deploy.RemoteState, error) {
	d.once.Do(func() { close(d.entered) })
	<-d.release
	return d.state, nil
}

// TestServerWaitInFlightOwnsAcceptedExecution은 C1①이다: ACCEPTED된 실행이 진행 중인 동안
// WaitInFlight가 블록하고, 실행이 terminal을 기록하고 끝나야 반환함을 본다(SIGTERM이 dispatch·
// terminal 기록을 끊지 않도록 종료가 소유·대기).
func TestServerWaitInFlightOwnsAcceptedExecution(t *testing.T) {
	key := []byte("k")
	ledger := newTestLedger(t)
	fake := &blockingDispatcher{entered: make(chan struct{}), release: make(chan struct{}), state: deploy.StateCompleted}
	s, err := NewServer(ServerConfig{Target: deploy.TargetSettlement, Key: key, Dispatcher: fake, Ledger: ledger, ExecBudget: 10 * time.Second, Skew: 60 * time.Second})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, signedDeployReq(key, "req-1", time.Now().Unix(), testManifest(deploy.TargetSettlement, "req-1"), 1))
	}()
	<-fake.entered // ACCEPTED 기록 뒤 dispatch 진입(inflight=1 · 블로킹)

	ctx1, c1 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer c1()
	if err := s.WaitInFlight(ctx1); err == nil {
		t.Fatal("in-flight 실행 중인데 WaitInFlight가 반환했다(종료가 실행을 소유하지 못함)")
	}
	close(fake.release) // dispatch 완료 → Finalize → 응답

	ctx2, c2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer c2()
	if err := s.WaitInFlight(ctx2); err != nil {
		t.Fatalf("dispatch 완료 후 WaitInFlight가 반환하지 않음: %v", err)
	}
	if st, ok := ledger.Status("req-1"); !ok || st != StateCompleted {
		t.Fatalf("종료 대기 후 terminal(COMPLETED)이 기록돼야 한다: st=%q ok=%v", st, ok)
	}
}

// --- C2 — greenwashing: (COMPLETED, err) → UNKNOWN ---

// TestServerCompletedWithErrorNormalizedToUnknown은 위성이 (COMPLETED, err≠nil)을 UNKNOWN으로
// 정규화해 응답·원장에 담음을 본다(coordinator 우회 차단). 재전송도 UNKNOWN 보고(재실행 없음).
func TestServerCompletedWithErrorNormalizedToUnknown(t *testing.T) {
	fake := &fakeLocalDispatcher{state: deploy.StateCompleted, err: errors.New("승격 실패")}
	srv, _ := newTestSatellite(t, deploy.TargetSettlement, []byte("k"), fake)
	rd, _ := NewRemoteDispatcher(srv.URL, []byte("k"), 5*time.Second, deploy.TargetSettlement)

	st, err := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st != deploy.StateUnknown || err == nil {
		t.Fatalf("(COMPLETED,err)는 UNKNOWN으로 정규화돼야 한다(greenwashing 차단): st=%q err=%v", st, err)
	}
	// terminal도 UNKNOWN — 재전송이 재실행 없이 UNKNOWN 보고.
	st2, _ := rd.Dispatch(context.Background(), testManifest(deploy.TargetSettlement, "req-1"), 1)
	if st2 != deploy.StateUnknown {
		t.Fatalf("terminal도 UNKNOWN이어야 한다(재전송 보고): %q", st2)
	}
	if fake.callCount() != 1 {
		t.Fatalf("UNKNOWN terminal은 재실행하지 않아야 한다: calls=%d", fake.callCount())
	}
}

// --- C4 — 신선도 창 ---

// TestServerRejectsStaleTimestamp은 서명이 유효해도 timestamp가 skew 창 밖이면 거절하고 부작용·
// 원장 기록이 없음을 본다(가로챈 유효 요청의 락 만료 후 재생 차단).
func TestServerRejectsStaleTimestamp(t *testing.T) {
	key := []byte("k")
	ledger := newTestLedger(t)
	fake := &fakeLocalDispatcher{state: deploy.StateCompleted}
	s := newTestServer(t, deploy.TargetSettlement, key, fake, ledger)

	stale := time.Now().Add(-time.Hour).Unix()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, signedDeployReq(key, "req-1", stale, testManifest(deploy.TargetSettlement, "req-1"), 1))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale timestamp는 401이어야 한다: code=%d", rec.Code)
	}
	if fake.callCount() != 0 {
		t.Fatalf("stale인데 실행됐다: calls=%d", fake.callCount())
	}
	if _, ok := ledger.Status("req-1"); ok {
		t.Fatal("stale인데 원장에 ACCEPTED가 기록됐다(부작용 발생)")
	}
}

// --- C7 — body 상한(slow/거대 body DoS) ---

// TestServerRejectsOversizedBody는 MaxBodyBytes를 넘는 body가 HMAC 검증·실행 전에 거절됨을 본다.
func TestServerRejectsOversizedBody(t *testing.T) {
	key := []byte("k")
	ledger := newTestLedger(t)
	fake := &fakeLocalDispatcher{state: deploy.StateCompleted}
	s, err := NewServer(ServerConfig{Target: deploy.TargetSettlement, Key: key, Dispatcher: fake, Ledger: ledger, ExecBudget: 10 * time.Second, Skew: 60 * time.Second, MaxBodyBytes: 256})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	big := testManifest(deploy.TargetSettlement, "req-1")
	big.CommitSHA = string(bytes.Repeat([]byte("x"), 1024)) // body를 256바이트 초과로 부풀린다
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, signedDeployReq(key, "req-1", time.Now().Unix(), big, 1))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("거대 body는 413이어야 한다(HMAC 전 거절): code=%d", rec.Code)
	}
	if fake.callCount() != 0 {
		t.Fatalf("거대 body인데 실행됐다: calls=%d", fake.callCount())
	}
}

// --- C8 — ABSENT wire 상태 ---

// TestStatusAbsentDistinctFromDurableUnexecuted는 본 적 없는 requestId(ABSENT)와 durable-
// UNEXECUTED가 wire·서명 계약에서 구분됨을 본다(조각 C가 ABSENT를 재개 근거로 오인하지 않게).
func TestStatusAbsentDistinctFromDurableUnexecuted(t *testing.T) {
	key := []byte("k")
	ledger := newTestLedger(t)
	s := newTestServer(t, deploy.TargetSettlement, key, &fakeLocalDispatcher{}, ledger)

	// 1) 본 적 없는 requestId → ABSENT
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, signedStatusReq(key, "never", time.Now().Unix()))
	absent := decodeResp(t, rec)
	if absent.State != WireAbsent {
		t.Fatalf("본 적 없는 requestId는 ABSENT여야 한다: %q", absent.State)
	}
	// 응답 서명이 그 상태에 결박됐는지도 확인(위조 방어).
	if !Verify(key, ResponseCanonical("never", BodyDigest(nil), ActionStatus, "200", WireAbsent), rec.Header().Get(HeaderSignature)) {
		t.Fatal("ABSENT 응답 서명이 검증되지 않는다")
	}

	// 2) durable UNEXECUTED 기록 후 조회 → UNEXECUTED
	if dec := ledger.Accept("req-u", "d"); !dec.Proceed {
		t.Fatalf("Accept: %+v", dec)
	}
	if err := ledger.Finalize("req-u", "d", StateUnexecuted); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, signedStatusReq(key, "req-u", time.Now().Unix()))
	durable := decodeResp(t, rec2)
	if durable.State != string(StateUnexecuted) {
		t.Fatalf("durable UNEXECUTED는 UNEXECUTED여야 한다: %q", durable.State)
	}
	if absent.State == durable.State {
		t.Fatal("ABSENT와 durable-UNEXECUTED가 wire에서 동일하다(C8 실패 — 조각 C 재개 오인 위험)")
	}
}

// --- gap: manifest.requestId ≠ header requestId ---

// TestServerRejectsRequestIDMismatch는 서명은 유효하나 manifest.requestId가 헤더(서명 범위)의
// requestId와 다르면 부작용 전 거절됨을 본다(DO-10 ⑴).
func TestServerRejectsRequestIDMismatch(t *testing.T) {
	key := []byte("k")
	ledger := newTestLedger(t)
	fake := &fakeLocalDispatcher{state: deploy.StateCompleted}
	s := newTestServer(t, deploy.TargetSettlement, key, fake, ledger)

	m := testManifest(deploy.TargetSettlement, "manifest-id")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, signedDeployReq(key, "header-id", time.Now().Unix(), m, 1)) // 헤더로 서명 → 서명 유효
	r := decodeResp(t, rec)
	if r.State != string(StateUnexecuted) {
		t.Fatalf("requestId 불일치는 UNEXECUTED 거절이어야 한다: %q", r.State)
	}
	if fake.callCount() != 0 {
		t.Fatalf("requestId 불일치인데 실행됐다: calls=%d", fake.callCount())
	}
}

// --- gap: fsync 순서(ACCEPTED before docker · terminal before response) ---

// inspectDispatcher는 Dispatch 진입 시점에 원장 상태를 포착한다(ACCEPTED가 docker 전에 내구
// 기록됐는지 관측).
type inspectDispatcher struct {
	ledger     *Ledger
	requestID  string
	onDispatch func(LedgerState, bool)
	state      deploy.RemoteState
}

func (d *inspectDispatcher) Dispatch(_ context.Context, _ deploy.Manifest, _ store.FencingToken) (deploy.RemoteState, error) {
	st, ok := d.ledger.Status(d.requestID)
	d.onDispatch(st, ok)
	return d.state, nil
}

// TestServerFsyncOrdering은 ACCEPTED가 docker(dispatch) **전에** 내구 기록되고, terminal이 응답
// **전에** 기록됨을 본다(crash window 최소화의 순서 계약).
func TestServerFsyncOrdering(t *testing.T) {
	key := []byte("k")
	ledger := newTestLedger(t)
	var gotState LedgerState
	var gotOK bool
	fake := &inspectDispatcher{ledger: ledger, requestID: "req-1", onDispatch: func(s LedgerState, ok bool) { gotState, gotOK = s, ok }, state: deploy.StateCompleted}
	s := newTestServer(t, deploy.TargetSettlement, key, fake, ledger)

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, signedDeployReq(key, "req-1", time.Now().Unix(), testManifest(deploy.TargetSettlement, "req-1"), 1))

	// ACCEPTED before docker: dispatch 진입 시 원장에 비terminal 레코드가 있어(Status→UNKNOWN) 관측된다.
	if !gotOK || gotState != StateUnknown {
		t.Fatalf("dispatch 진입 시 ACCEPTED가 내구 기록돼 있어야 한다(Status→UNKNOWN): st=%q ok=%v", gotState, gotOK)
	}
	// terminal before response: 응답이 반환된 시점(ServeHTTP 종료 후)에 원장은 이미 COMPLETED.
	if st, ok := ledger.Status("req-1"); !ok || st != StateCompleted {
		t.Fatalf("응답 전에 terminal(COMPLETED)이 기록돼야 한다: st=%q ok=%v", st, ok)
	}
	if r := decodeResp(t, rec); r.State != string(StateCompleted) {
		t.Fatalf("응답 state COMPLETED 기대: %q", r.State)
	}
}
