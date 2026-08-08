// httpentry 진입 층의 단위 테스트. 전송 제한(method·body)·게이트 1(HMAC + 신선도)·게이트
// 2(OIDC)·requestId 멱등에 더해, 이제 종단 수신이 오케스트레이션 층에 배선됐으므로 그
// 거절/재개 경로를 우선 밟는다:
//   - 서명 부재·위조·만료·OIDC 거절 = 401 (RL-8 — 검증 실패는 무조건 거절).
//   - 동일 requestId + 다른 digest = 409(거절·기록).
//   - 유효·신선·신규 = 체인 통과 → 오케스트레이션 → 실행 지점 도달(501 — dispatch 미구현 #15).
//   - 재전송: 미실행이면 재개(501, #9 갭 차단) · 완료면 재실행 없이 200 · UNKNOWN이면 409.
//
// 게이트 1은 실제 auth.Verifier(고정 Clock), 오케스트레이션은 실제 deploy.Coordinator에
// dev·락 획득·스텁 dispatch 페이크를 물려 digest 계산·헤더 파싱·배선까지 함께 검증한다 —
// 페이크 verifier·오케스트레이터로는 그 배선이 조용히 깨져도 잡지 못한다.
package httpentry

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/auth"
	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/store"
)

// --- 고정 시각·테스트 키 ------------------------------------------------------

var testNow = time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

var testHMACKey = []byte("httpentry-test-key-not-a-secret")

type fixedClock struct{}

func (fixedClock) Now() time.Time { return testNow }

// --- store 페이크 -------------------------------------------------------------

// fakeLedger는 인메모리 재생 방어 원장이다. store.LedgerStore의 3분기 계약을 흉내낸다.
type fakeLedger struct {
	mu     sync.Mutex
	digest map[string]string // requestID -> body digest
	jtis   map[string]bool
}

func newFakeLedger() *fakeLedger {
	return &fakeLedger{digest: map[string]string{}, jtis: map[string]bool{}}
}

func (f *fakeLedger) Reserve(_ context.Context, requestID, jti, bodyDigest string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// 실제 store.Reserve와 같은 우선순위: requestId(PK)를 먼저 본다 — 이미 있으면
	// digest를 대조해 재생/충돌을 가른다. requestId가 신규일 때만 jti 재사용을 본다
	// (동일 requestId + 동일 jti + 다른 digest는 충돌이지 jti 재생이 아니다).
	if d, ok := f.digest[requestID]; ok {
		if d == bodyDigest {
			return store.ErrReplay
		}
		return store.ErrDigestConflict
	}
	if jti != "" && f.jtis[jti] {
		return store.ErrReplay
	}
	f.digest[requestID] = bodyDigest
	if jti != "" {
		f.jtis[jti] = true
	}
	return nil
}

// --- OIDC 게이트 페이크 -------------------------------------------------------

// fakeOIDC는 게이트 2를 대체한다. accept가 true면 fixedJTI를 실은 통과 결정을,
// false면 거절 결정을 낸다 — 게이트 2 자체의 행렬은 auth 패키지가 검증하므로, 여기서는
// 배선(토큰 헤더 읽기·jti 전달·거절 시 401·기록)만 못박는다.
type fakeOIDC struct {
	accept    bool
	fixedJTI  string
	reason    string
	lastToken string
}

func (f *fakeOIDC) Verify(_ context.Context, rawToken string) auth.OIDCDecision {
	f.lastToken = rawToken
	if !f.accept {
		return auth.OIDCDecision{Accepted: false, Reason: f.reason}
	}
	return auth.OIDCDecision{Accepted: true, JTI: f.fixedJTI, SelfReport: true}
}

// fakeHistory는 인메모리 이력이다. append와 최신 읽기만 지원한다(append-only).
type fakeHistory struct {
	mu      sync.Mutex
	events  map[string][]store.HistoryEvent
	readErr error // 설정 시 ReadLatest가 이 오류를 반환한다(이력 조회 실패 흉내).
}

func newFakeHistory() *fakeHistory {
	return &fakeHistory{events: map[string][]store.HistoryEvent{}}
}

func (f *fakeHistory) AppendEvent(_ context.Context, ev store.HistoryEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events[ev.RequestID] = append(f.events[ev.RequestID], ev)
	return nil
}

func (f *fakeHistory) ReadLatest(_ context.Context, requestID string) (store.HistoryEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return store.HistoryEvent{}, f.readErr
	}
	evs := f.events[requestID]
	if len(evs) == 0 {
		return store.HistoryEvent{}, nil
	}
	return evs[len(evs)-1], nil
}

func (f *fakeHistory) count(requestID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events[requestID])
}

// find는 requestID의 이력에서 주어진 event_type의 첫 이벤트를 찾는다(예약 이벤트가 최신이
// 아닐 수 있으므로 — 오케스트레이션이 뒤에 STEP_RESULT를 덧붙인다).
func (f *fakeHistory) find(requestID, eventType string) (store.HistoryEvent, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ev := range f.events[requestID] {
		if ev.EventType == eventType {
			return ev, true
		}
	}
	return store.HistoryEvent{}, false
}

// --- 오케스트레이션 협력자 페이크 --------------------------------------------

// grantLock은 항상 획득·해제를 허용하는 배포 창 락이다(진입 층 배선 테스트용 — 락의 실
// 계약은 store 통합 테스트가 진다).
type grantLock struct{}

func (grantLock) Acquire(context.Context, store.HolderKind, string, time.Duration) (store.FencingToken, bool, error) {
	return 1, true, nil
}
func (grantLock) Renew(context.Context, store.HolderKind, string, store.FencingToken, time.Duration) (bool, error) {
	return true, nil
}
func (grantLock) Release(context.Context, store.HolderKind, string, store.FencingToken) (bool, error) {
	return true, nil
}

// devMode는 항상 dev·고정 version을 돌려주는 ModeReader다(모드 판정 배선 테스트용).
type devMode struct{}

func (devMode) Current(context.Context, string) (string, uint64, error) { return "dev", 1, nil }

// stateDispatcher는 고정 상태를 내는 실행 지점이다(완료·UNKNOWN 사상 배선 테스트용).
type stateDispatcher struct{ state deploy.RemoteState }

func (d stateDispatcher) Dispatch(context.Context, deploy.Manifest, store.FencingToken) (deploy.RemoteState, error) {
	return d.state, nil
}

// --- 테스트 하네스 ------------------------------------------------------------

func testConfig(maxBody int64) Config {
	return Config{ListenAddr: "127.0.0.1:0", MaxBodyBytes: maxBody}
}

// testDeps는 실제 게이트 1 verifier(고정 시각)·통과하는 게이트 2 페이크·인메모리 store
// 페이크·정상 경로 오케스트레이터(dev·락 획득·UNEXECUTED dispatch)를 조립한다. 게이트 2
// 행렬 자체는 auth 패키지가 검증하므로 기본은 통과다.
func testDeps(t *testing.T) (Deps, *fakeHistory) {
	t.Helper()
	return testDepsWith(t, &fakeOIDC{accept: true, fixedJTI: "jti-default"}, deploy.StubDispatcher{})
}

// testDepsWithOIDC는 지정한 게이트 2로 deps를 조립한다(거절·자기 신고 배선 테스트용).
func testDepsWithOIDC(t *testing.T, oidc OIDCGate) (Deps, *fakeHistory) {
	t.Helper()
	return testDepsWith(t, oidc, deploy.StubDispatcher{})
}

// testDepsWith는 지정한 게이트 2·실행 지점으로 deps를 조립한다. 오케스트레이터의 이력은
// 미들웨어와 같은 fakeHistory를 공유한다 — 재전송 분류가 dispatch가 남긴 상태를 읽어야
// 하기 때문이다.
func testDepsWith(t *testing.T, oidc OIDCGate, dispatcher deploy.Dispatcher) (Deps, *fakeHistory) {
	t.Helper()
	skew := auth.DefaultClockSkew
	v, err := auth.NewVerifier(auth.Config{Key: testHMACKey, Skew: &skew}, fixedClock{})
	if err != nil {
		t.Fatalf("verifier 생성 실패: %v", err)
	}
	hist := newFakeHistory()
	coord := deploy.NewCoordinator(deploy.Deps{
		Mode:       devMode{},
		Lock:       grantLock{},
		History:    hist,
		Dispatcher: dispatcher,
		HolderID:   "deploy-test",
		Lease:      time.Minute,
	})
	return Deps{Verifier: v, OIDC: oidc, Ledger: newFakeLedger(), History: hist, Deploy: coord}, hist
}

// manifestBody는 대상·requestID로 완전한(DO-18 6칸) manifest JSON을 만든다. manifest의
// requestId는 서명될 envelope requestId와 같아야 오케스트레이션 검증을 통과한다.
func manifestBody(target, requestID string) string {
	return `{"target":"` + target + `","commitSha":"c1","imageDigest":"sha256:` + strings.Repeat("a", 64) + `",` +
		`"composeRevision":"rev1","configVersion":"v1","requestId":"` + requestID + `"}`
}

// signedRequest는 대상·requestID로 완전한 manifest를 만들어 올바르게 서명된 POST /deploy
// 요청을 만든다. envelope requestId와 manifest의 requestId가 일치한다.
func signedRequest(target, requestID string, issuedAt, expiresAt time.Time) *http.Request {
	return signedBody(manifestBody(target, requestID), requestID, issuedAt, expiresAt)
}

// signedBody는 지정한 원본 본문·requestID로 서명된 요청을 만든다(본문을 직접 지정해야
// 하는 테스트용 — digest 충돌 등).
func signedBody(body, requestID string, issuedAt, expiresAt time.Time) *http.Request {
	areq := auth.Request{
		Method:     http.MethodPost,
		Path:       "/deploy",
		BodyDigest: bodyDigest([]byte(body)),
		RequestID:  requestID,
		IssuedAt:   issuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:  expiresAt.UTC().Format(time.RFC3339),
	}
	sig := auth.Sign(testHMACKey, areq)

	r := httptest.NewRequest(http.MethodPost, "/deploy", strings.NewReader(body))
	r.Header.Set(headerRequestID, areq.RequestID)
	r.Header.Set(headerIssuedAt, areq.IssuedAt)
	r.Header.Set(headerExpiresAt, areq.ExpiresAt)
	r.Header.Set(headerSignature, hex.EncodeToString(sig))
	// 게이트 2가 읽을 OIDC 토큰(더미) — 실제 검증은 주입된 게이트 페이크가 판정한다.
	r.Header.Set(headerOIDCToken, "dummy-oidc-token")
	return r
}

// freshWindow는 고정 시각 기준으로 유효한 (issuedAt, expiresAt)를 준다.
func freshWindow() (time.Time, time.Time) {
	return testNow.Add(-30 * time.Second), testNow.Add(5 * time.Minute)
}

// --- 전송 제한(기존 계약 — 서명 도입 후에도 유지) -----------------------------

func TestNonPostRejected405(t *testing.T) {
	deps, _ := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/deploy", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /deploy: 코드 = %d, 기대 = 405", method, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); !strings.Contains(allow, http.MethodPost) {
			t.Errorf("%s /deploy: Allow 헤더 = %q, POST 포함 기대", method, allow)
		}
	}
}

func TestBodyOverLimitRejected413(t *testing.T) {
	const limit = 16
	deps, _ := testDeps(t)
	h := NewHandler(testConfig(limit), deps)

	body := strings.NewReader(strings.Repeat("A", limit+1))
	req := httptest.NewRequest(http.MethodPost, "/deploy", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("상한 초과 본문: 코드 = %d, 기대 = 413", rec.Code)
	}
}

// --- 게이트 1 거절 경로(우선) -------------------------------------------------

// TestMissingSignatureRejected는 서명 헤더가 없으면 401로 거절하는지 확인한다(RL-8).
func TestMissingSignatureRejected(t *testing.T) {
	deps, hist := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)

	req := httptest.NewRequest(http.MethodPost, "/deploy", strings.NewReader("{}"))
	req.Header.Set(headerRequestID, "req-nosig")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("서명 부재: 코드 = %d, 기대 = 401", rec.Code)
	}
	if hist.count("req-nosig") == 0 {
		t.Error("거절이 이력에 기록되지 않았다 (RL-8)")
	}
}

// TestForgedSignatureRejected는 서명이 위조되면 401로 거절하고 기록하는지 확인한다.
func TestForgedSignatureRejected(t *testing.T) {
	deps, hist := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)

	iat, exp := freshWindow()
	req := signedRequest("core", "req-forge", iat, exp)
	// 서명을 한 바이트 뒤집는다(hex 문자 하나 변경).
	sig := req.Header.Get(headerSignature)
	forged := "0" + sig[1:]
	if forged == sig {
		forged = "1" + sig[1:]
	}
	req.Header.Set(headerSignature, forged)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("위조 서명: 코드 = %d, 기대 = 401", rec.Code)
	}
	if hist.count("req-forge") == 0 {
		t.Error("위조 거절이 이력에 기록되지 않았다 (RL-8)")
	}
}

// TestTamperedBodyRejected는 서명 후 본문이 바뀌면 digest 불일치로 401인지 확인한다
// (서명이 body digest를 덮으므로 — DO-10 ⑴).
func TestTamperedBodyRejected(t *testing.T) {
	deps, _ := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)

	iat, exp := freshWindow()
	// 서명은 "core" 본문의 digest에 대해 계산하고, 실제로는 "ledger" 본문을 보낸다 =
	// 전송 중 본문이 바뀐 것과 같다. digest가 어긋나 서명이 불일치해야 한다.
	signedFor := auth.Request{
		Method: http.MethodPost, Path: "/deploy",
		BodyDigest: bodyDigest([]byte(`{"target":"core"}`)),
		RequestID:  "req-tamper",
		IssuedAt:   iat.UTC().Format(time.RFC3339),
		ExpiresAt:  exp.UTC().Format(time.RFC3339),
	}
	sig := auth.Sign(testHMACKey, signedFor)

	req := httptest.NewRequest(http.MethodPost, "/deploy", strings.NewReader(`{"target":"ledger"}`))
	req.Header.Set(headerRequestID, signedFor.RequestID)
	req.Header.Set(headerIssuedAt, signedFor.IssuedAt)
	req.Header.Set(headerExpiresAt, signedFor.ExpiresAt)
	req.Header.Set(headerSignature, hex.EncodeToString(sig))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("본문 변조: 코드 = %d, 기대 = 401", rec.Code)
	}
}

// TestExpiredRejected는 만료된(스큐 밖) 요청이 401인지 확인한다(DO-10 ⑵).
func TestExpiredRejected(t *testing.T) {
	deps, _ := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)

	// expiresAt를 스큐보다 더 과거로 둔다.
	iat := testNow.Add(-1 * time.Hour)
	exp := testNow.Add(-10 * time.Minute)
	req := signedRequest("core", "req-expired", iat, exp)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("만료 요청: 코드 = %d, 기대 = 401", rec.Code)
	}
}

// --- 멱등 3분기 --------------------------------------------------------------

// TestValidNewRequestReachesReceiver는 유효·신선·신규 요청이 게이트 1과 멱등을 통과해
// 오케스트레이션을 통과해 실행 지점에 도달하는지 확인한다(dispatch 미구현이라 501). 완전
// manifest·dev·락 획득·UNEXECUTED dispatch를 거친 것이며, 405/413/401/409/422가 아니라는
// 점이 전 단계를 전부 통과했음을 증명한다.
func TestValidNewRequestReachesReceiver(t *testing.T) {
	deps, hist := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)

	iat, exp := freshWindow()
	req := signedRequest("core", "req-new", iat, exp)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("유효·신규 요청: 코드 = %d, 기대 = 501(실행 지점 도달·dispatch 미구현)", rec.Code)
	}
	if _, ok := hist.find("req-new", "RESERVED"); !ok {
		t.Error("신규 예약이 이력(RESERVED)에 기록되지 않았다")
	}
	if _, ok := hist.find("req-new", "STEP_RESULT"); !ok {
		t.Error("실행 지점 상태(STEP_RESULT/UNEXECUTED)가 이력에 기록되지 않았다")
	}
}

// TestReplayUnexecutedResumes는 예약 후 미완(미실행)이 된 배포를 동일 요청 재전송이 재개해
// 완주시키는지 확인한다(#9 갭 차단 — ErrReplay로 영영 단락되지 않는다). dispatch가 스텁이라
// 상태는 UNEXECUTED(부작용 0)로 남고, 재전송은 재개되어 다시 실행 지점(501)에 도달한다 —
// 200(상태만 반환)으로 단락되지 않는 것이 핵심이다.
func TestReplayUnexecutedResumes(t *testing.T) {
	deps, hist := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	// 1차 — 신규 → 실행 지점 도달(UNEXECUTED).
	first := signedRequest("core", "req-dup", iat, exp)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, first)
	if rec1.Code != http.StatusNotImplemented {
		t.Fatalf("1차 요청: 코드 = %d, 기대 = 501", rec1.Code)
	}

	// 2차 — 같은 id·같은 본문 재전송 → 재개(단락 아님). 다시 실행 지점(501).
	second := signedRequest("core", "req-dup", iat, exp)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, second)
	if rec2.Code != http.StatusNotImplemented {
		t.Fatalf("재전송: 코드 = %d, 기대 = 501(재개 — 미완 배포 완주). 200이면 갭이 열린 것", rec2.Code)
	}
	// 재개가 실제 오케스트레이션을 다시 돌렸다 = STEP_RESULT가 하나 더 쌓였다(RESERVED +
	// STEP_RESULT×2 = 3). 단순 상태 반환이었다면 2에 머문다.
	if n := hist.count("req-dup"); n < 3 {
		t.Errorf("재전송이 재개되지 않았다(이력 %d행) — 미완 배포가 완주되지 않는다", n)
	}
}

// TestReplayCompletedReturnsState는 이미 완료된 배포의 재전송이 재실행 없이 200을 반환하는지
// 확인한다(DO-10 ⑷ — 완료는 재개하지 않는다). dispatch가 COMPLETED를 내면 첫 요청이 완료로
// 기록되고, 같은 요청 재전송은 재개 없이 완료 상태만 반환한다.
func TestReplayCompletedReturnsState(t *testing.T) {
	deps, _ := testDepsWith(t, &fakeOIDC{accept: true, fixedJTI: "jti-done"}, stateDispatcher{state: deploy.StateCompleted})
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	first := signedRequest("core", "req-done", iat, exp)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, first)
	if rec1.Code != http.StatusOK {
		t.Fatalf("1차(완료): 코드 = %d, 기대 = 200", rec1.Code)
	}

	second := signedRequest("core", "req-done", iat, exp)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, second)
	if rec2.Code != http.StatusOK {
		t.Fatalf("완료 재전송: 코드 = %d, 기대 = 200(재실행 없음)", rec2.Code)
	}
	if rec2.Header().Get("X-Deploy-Idempotent-Replay") != "true" {
		t.Error("완료 재전송 응답에 멱등 재생 표식이 없다")
	}
}

// TestReplayReadErrorFailsClosed는 재전송 분류의 근거 이력 조회가 실패하면 200이 아니라
// 500(fail-closed)으로 닫는지 확인한다. 읽기 오류를 empty와 동일 취급해 200을 내면 완료된
// 배포를 미예약으로 오판할 수 있으므로, 재개/보고 판정이 불가하면 재시도하지 않고 닫는다.
func TestReplayReadErrorFailsClosed(t *testing.T) {
	deps, hist := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	// 1차 — 신규 예약·실행 지점 도달(501).
	first := signedRequest("core", "req-readerr", iat, exp)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, first)
	if rec1.Code != http.StatusNotImplemented {
		t.Fatalf("1차 요청: 코드 = %d, 기대 = 501", rec1.Code)
	}

	// 2차 — 재전송인데 이력 조회가 실패한다 → 500(fail-closed), 200 아님.
	hist.readErr = errors.New("이력 조회 실패")
	second := signedRequest("core", "req-readerr", iat, exp)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, second)
	if rec2.Code != http.StatusInternalServerError {
		t.Fatalf("재전송 이력 조회 실패: 코드 = %d, 기대 = 500(fail-closed) — 200이면 미예약 오판", rec2.Code)
	}
}

// TestSameIDDifferentDigestRejected는 동일 requestId+다른 본문이 409로 거절되는지
// 확인한다(DO-10 ⑷ — 같은 멱등 키로 다른 내용 배포 금지).
func TestSameIDDifferentDigestRejected(t *testing.T) {
	deps, hist := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	first := signedRequest("core", "req-conflict", iat, exp)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, first)
	if rec1.Code != http.StatusNotImplemented {
		t.Fatalf("1차 요청: 코드 = %d, 기대 = 501", rec1.Code)
	}

	// 같은 id, 다른 본문(다시 올바르게 서명한다 — 서명은 유효하되 digest가 다르다).
	second := signedRequest("ledger", "req-conflict", iat, exp)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, second)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("id 충돌: 코드 = %d, 기대 = 409", rec2.Code)
	}
	if _, ok := hist.find("req-conflict", "REJECTED"); !ok {
		t.Error("충돌 거절이 이력에 기록되지 않았다 (RL-8)")
	}
}

// --- 게이트 2(OIDC) 배선 -----------------------------------------------------

// TestOIDCRejectedReturns401는 게이트 1을 통과해도 게이트 2가 거절하면 401로 막고
// 이력에 남기는지 확인한다(HMAC AND OIDC — 한쪽만으로는 배포를 열지 않는다).
func TestOIDCRejectedReturns401(t *testing.T) {
	deps, hist := testDepsWithOIDC(t, &fakeOIDC{accept: false, reason: "repository_id 불일치"})
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)

	iat, exp := freshWindow()
	req := signedRequest("core", "req-oidc-reject", iat, exp)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("OIDC 거절: 코드 = %d, 기대 = 401", rec.Code)
	}
	if hist.count("req-oidc-reject") == 0 {
		t.Error("OIDC 거절이 이력에 기록되지 않았다 (RL-8)")
	}
}

// TestMissingOIDCTokenRejected는 OIDC 토큰 헤더가 없으면 게이트 2에서 401로 막는지
// 확인한다 — 게이트 2 판정을 부르기도 전에 토큰 부재로 거절한다.
func TestMissingOIDCTokenRejected(t *testing.T) {
	deps, hist := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)

	iat, exp := freshWindow()
	req := signedRequest("core", "req-no-oidc", iat, exp)
	req.Header.Del(headerOIDCToken) // OIDC 토큰 제거
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("OIDC 토큰 부재: 코드 = %d, 기대 = 401", rec.Code)
	}
	if hist.count("req-no-oidc") == 0 {
		t.Error("토큰 부재 거절이 이력에 기록되지 않았다 (RL-8)")
	}
}

// TestJTIReuseReturnsReplay는 서로 다른 requestId라도 게이트 2가 실어 온 jti가 재사용되면
// 재실행 없이 200으로 처리되는지 확인한다(토큰 재사용 = 재전송 · DO-10 ⑶ · DO-11). 기본
// 게이트 페이크는 고정 jti를 모든 요청에 실으므로 두 번째 요청은 원장 jti UNIQUE에 걸려
// ErrReplay가 된다. 새 requestId(req-jti-B)는 예약된 적이 없어 재개하지 않고(예약-우선
// 불변식) 상태만 반환한다 — 재사용 토큰이 미예약 배포를 열지 못한다.
func TestJTIReuseReturnsReplay(t *testing.T) {
	deps, _ := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	// 1차 — 신규(jti-default 선점).
	first := signedRequest("core", "req-jti-A", iat, exp)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, first)
	if rec1.Code != http.StatusNotImplemented {
		t.Fatalf("1차 요청: 코드 = %d, 기대 = 501", rec1.Code)
	}

	// 2차 — 다른 requestId·다른 본문이지만 같은 jti(토큰 재사용).
	second := signedRequest("ledger", "req-jti-B", iat, exp)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, second)
	if rec2.Code != http.StatusOK {
		t.Fatalf("jti 재사용: 코드 = %d, 기대 = 200(재실행 없음)", rec2.Code)
	}
	if rec2.Header().Get("X-Deploy-Idempotent-Replay") != "true" {
		t.Error("jti 재사용 응답에 멱등 재생 표식이 없다")
	}
}

// TestSelfReportRecordedOnReserve는 게이트 2가 자기 신고로 통과한 요청의 신규 예약
// 이력에 그 한계가 남는지 확인한다(잔여-5 — 운영 승인은 기계 보증이 아니다).
func TestSelfReportRecordedOnReserve(t *testing.T) {
	deps, hist := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)

	iat, exp := freshWindow()
	req := signedRequest("core", "req-selfreport", iat, exp)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// 오케스트레이션이 뒤에 STEP_RESULT를 덧붙이므로 최신이 아니라 RESERVED 이벤트를 본다.
	ev, ok := hist.find("req-selfreport", "RESERVED")
	if !ok {
		t.Fatal("예약(RESERVED) 이벤트가 이력에 없다")
	}
	if ev.Result != "OPERATIONAL_APPROVAL_SELF_REPORTED" {
		t.Errorf("자기 신고 한계가 예약 이력에 남지 않았다: Result = %q", ev.Result)
	}
}

// --- 오케스트레이션 배선(거절·상태 사상) ------------------------------------

// TestMalformedManifestRejected는 서명·게이트를 통과해도 manifest가 불완전(DO-18 6칸
// 미충족)하면 실행 지점에 닿지 않고 422로 거절되는지 확인한다 — 서명된 것이 곧 배포 가능한
// 것이 아니다.
func TestMalformedManifestRejected(t *testing.T) {
	deps, _ := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	// 대상만 있고 나머지 DO-18 필드가 없는 body를 올바르게 서명해 보낸다(게이트는 통과).
	req := signedBody(`{"target":"core"}`, "req-badmanifest", iat, exp)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("불완전 manifest: 코드 = %d, 기대 = 422", rec.Code)
	}
}

// TestUnknownStateEscalates는 직전 시도가 UNKNOWN으로 남은 요청의 재전송이 무턱대고
// 재실행되지 않고 409로 사람에게 올라가는지 확인한다(DO-16 ⑵ — 재시도·실패 접기 금지).
func TestUnknownStateEscalates(t *testing.T) {
	deps, _ := testDepsWith(t, &fakeOIDC{accept: true, fixedJTI: "jti-unknown"}, stateDispatcher{state: deploy.StateUnknown})
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	// 1차 — dispatch가 UNKNOWN → 409(락 유지·사람 개입), 이력에 UNKNOWN 기록.
	first := signedRequest("core", "req-unknown", iat, exp)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, first)
	if rec1.Code != http.StatusConflict {
		t.Fatalf("1차(UNKNOWN): 코드 = %d, 기대 = 409", rec1.Code)
	}

	// 2차 — 같은 요청 재전송 → 재개하지 않고 에스컬레이션(409). 자동 재시도 금지.
	second := signedRequest("core", "req-unknown", iat, exp)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, second)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("UNKNOWN 재전송: 코드 = %d, 기대 = 409(재시도 금지·사람 개입)", rec2.Code)
	}
}

// --- 설정 로딩(기존) ---------------------------------------------------------

func TestLoadConfig(t *testing.T) {
	t.Run("주소 없으면 오류", func(t *testing.T) {
		t.Setenv("AGENT_LISTEN_ADDR", "")
		if _, err := LoadConfig(); err == nil {
			t.Error("AGENT_LISTEN_ADDR 없이 LoadConfig가 성공했다 (fail-closed 기대)")
		}
	})

	t.Run("상한 미지정이면 기본값", func(t *testing.T) {
		t.Setenv("AGENT_LISTEN_ADDR", "127.0.0.1:0")
		t.Setenv("AGENT_MAX_BODY_BYTES", "")
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig 오류: %v", err)
		}
		if cfg.MaxBodyBytes != DefaultMaxBodyBytes {
			t.Errorf("MaxBodyBytes = %d, 기대 = %d (기본값)", cfg.MaxBodyBytes, DefaultMaxBodyBytes)
		}
	})

	t.Run("잘못된 상한이면 오류", func(t *testing.T) {
		t.Setenv("AGENT_LISTEN_ADDR", "127.0.0.1:0")
		t.Setenv("AGENT_MAX_BODY_BYTES", "-1")
		if _, err := LoadConfig(); err == nil {
			t.Error("음수 상한으로 LoadConfig가 성공했다 (fail-closed 기대)")
		}
	})
}
