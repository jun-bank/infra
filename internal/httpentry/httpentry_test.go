// httpentry 진입 층의 단위 테스트. 전송 제한(method·body)에 더해, 이제 게이트 1(HMAC +
// 신선도)과 requestId 멱등 3분기가 체인에 붙었으므로 그 거절/재생 경로를 우선 밟는다:
//   - 서명 부재·위조·만료 = 401 (RL-8 — 서명 실패는 무조건 거절).
//   - 동일 requestId + 동일 digest 재전송 = 200(재실행 없음).
//   - 동일 requestId + 다른 digest = 409(거절·기록).
//   - 유효·신선·신규 = 체인 통과 → 종단 수신(아직 501, 오케스트레이션 미구현).
//
// 게이트 1은 실제 auth.Verifier(고정 Clock)로 통과시켜 digest 계산·헤더 파싱·정규화
// 배선까지 함께 검증한다 — 페이크 verifier로는 그 배선이 조용히 깨져도 잡지 못한다.
// store만 인메모리 페이크다(원장·이력의 실계약은 store 통합 테스트가 진다).
package httpentry

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/auth"
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
	if jti != "" && f.jtis[jti] {
		return store.ErrReplay
	}
	if d, ok := f.digest[requestID]; ok {
		if d == bodyDigest {
			return store.ErrReplay
		}
		return store.ErrDigestConflict
	}
	f.digest[requestID] = bodyDigest
	if jti != "" {
		f.jtis[jti] = true
	}
	return nil
}

// fakeHistory는 인메모리 이력이다. append와 최신 읽기만 지원한다(append-only).
type fakeHistory struct {
	mu     sync.Mutex
	events map[string][]store.HistoryEvent
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

// --- 테스트 하네스 ------------------------------------------------------------

func testConfig(maxBody int64) Config {
	return Config{ListenAddr: "127.0.0.1:0", MaxBodyBytes: maxBody}
}

// testDeps는 실제 게이트 1 verifier(고정 시각)와 인메모리 store 페이크를 조립한다.
func testDeps(t *testing.T) (Deps, *fakeHistory) {
	t.Helper()
	skew := auth.DefaultClockSkew
	v, err := auth.NewVerifier(auth.Config{Key: testHMACKey, Skew: &skew}, fixedClock{})
	if err != nil {
		t.Fatalf("verifier 생성 실패: %v", err)
	}
	hist := newFakeHistory()
	return Deps{Verifier: v, Ledger: newFakeLedger(), History: hist}, hist
}

// signedRequest는 지정한 본문·시각으로 올바르게 서명된 POST /deploy 요청을 만든다.
// tamper가 nil이 아니면 서명 계산 직전의 요청을 변형해 위조·만료 등을 흉내낸다.
func signedRequest(body, requestID string, issuedAt, expiresAt time.Time) *http.Request {
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
	req := signedRequest(`{"target":"core"}`, "req-forge", iat, exp)
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
	req := signedRequest(`{"target":"core"}`, "req-expired", iat, exp)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("만료 요청: 코드 = %d, 기대 = 401", rec.Code)
	}
}

// --- 멱등 3분기 --------------------------------------------------------------

// TestValidNewRequestReachesReceiver는 유효·신선·신규 요청이 게이트 1과 멱등을 통과해
// 종단 수신에 도달하는지 확인한다(아직 501 — 오케스트레이션 미구현). 405/413/401이
// 아니라는 점이 전 단계를 통과했음을 증명한다.
func TestValidNewRequestReachesReceiver(t *testing.T) {
	deps, hist := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)

	iat, exp := freshWindow()
	req := signedRequest(`{"target":"core"}`, "req-new", iat, exp)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("유효·신규 요청: 코드 = %d, 기대 = 501(종단 도달)", rec.Code)
	}
	if hist.count("req-new") == 0 {
		t.Error("신규 예약이 이력(RESERVED)에 기록되지 않았다")
	}
}

// TestReplaySameDigestReturnsCurrentState는 동일 requestId+동일 본문 재전송이 재실행
// 없이 200을 반환하는지 확인한다(DO-10 ⑷ — 두 번 배포되지 않는다).
func TestReplaySameDigestReturnsCurrentState(t *testing.T) {
	deps, _ := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	// 1차 — 신규.
	first := signedRequest(`{"target":"core"}`, "req-dup", iat, exp)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, first)
	if rec1.Code != http.StatusNotImplemented {
		t.Fatalf("1차 요청: 코드 = %d, 기대 = 501", rec1.Code)
	}

	// 2차 — 같은 id·같은 본문 재전송.
	second := signedRequest(`{"target":"core"}`, "req-dup", iat, exp)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, second)
	if rec2.Code != http.StatusOK {
		t.Fatalf("재전송: 코드 = %d, 기대 = 200(재실행 없음)", rec2.Code)
	}
	if rec2.Header().Get("X-Deploy-Idempotent-Replay") != "true" {
		t.Error("재전송 응답에 멱등 재생 표식이 없다")
	}
}

// TestSameIDDifferentDigestRejected는 동일 requestId+다른 본문이 409로 거절되는지
// 확인한다(DO-10 ⑷ — 같은 멱등 키로 다른 내용 배포 금지).
func TestSameIDDifferentDigestRejected(t *testing.T) {
	deps, hist := testDeps(t)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	first := signedRequest(`{"target":"core"}`, "req-conflict", iat, exp)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, first)
	if rec1.Code != http.StatusNotImplemented {
		t.Fatalf("1차 요청: 코드 = %d, 기대 = 501", rec1.Code)
	}

	// 같은 id, 다른 본문(다시 올바르게 서명한다 — 서명은 유효하되 digest가 다르다).
	second := signedRequest(`{"target":"ledger"}`, "req-conflict", iat, exp)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, second)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("id 충돌: 코드 = %d, 기대 = 409", rec2.Code)
	}
	if hist.count("req-conflict") < 2 { // RESERVED + REJECTED
		t.Error("충돌 거절이 이력에 기록되지 않았다 (RL-8)")
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
