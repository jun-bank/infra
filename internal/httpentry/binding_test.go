// repo↔target 결박의 통합 테스트 — 여기서는 게이트 2를 **실제 auth.OIDCVerifier**로
// 세운다(서명 검증만 페이크). 페이크 게이트로는 "결정을 어떻게 쓰는가"만 검증되고
// "행렬이 그 결정을 내는가"는 검증되지 않아, 둘 사이가 조용히 갈리면 아무도 잡지 못하기
// 때문이다(실제 정책 → 실제 판정 → HTTP status까지 한 줄로 잇는다).
//
// 또 하나의 축은 동시성이다: 결박·멱등·락은 순차 테스트에서 전부 통과해도 두 요청이
// 겹치는 순간 깨질 수 있다. -race로 도는 동시성 케이스가 "예약 ≤1 · 실행 ≤1"을 지킨다.
package httpentry

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/auth"
	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/store"
)

// --- 실 게이트 2 하네스 -------------------------------------------------------

// 두 저장소의 신원(실 정책의 allowlist 항목과 짝을 이룬다).
const (
	coreToken    = "token-core"
	gatewayToken = "token-gateway"

	coreRepo   = "jun-bank/infra"
	coreRepoID = "123456"
	coreWFRef  = "jun-bank/infra/.github/workflows/deploy.yml@refs/heads/main"

	gatewayRepo   = "jun-bank/gateway"
	gatewayRepoID = "777777"
	gatewayWFRef  = "jun-bank/gateway/.github/workflows/deploy.yml@refs/heads/main"

	testIssuer   = "https://token.actions.githubusercontent.com"
	testAudience = "https://deploy.jun-bank.example"
	testOwnerID  = "654321"
)

// stubTokenVerifier는 서명 검증을 대체한다 — 토큰 문자열마다 미리 정한 claim을 돌려주고,
// 모르는 토큰은 서명 오류로 취급한다(실제 JWKS 경로는 auth 패키지가 검증한다).
type stubTokenVerifier struct{ claims map[string]auth.Claims }

func (s stubTokenVerifier) VerifyToken(_ context.Context, raw string) (auth.Claims, error) {
	c, ok := s.claims[raw]
	if !ok {
		return auth.Claims{}, auth.ErrOIDCMalformed
	}
	return c, nil
}

// realClaims는 지정한 저장소의 정상 claim이다(고정 시각 기준으로 신선하다).
func realClaims(repo, repoID, wfRef, jti string) auth.Claims {
	return auth.Claims{
		Issuer:         testIssuer,
		Audience:       []string{testAudience},
		Subject:        "repo:" + repo + ":ref:refs/heads/main",
		Repository:     repo,
		RepositoryID:   repoID,
		OwnerID:        testOwnerID,
		Ref:            "refs/heads/main",
		JobWorkflowRef: wfRef,
		Environment:    "production",
		JTI:            jti,
		IssuedAt:       testNow.Add(-30 * time.Second).Unix(),
		NotBefore:      testNow.Add(-30 * time.Second).Unix(),
		ExpiresAt:      testNow.Add(5 * time.Minute).Unix(),
	}
}

// twoRepoPolicy는 core·gateway 두 항목이 등재된 실 정책이다.
func twoRepoPolicy(t *testing.T) auth.OIDCPolicy {
	t.Helper()
	list, err := auth.NewOIDCAllowlist([]auth.OIDCAllowEntry{
		{Repository: coreRepo, RepositoryID: coreRepoID, JobWorkflowRef: coreWFRef, Target: deploy.TargetCore},
		{Repository: gatewayRepo, RepositoryID: gatewayRepoID, JobWorkflowRef: gatewayWFRef, Target: deploy.TargetGateway},
	})
	if err != nil {
		t.Fatalf("테스트 allowlist 구성 실패: %v", err)
	}
	return auth.OIDCPolicy{
		Issuer:       testIssuer,
		Audience:     testAudience,
		OwnerID:      testOwnerID,
		RefAllowlist: []string{"refs/heads/main"},
		Allowlist:    list,
		Skew:         auth.DefaultClockSkew,
	}
}

// realGate는 주어진 claim 표로 실제 게이트 2를 만든다.
func realGate(t *testing.T, policy auth.OIDCPolicy, claims map[string]auth.Claims) OIDCGate {
	t.Helper()
	gate, err := auth.NewOIDCVerifier(stubTokenVerifier{claims: claims}, policy, fixedClock{})
	if err != nil {
		t.Fatalf("게이트 2 구성 실패: %v", err)
	}
	return gate
}

// realGateDeps는 실 게이트 2를 물린 deps를 만든다(나머지 협력자는 기존 페이크 그대로).
func realGateDeps(t *testing.T, dispatcher deploy.Dispatcher) (Deps, *fakeHistory) {
	t.Helper()
	claims := map[string]auth.Claims{
		coreToken:    realClaims(coreRepo, coreRepoID, coreWFRef, "jti-core"),
		gatewayToken: realClaims(gatewayRepo, gatewayRepoID, gatewayWFRef, "jti-gateway"),
	}
	return testDepsWith(t, realGate(t, twoRepoPolicy(t), claims), dispatcher)
}

// withToken은 요청의 OIDC 토큰 헤더를 바꾼다(신원 교체).
func withToken(r *http.Request, token string) *http.Request {
	r.Header.Set(headerOIDCToken, token)
	return r
}

// serve는 요청 하나를 태우고 응답 recorder를 준다.
func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// countingDispatcher는 실행 횟수와 **동시 실행 최대치**를 세는 실행 지점이다.
//
// maxActive가 필요한 이유: 호출 횟수만 세면 "두 번 실행됐다"와 "두 번 겹쳐 실행됐다"가
// 구분되지 않는다. 앞의 것은 설계상 허용된다(미실행 상태의 재전송은 재개된다 — 부작용 0
// 증명 위에 선 #9 계약). 금지된 것은 뒤의 것 — 같은 배포가 동시에 두 번 도는 것이며,
// 그것을 막는 것은 배포 창 락이다(CD-3·BG-4: dispatch는 락 보유 단계). hold는 그 겹침이
// 관측 가능하도록 실행이 잠시 머무는 시간이다.
type countingDispatcher struct {
	mu        sync.Mutex
	calls     int
	active    int
	maxActive int
	state     deploy.RemoteState
	hold      time.Duration
}

func (d *countingDispatcher) Dispatch(context.Context, deploy.Manifest, store.FencingToken) (deploy.RemoteState, error) {
	d.mu.Lock()
	d.calls++
	d.active++
	if d.active > d.maxActive {
		d.maxActive = d.active
	}
	d.mu.Unlock()

	if d.hold > 0 {
		time.Sleep(d.hold)
	}

	d.mu.Lock()
	d.active--
	d.mu.Unlock()
	return d.state, nil
}

func (d *countingDispatcher) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// maxConcurrent는 동시에 실행 중이었던 dispatch의 최대 수다.
func (d *countingDispatcher) maxConcurrent() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.maxActive
}

// serializingLock은 한 번에 하나만 잡히는 배포 창 락이다(실 락의 상호배제 계약을 흉내낸다).
// 보유 중 다른 주체의 획득은 실패하며(획득 실패 = 경합 → 409), 해제하면 다시 잡힌다.
// grantLock(항상 획득)으로는 "실행이 락 밖에서 일어나도" 아무도 눈치채지 못한다.
type serializingLock struct {
	mu    sync.Mutex
	held  bool
	token store.FencingToken
}

func (l *serializingLock) Acquire(context.Context, store.HolderKind, string, time.Duration) (store.FencingToken, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return 0, false, nil
	}
	l.held = true
	l.token++
	return l.token, true, nil
}

func (l *serializingLock) Renew(context.Context, store.HolderKind, string, store.FencingToken, time.Duration) (bool, error) {
	return true, nil
}

func (l *serializingLock) Release(context.Context, store.HolderKind, string, store.FencingToken) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.held = false
	return true, nil
}

// --- 실 정책 → HTTP (U8·I1) ---------------------------------------------------

// TestRealPolicyTwoReposEndToEnd는 두 항목이 등재된 실 정책으로 진입 층 전체를 밟는다:
// 각 저장소는 자기 대상을 배포할 수 있고(501 — 실행 지점 도달), 남의 대상은 배포할 수
// 없다(403). 페이크 게이트가 아니라 실제 행렬이 이 판정을 냈다는 것이 이 테스트의 값이다.
func TestRealPolicyTwoReposEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name     string
		token    string
		target   string
		wantCode int
	}{
		{"core 토큰 → core 배포", coreToken, "core", http.StatusNotImplemented},
		{"gateway 토큰 → gateway 배포", gatewayToken, "gateway", http.StatusNotImplemented},
		{"core 토큰 → gateway 배포(교차)", coreToken, "gateway", http.StatusForbidden},
		{"gateway 토큰 → core 배포(교차)", gatewayToken, "core", http.StatusForbidden},
		{"core 토큰 → ledger 배포(미배선 대상)", coreToken, "ledger", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, _ := realGateDeps(t, deploy.StubDispatcher{})
			h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
			iat, exp := freshWindow()

			rec := serve(h, withToken(signedRequest(tc.target, "req-"+tc.target+"-"+tc.token, iat, exp), tc.token))
			if rec.Code != tc.wantCode {
				t.Fatalf("%s: 코드 = %d, 기대 = %d", tc.name, rec.Code, tc.wantCode)
			}
		})
	}
}

// TestRealPolicyMatrixRejectionsMapTo401은 기존 행렬 각 칸이 어긋났을 때의 HTTP 사상을
// 회귀로 못박는다(I14): 전부 401이며 이력에 남는다. 결박(403)은 **행렬을 통과한 뒤**의
// 판정이므로, 행렬 거절이 403으로 새거나 그 반대가 되면 여기서 걸린다.
func TestRealPolicyMatrixRejectionsMapTo401(t *testing.T) {
	valid := realClaims(coreRepo, coreRepoID, coreWFRef, "jti-core")

	for _, tc := range []struct {
		name     string
		mutate   func(*auth.Claims)
		wantCode string // 이력에 남아야 할 기계 판독 코드("" = 코드 없음)
	}{
		{"iss 불일치", func(c *auth.Claims) { c.Issuer = "https://evil.example" }, ""},
		{"aud 불일치", func(c *auth.Claims) { c.Audience = []string{"https://github.com/jun-bank"} }, ""},
		{"owner_id 불일치", func(c *auth.Claims) { c.OwnerID = "111111" }, ""},
		{"ref 허용목록 밖", func(c *auth.Claims) { c.Ref = "refs/heads/feature-x" }, ""},
		{"jti 부재", func(c *auth.Claims) { c.JTI = "" }, ""},
		{"만료(I6 — 403 아님)", func(c *auth.Claims) { c.ExpiresAt = testNow.Add(-time.Hour).Unix() }, ""},
		{"미등재 저장소", func(c *auth.Claims) { c.RepositoryID = "999999" }, auth.ReasonUnregisteredRepo},
		{"개명(ID 등재·이름 다름)", func(c *auth.Claims) { c.Repository = "jun-bank/renamed" }, auth.ReasonRepoRenamed},
		{"다른 워크플로", func(c *auth.Claims) {
			c.JobWorkflowRef = "jun-bank/infra/.github/workflows/release.yml@refs/heads/main"
		}, auth.ReasonWorkflowRefMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := valid
			tc.mutate(&claims)
			deps, hist := testDepsWith(t,
				realGate(t, twoRepoPolicy(t), map[string]auth.Claims{coreToken: claims}),
				deploy.StubDispatcher{})
			ledger := ledgerOf(t, deps)
			h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
			iat, exp := freshWindow()

			rec := serve(h, withToken(signedRequest("core", "req-matrix", iat, exp), coreToken))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s: 코드 = %d, 기대 = 401 (게이트 2 거절)", tc.name, rec.Code)
			}
			if n := ledger.reserveCount(); n != 0 {
				t.Errorf("게이트 2 거절인데 원장 선점이 %d회 일어났다", n)
			}
			ev, ok := hist.find("req-matrix", "REJECTED")
			if !ok {
				t.Fatal("게이트 2 거절이 이력에 없다 (RL-8)")
			}
			if ev.ReasonCode != tc.wantCode {
				t.Errorf("이력 코드 = %q, 기대 = %q", ev.ReasonCode, tc.wantCode)
			}
			// G8 — 정책 내용(등재된 이름 등)이 응답으로 새지 않는다.
			if strings.Contains(rec.Body.String(), coreRepo) || strings.Contains(rec.Body.String(), "allowlist") {
				t.Errorf("응답이 정책 내용을 노출했다: %q", rec.Body.String())
			}
		})
	}
}

// TestGateOneFailureSkipsGateTwo는 게이트 1이 막은 요청에 대해 게이트 2가 아예 호출되지
// 않는지 확인한다(I5). 순서가 뒤집히거나 체인이 재배열되면 위조 서명 요청이 신원 판정
// 비용(실서비스에서는 JWKS 페치)을 유발하고, 게이트 1의 "먼저 막는다"가 무의미해진다.
func TestGateOneFailureSkipsGateTwo(t *testing.T) {
	oidc := acceptingOIDC("jti-skip", deploy.TargetCore)
	deps, _ := testDepsWithOIDC(t, oidc)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	req := signedRequest("core", "req-forged", iat, exp)
	sig := req.Header.Get(headerSignature)
	forged := "0" + sig[1:]
	if forged == sig {
		forged = "1" + sig[1:]
	}
	req.Header.Set(headerSignature, forged)

	if rec := serve(h, req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("위조 서명: 코드 = %d, 기대 = 401", rec.Code)
	}
	if n := oidc.verifyCalls(); n != 0 {
		t.Errorf("게이트 1이 막은 요청에 게이트 2가 %d회 호출됐다 (체인 순서 계약)", n)
	}
}

// --- 재전송·상태 노출 (I10·I11) ----------------------------------------------

// TestSameRepoOtherTargetReplayForbidden은 같은 저장소가 **완료된 requestId로 다른 대상**을
// 배포하려는 재전송을 막는지 본다(I10). 신원은 정당하지만 대상이 자기 것이 아니므로 403이며,
// 멱등 분기(상태 반환·재개)에 닿기 전에 끊긴다.
func TestSameRepoOtherTargetReplayForbidden(t *testing.T) {
	deps, _ := realGateDeps(t, stateDispatcher{state: deploy.StateCompleted})
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	if rec := serve(h, withToken(signedRequest("core", "req-same-repo", iat, exp), coreToken)); rec.Code != http.StatusOK {
		t.Fatalf("1차(core 완료): 코드 = %d, 기대 = 200", rec.Code)
	}

	// 같은 requestId·같은 저장소 토큰이지만 대상이 gateway다.
	rec := serve(h, withToken(signedRequest("gateway", "req-same-repo", iat, exp), coreToken))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("같은 repo·다른 대상 재전송: 코드 = %d, 기대 = 403", rec.Code)
	}
	if rec.Header().Get("X-Deploy-Idempotent-Replay") != "" {
		t.Error("거절 응답에 멱등 재생 표식이 실렸다")
	}
}

// TestUnregisteredRepoReplayNoStateLeak은 **미등재 저장소**의 토큰이 이미 완료된
// requestId를 재전송해도 배포 상태를 얻지 못함을 확인한다(I11).
//
// 이때의 코드는 403이 아니라 401이다 — 결박(403)은 "등재됐으나 대상이 다르다"이고,
// 미등재는 그보다 앞선 게이트 2의 신원 거절이기 때문이다. 요구되는 불변식(상태 미노출·
// 200 아님)은 그대로 서며, 그 경계를 여기서 명시적으로 못박는다.
func TestUnregisteredRepoReplayNoStateLeak(t *testing.T) {
	const strangerToken = "token-stranger"
	claims := map[string]auth.Claims{
		coreToken: realClaims(coreRepo, coreRepoID, coreWFRef, "jti-core"),
		// 등재되지 않은 저장소 — 나머지 칸은 전부 정상이다(미등재 하나만으로 갈린다).
		strangerToken: realClaims("someone/evil", "999999", "someone/evil/.github/workflows/deploy.yml@refs/heads/main", "jti-stranger"),
	}
	deps, hist := testDepsWith(t,
		realGate(t, twoRepoPolicy(t), claims),
		stateDispatcher{state: deploy.StateCompleted})
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	if rec := serve(h, withToken(signedRequest("core", "req-stranger", iat, exp), coreToken)); rec.Code != http.StatusOK {
		t.Fatalf("1차(완료): 코드 = %d, 기대 = 200", rec.Code)
	}

	rec := serve(h, withToken(signedRequest("core", "req-stranger", iat, exp), strangerToken))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("미등재 저장소 재전송: 코드 = %d, 기대 = 401(게이트 2 신원 거절)", rec.Code)
	}
	if rec.Header().Get("X-Deploy-Idempotent-Replay") != "" {
		t.Error("거절 응답에 멱등 재생 표식이 실렸다 — 배포 상태를 미등재 신원에 노출한다")
	}
	if body := rec.Body.String(); strings.Contains(body, "COMPLETED") || strings.Contains(body, "이미 수신된") {
		t.Errorf("거절 응답이 배포 상태를 노출했다: %q", body)
	}
	ev, ok := hist.find("req-stranger", "REJECTED")
	if !ok {
		t.Fatal("미등재 거절이 이력에 없다 (RL-8)")
	}
	if ev.ReasonCode != auth.ReasonUnregisteredRepo {
		t.Errorf("이력 코드 = %q, 기대 = %s", ev.ReasonCode, auth.ReasonUnregisteredRepo)
	}
}

// TestRequestTargetCaseVariantForbidden은 요청 manifest의 target 대소문자 변형이 결박을
// 우회하지 못함을 확인한다(U9 — "PROD"류 표기). 대조는 정확 일치이므로 불일치 거절이다.
func TestRequestTargetCaseVariantForbidden(t *testing.T) {
	for _, target := range []string{"CORE", "Core", "PROD", "core "} {
		t.Run("target="+target, func(t *testing.T) {
			deps, hist := realGateDeps(t, deploy.StubDispatcher{})
			ledger := ledgerOf(t, deps)
			h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
			iat, exp := freshWindow()

			rec := serve(h, withToken(signedRequest(target, "req-case", iat, exp), coreToken))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("target %q: 코드 = %d, 기대 = 403 (정확 일치)", target, rec.Code)
			}
			if n := ledger.reserveCount(); n != 0 {
				t.Errorf("결박 거절인데 원장 선점이 %d회 일어났다", n)
			}
			ev, _ := hist.find("req-case", "REJECTED")
			if ev.ReasonCode != ReasonTargetForbidden {
				t.Errorf("이력 코드 = %q, 기대 = %s", ev.ReasonCode, ReasonTargetForbidden)
			}
		})
	}
}

// --- 이력 코드 4종 영속 (G3) --------------------------------------------------

// TestRejectionReasonCodesPersisted는 요구된 코드 4종이 각각의 경로에서 이력에 남는지
// 확인한다. 코드가 없으면 "왜 거절됐는가"의 집계가 사유 문장 매칭에 기대게 된다.
func TestRejectionReasonCodesPersisted(t *testing.T) {
	valid := realClaims(coreRepo, coreRepoID, coreWFRef, "jti-core")

	for _, tc := range []struct {
		name     string
		mutate   func(*auth.Claims) // nil이면 정상 신원(결박에서 걸린다)
		target   string
		wantCode string
		wantHTTP int
	}{
		{"미등재", func(c *auth.Claims) { c.RepositoryID = "999999" }, "core", auth.ReasonUnregisteredRepo, http.StatusUnauthorized},
		{"개명", func(c *auth.Claims) { c.Repository = "jun-bank/moved" }, "core", auth.ReasonRepoRenamed, http.StatusUnauthorized},
		{"워크플로 불일치", func(c *auth.Claims) {
			c.JobWorkflowRef = "jun-bank/infra/.github/workflows/other.yml@refs/heads/main"
		}, "core", auth.ReasonWorkflowRefMismatch, http.StatusUnauthorized},
		{"결박 위반", nil, "gateway", ReasonTargetForbidden, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := valid
			if tc.mutate != nil {
				tc.mutate(&claims)
			}
			deps, hist := testDepsWith(t,
				realGate(t, twoRepoPolicy(t), map[string]auth.Claims{coreToken: claims}),
				deploy.StubDispatcher{})
			h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
			iat, exp := freshWindow()

			rec := serve(h, withToken(signedRequest(tc.target, "req-code", iat, exp), coreToken))
			if rec.Code != tc.wantHTTP {
				t.Fatalf("%s: 코드 = %d, 기대 = %d", tc.name, rec.Code, tc.wantHTTP)
			}
			ev, ok := hist.find("req-code", "REJECTED")
			if !ok {
				t.Fatal("거절이 이력에 없다 (RL-8)")
			}
			if ev.ReasonCode != tc.wantCode {
				t.Errorf("이력 코드 = %q, 기대 = %q", ev.ReasonCode, tc.wantCode)
			}
			if ev.RejectReason == "" {
				t.Error("코드만 있고 사람이 읽는 사유가 없다 (코드는 사유를 대체하지 않는다)")
			}
		})
	}
}

// TestInternalBindingErrorObservable은 배선 오류(통과했는데 허용 대상이 없음)가 500으로
// 닫히면서 **관측 가능**한지 확인한다(G4): 로그 한 줄 + 코드가 붙은 이력 행. 조용한 500은
// 운영자에게 "왜"가 없는 장애다.
func TestInternalBindingErrorObservable(t *testing.T) {
	// 표준 로거의 출력을 잠시 가로챈다(테스트 종료 시 원래대로 — 다른 테스트의 로그를
	// 삼키지 않게).
	var logs strings.Builder
	prevFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(prevFlags)
	})

	deps, hist := testDepsWithOIDC(t, acceptingOIDC("jti-broken", ""))
	ledger := ledgerOf(t, deps)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	rec := serve(h, signedRequest("core", "req-wiring", iat, exp))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("배선 오류: 코드 = %d, 기대 = 500", rec.Code)
	}
	if n := ledger.reserveCount(); n != 0 {
		t.Errorf("배선 오류인데 원장 선점이 %d회 일어났다", n)
	}
	ev, ok := hist.find("req-wiring", "REJECTED")
	if !ok {
		t.Fatal("배선 오류가 이력에 기록되지 않았다 (조용한 500 금지)")
	}
	if ev.ReasonCode != ReasonInternalBindingError {
		t.Errorf("이력 코드 = %q, 기대 = %s", ev.ReasonCode, ReasonInternalBindingError)
	}
	out := logs.String()
	if !strings.Contains(out, "내부 배선 오류") || !strings.Contains(out, "req-wiring") {
		t.Errorf("로그에 배선 오류·requestId가 남지 않았다: %q", out)
	}
	// 로그에 토큰·서명 등 비밀이 섞이지 않는다(진단은 식별자까지다).
	if strings.Contains(out, "dummy-oidc-token") {
		t.Errorf("로그에 OIDC 토큰이 남았다: %q", out)
	}
}

// --- manifest 형식 오류의 경계 (I4) -------------------------------------------

// TestNonTargetManifestErrorReachesOrchestration은 **target 외** 필드가 잘못된 manifest의
// 현행 경계를 확정한다: 결박은 target만 보므로 통과하고, 완전성 검증(DO-18 6칸)은 락 안의
// VerifyManifest가 소유하므로 그때 422가 된다 — 즉 이 경로는 **선점이 일어난 뒤** 거절된다.
//
// ⚠️ 이것은 의도된 경계이지 누락이 아니다(design rev.2: "전체 manifest 검증은 VerifyManifest
// 소유"). 선점 이전으로 당기려면 진입 층이 manifest 전체를 파싱해야 하고, 그러면 검증의
// 정본이 둘이 된다. 이 테스트는 그 경계가 **말없이 바뀌지 않도록** 현행 동작을 못박는다.
func TestNonTargetManifestErrorReachesOrchestration(t *testing.T) {
	deps, _ := realGateDeps(t, deploy.StubDispatcher{})
	ledger := ledgerOf(t, deps)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	// target은 허용된 core지만 DO-18 나머지 칸이 없다.
	rec := serve(h, withToken(signedBody(`{"target":"core"}`, "req-partial", iat, exp), coreToken))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("불완전 manifest: 코드 = %d, 기대 = 422", rec.Code)
	}
	if n := ledger.reserveCount(); n != 1 {
		t.Errorf("선점 횟수 = %d, 기대 = 1 (target 외 검증은 선점 뒤 — 경계 확정)", n)
	}
}

// --- 동시성 (I15·I16·I18) -----------------------------------------------------

// TestConcurrentSameRequestID는 동일 requestId 2건이 겹쳐 들어올 때의 불변식을 본다(I15).
//
// ★ 무엇이 불변식이고 무엇이 아닌가(단언을 공허하게 만들지 않으려면 이 구분이 먼저다):
//
//	불변식 ⑴ 선점 **성공**은 정확히 1 — 둘 다 신규로 판정되면 멱등이 무너진다.
//	불변식 ⑵ 예약(RESERVED) 이력도 정확히 1행 — 성공 하나당 한 행이다.
//	불변식 ⑶ dispatch 호출 수 == 501 응답 수 — 501은 "실행 지점 도달"의 뜻이므로, 실행
//	         없이 501을 내거나(거짓 보고) 501 없이 실행하는(무음 실행) 쪽 다 걸린다.
//	불변식 ⑷ 동시 실행 최대 1 — 같은 배포가 **겹쳐** 돌지 않는다(배포 창 락이 세우는 계약).
//
//	불변식이 아닌 것: "501이 정확히 1개". 선점에 실패한 쪽은 재전송으로 분류되는데, 그
//	분류는 그 시점의 이력에 달렸다(ClassifyReplay) — 아직 아무 행도 없으면 상태 반환(200),
//	RESERVED·UNEXECUTED가 보이면 재개(501)다. 재개는 설계상 허용된 결과이므로(#9 갭 차단 ·
//	미실행 = 부작용 0 증명) 501 개수를 1로 못박으면 테스트가 타이밍에 따라 깨진다.
//	그래서 개수 대신 ⑶의 **결합**을 단언한다 — 실행과 보고가 어긋나는 것이 진짜 결함이다.
func TestConcurrentSameRequestID(t *testing.T) {
	// hold를 주어 겹침이 관측 가능하게 하고, 직렬화하는 락으로 실행이 락 안에서 일어나는지
	// 본다(항상 획득하는 grantLock으로는 ⑷가 페이크에 가려 검증되지 않는다).
	disp := &countingDispatcher{state: deploy.StateUnexecuted, hold: 20 * time.Millisecond}
	claims := map[string]auth.Claims{coreToken: realClaims(coreRepo, coreRepoID, coreWFRef, "jti-core")}
	deps, hist := testDepsWithLock(t, realGate(t, twoRepoPolicy(t), claims), disp, &serializingLock{})
	ledger := ledgerOf(t, deps)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	const concurrent = 2
	var wg sync.WaitGroup
	codes := make([]int, concurrent)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = serve(h, withToken(signedRequest("core", "req-concurrent", iat, exp), coreToken)).Code
		}(i)
	}
	wg.Wait()

	// ⑴ 둘 다 게이트·결박을 통과해 각각 선점을 시도하지만, 신규는 하나뿐이다.
	if n := ledger.reserveCount(); n != concurrent {
		t.Errorf("선점 시도 = %d, 기대 = %d (둘 다 원장에 닿는다)", n, concurrent)
	}
	if n := ledger.reserveSuccessCount(); n != 1 {
		t.Fatalf("선점 성공 = %d, 기대 = 1 (동시 2건이 둘 다 신규가 되면 같은 배포가 두 번 열린다)", n)
	}
	// ⑵ 예약 이력도 정확히 한 행이다.
	if n := hist.countType("req-concurrent", "RESERVED"); n != 1 {
		t.Errorf("RESERVED 이력 = %d행, 기대 = 1", n)
	}

	// ⑶ 실행 횟수와 "실행 지점 도달(501)" 보고 수가 정확히 맞아야 한다.
	reached := 0
	for _, c := range codes {
		switch c {
		case http.StatusNotImplemented:
			reached++
		case http.StatusOK, http.StatusConflict:
			// 상태 반환(아직 이력이 없어 완료로 분류) · 락 경합 — 둘 다 허용된 결과다.
		default:
			t.Errorf("예상 밖 코드 = %d (501 재개 · 200 상태 반환 · 409 경합 중 하나여야 한다)", c)
		}
	}
	if reached < 1 {
		t.Errorf("501이 하나도 없다 — 선점에 성공한 쪽은 반드시 실행 지점에 닿아야 한다 (codes=%v)", codes)
	}
	if disp.count() != reached {
		t.Errorf("dispatch 호출 = %d회 · 501 응답 = %d건 — 실행과 보고가 어긋난다(무음 실행 또는 거짓 보고)", disp.count(), reached)
	}
	// ⑷ 겹쳐 돌지 않는다 — 락이 실행 구간을 감싼다.
	if n := disp.maxConcurrent(); n != 1 {
		t.Errorf("동시 실행 최대 = %d, 기대 = 1 (같은 배포가 겹쳐 돌았다 — dispatch가 락 밖에서 실행된다)", n)
	}
}

// TestConcurrentCrossRepoContention은 같은 requestId를 **두 저장소**가 동시에 밀 때
// 결박이 흔들리지 않는지 본다(I16): core 대상 요청은 core 토큰만 통과할 수 있고, gateway
// 토큰 쪽은 항상 403이며 원장·실행에 닿지 않는다.
func TestConcurrentCrossRepoContention(t *testing.T) {
	disp := &countingDispatcher{state: deploy.StateUnexecuted}
	deps, _ := realGateDeps(t, disp)
	ledger := ledgerOf(t, deps)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	var wg sync.WaitGroup
	var coreCode, gatewayCode int
	wg.Add(2)
	go func() {
		defer wg.Done()
		coreCode = serve(h, withToken(signedRequest("core", "req-cross-race", iat, exp), coreToken)).Code
	}()
	go func() {
		defer wg.Done()
		gatewayCode = serve(h, withToken(signedRequest("core", "req-cross-race", iat, exp), gatewayToken)).Code
	}()
	wg.Wait()

	if gatewayCode != http.StatusForbidden {
		t.Errorf("교차 repo 요청: 코드 = %d, 기대 = 403 (경합과 무관하게 결박이 선다)", gatewayCode)
	}
	if coreCode != http.StatusNotImplemented {
		t.Errorf("정당한 요청: 코드 = %d, 기대 = 501", coreCode)
	}
	if n := ledger.reserveCount(); n != 1 {
		t.Errorf("선점 시도 = %d, 기대 = 1 (결박에 걸린 쪽은 원장에 닿지 않는다)", n)
	}
	if disp.count() != 1 {
		t.Errorf("dispatch 호출 = %d회, 기대 = 1", disp.count())
	}
}

// TestConcurrentIndependentDeploys는 서로 다른 배포 3건이 동시에 들어와도 간섭하지 않는지
// 본다(I18) — 각자의 신원·대상·requestId가 뒤섞이면 한 요청의 허용 대상이 다른 요청의
// 판정에 쓰일 수 있다(컨텍스트 누수).
func TestConcurrentIndependentDeploys(t *testing.T) {
	disp := &countingDispatcher{state: deploy.StateUnexecuted}
	deps, _ := realGateDeps(t, disp)
	h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
	iat, exp := freshWindow()

	cases := []struct {
		token, target, requestID string
		want                     int
	}{
		{coreToken, "core", "req-par-1", http.StatusNotImplemented},
		{gatewayToken, "gateway", "req-par-2", http.StatusNotImplemented},
		{coreToken, "gateway", "req-par-3", http.StatusForbidden}, // 교차 — 항상 거절
	}
	codes := make([]int, len(cases))

	var wg sync.WaitGroup
	for i, tc := range cases {
		wg.Add(1)
		go func(i int, token, target, id string) {
			defer wg.Done()
			codes[i] = serve(h, withToken(signedRequest(target, id, iat, exp), token)).Code
		}(i, tc.token, tc.target, tc.requestID)
	}
	wg.Wait()

	for i, tc := range cases {
		if codes[i] != tc.want {
			t.Errorf("%s(%s→%s): 코드 = %d, 기대 = %d (동시 실행이 판정을 흔들었다)", tc.requestID, tc.token, tc.target, codes[i], tc.want)
		}
	}
	if disp.count() != 2 {
		t.Errorf("dispatch 호출 = %d회, 기대 = 2 (거절된 1건은 실행에 닿지 않는다)", disp.count())
	}
}

// --- 두 설정 모드의 동등성 (I17) ---------------------------------------------

// TestFileModeAndSingleEnvModeEquivalent는 같은 신원·같은 요청에 대해 **파일 1항목 모드**와
// **단일 env 모드**가 같은 응답을 내는지 본다. 단일 env를 1항목 allowlist로 정규화한 이유가
// 바로 이것이다 — 검증 경로가 하나뿐이어야 모드 전환(이관)이 동작을 바꾸지 않는다.
func TestFileModeAndSingleEnvModeEquivalent(t *testing.T) {
	claims := map[string]auth.Claims{coreToken: realClaims(coreRepo, coreRepoID, coreWFRef, "jti-core")}

	// ⑴ 파일 모드 — 1항목.
	filePolicy := func() auth.OIDCPolicy {
		path := writeTempAllowlist(t, coreRepo+"|"+coreRepoID+"|"+coreWFRef+"|core\n")
		setOIDCEnv(t, map[string]string{
			"OIDC_ALLOWLIST_FILE": path,
		})
		p, err := auth.LoadOIDCPolicy()
		if err != nil {
			t.Fatalf("파일 모드 정책 로딩 실패: %v", err)
		}
		return p
	}()

	// ⑵ 단일 env 모드 — 같은 내용.
	envPolicy := func() auth.OIDCPolicy {
		setOIDCEnv(t, map[string]string{
			"OIDC_REPOSITORY":       coreRepo,
			"OIDC_REPOSITORY_ID":    coreRepoID,
			"OIDC_JOB_WORKFLOW_REF": coreWFRef,
			"OIDC_ALLOWED_TARGET":   "core",
		})
		p, err := auth.LoadOIDCPolicy()
		if err != nil {
			t.Fatalf("단일 env 모드 정책 로딩 실패: %v", err)
		}
		return p
	}()

	scenarios := []struct {
		name           string
		target, reqID  string
		wantSameStatus bool
	}{
		{name: "허용 대상", target: "core", reqID: "req-eq-1"},
		{name: "교차 대상", target: "gateway", reqID: "req-eq-2"},
		{name: "닫힌 집합 밖", target: "oracle-edge", reqID: "req-eq-3"},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			iat, exp := freshWindow()
			run := func(p auth.OIDCPolicy) int {
				deps, _ := testDepsWith(t, realGate(t, p, claims), deploy.StubDispatcher{})
				h := NewHandler(testConfig(DefaultMaxBodyBytes), deps)
				return serve(h, withToken(signedRequest(sc.target, sc.reqID, iat, exp), coreToken)).Code
			}
			fileCode, envCode := run(filePolicy), run(envPolicy)
			if fileCode != envCode {
				t.Fatalf("%s: 파일 모드 = %d · 단일 env 모드 = %d (두 모드가 같은 판정을 내야 한다)", sc.name, fileCode, envCode)
			}
		})
	}
}

// setOIDCEnv는 게이트 2 정책 env를 통째로 세운다(주지 않은 키는 빈 값 = 미설정).
func setOIDCEnv(t *testing.T, over map[string]string) {
	t.Helper()
	base := map[string]string{
		"OIDC_ISSUER":           testIssuer,
		"OIDC_AUDIENCE":         testAudience,
		"OIDC_OWNER_ID":         testOwnerID,
		"OIDC_REF_ALLOWLIST":    "refs/heads/main",
		"OIDC_ALLOWLIST_FILE":   "",
		"OIDC_REPOSITORY":       "",
		"OIDC_REPOSITORY_ID":    "",
		"OIDC_JOB_WORKFLOW_REF": "",
		"OIDC_ALLOWED_TARGET":   "",
		"AGENT_CLOCK_SKEW":      "",
	}
	for k, v := range over {
		base[k] = v
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
}

// writeTempAllowlist는 임시 allowlist 파일을 만들고 경로를 준다.
func writeTempAllowlist(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowlist.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("allowlist 파일 쓰기 실패: %v", err)
	}
	return path
}
