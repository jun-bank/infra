package agentrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/store"
)

// defaultMaxBodyBytes는 수신 body 상한 기본값이다(서명된 manifest+token — 동봉 compose 포함해도 작다).
const defaultMaxBodyBytes int64 = 1 << 20

// ServerConfig는 위성 실행자(Server)의 배선이다. main이 아니라 위성(ROLE=agent)이 조립한다.
type ServerConfig struct {
	// Target은 이 위성이 담당하는 유일 대상이다(AGENT_TARGET ∈ {settlement,ledger}). manifest의
	// target이 이것과 다르면 부작용 전에 거절한다(R5 오배선 방어).
	Target deploy.Target
	// Key는 이 위성의 개별 RPC 키다(AGENT_RPC_KEY). 수신 요청 서명 검증·응답 서명에 쓴다.
	Key []byte
	// Dispatcher는 로컬 실행 지점이다 — 위성은 internal/dispatch를 재사용하는 deploy.LocalDispatcher를
	// 주입받아 자기 호스트를 배포한다(B5/G2 · 실행 로직 중복 0).
	Dispatcher deploy.Dispatcher
	// Ledger는 crash-safe 원장이다(멱등·재기동 안전·quarantine).
	Ledger *Ledger
	// ExecBudget은 요청 ctx와 분리된 background 실행의 상한이다(R7). 요청이 끊겨도 ACCEPTED 이후
	// 실행은 취소되지 않아야 하므로, 요청 ctx가 아니라 이 상한이 dispatch를 감싼다.
	ExecBudget time.Duration
	// Skew는 RPC timestamp 신선도 허용 창이다(C4). 서명이 유효해도 이 창 밖이면 거절한다 —
	// 가로챈 유효 요청을 락 만료 후 재생하는 것을 막는다(replay 방어). >0 필수(fail-closed).
	Skew time.Duration
	// MaxBodyBytes는 수신 body 상한이다(C7 · slow-body/거대 body DoS 방어). ≤0이면 기본값.
	MaxBodyBytes int64
	// Fence는 각 mutation 직전 fence 확인을 하는 역방향 확인기다(infra#37 조각 B). 설정되면
	// handleDeploy가 dispatch별 GuardSession을 만들어 execCtx에 실어 넘긴다 — 그 세션을 위성
	// 조립이 GuardLocalDispatcher로 감싼 실행기들이 mutation 직전에 소비한다(G-2·G-3). nil이면
	// fencing 없음(조각 A 동작 그대로 — 세션을 주입하지 않고 실행기도 decorate되지 않는다).
	// 위성 조립은 Fence 주입과 dispatcher decoration을 **함께** 하고, 둘이 어긋나면 decorate된
	// 실행기가 guard context 누락으로 fail-closed된다(G-2).
	Fence FenceConfirmer
	now   func() time.Time
}

// Server는 위성 실행자다. HTTP 핸들러(ServeHTTP)와 in-flight 실행 배수(WaitInFlight)를 함께
// 제공해, 종료 시 ACCEPTED된 배포가 terminal을 내구 기록할 때까지 소유·대기하게 한다(C1①).
type Server struct {
	cfg ServerConfig
	mux http.Handler
	// gate는 종료 gate와 in-flight 등록을 **원자로** 묶는다(C1). shuttingDown 확인과 inflight.Add를
	// 같은 락 안에서 해, WaitInFlight가 gate를 닫은 뒤엔 어떤 새 실행도 등록되지 못하게 한다 —
	// "Accept 직전 등록" + "gate 닫힘 뒤 신규 거절"로 shutdown race(등록 전 공백)를 없앤다.
	gate         sync.Mutex
	shuttingDown bool
	inflight     sync.WaitGroup
}

// NewServer는 위성 실행자를 만든다: POST /agent/deploy · GET /agent/status. 설정 검증은
// fail-closed다 — 키·dispatcher·원장·target·budget·skew 중 하나라도 없으면 오류.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := ValidateKey(cfg.Key); err != nil {
		return nil, err
	}
	if !cfg.Target.Valid() {
		return nil, fmt.Errorf("agentrpc: AGENT_TARGET이 닫힌 집합 밖(fail-closed): %q", cfg.Target)
	}
	if cfg.Target != deploy.TargetSettlement && cfg.Target != deploy.TargetLedger {
		return nil, fmt.Errorf("agentrpc: 위성 AGENT_TARGET은 settlement|ledger여야 한다(core·gateway는 .9 로컬): %q", cfg.Target)
	}
	if cfg.Dispatcher == nil {
		return nil, fmt.Errorf("agentrpc: 로컬 dispatcher가 nil(fail-closed)")
	}
	if cfg.Ledger == nil {
		return nil, fmt.Errorf("agentrpc: 원장이 nil(fail-closed)")
	}
	if cfg.ExecBudget <= 0 {
		return nil, fmt.Errorf("agentrpc: ExecBudget은 >0 이어야 한다(fail-closed): %s", cfg.ExecBudget)
	}
	if cfg.Skew <= 0 {
		return nil, fmt.Errorf("agentrpc: RPC skew는 >0 이어야 한다(신선도 창 · fail-closed): %s", cfg.Skew)
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	k := make([]byte, len(cfg.Key))
	copy(k, cfg.Key)
	cfg.Key = k

	s := &Server{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc(PathDeploy, s.handleDeploy)
	mux.HandleFunc(PathStatus, s.handleStatus)
	s.mux = mux
	return s, nil
}

// ServeHTTP는 내부 mux로 위임한다(Server가 http.Handler).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// WaitInFlight는 진행 중인(ACCEPTED된) 배포 실행이 전부 terminal을 기록하고 끝날 때까지
// 기다린다(C1① — 종료 시 in-flight 소유). ctx가 먼저 끝나면 ctx.Err()를 낸다. 호출자(runAgent)는
// 리스너를 닫아 새 요청을 막은 뒤 이 함수를 ExecBudget까지 기다려, SIGTERM이 pull/up 도중
// dispatch·terminal 기록을 끊지 않게 한다.
func (s *Server) WaitInFlight(ctx context.Context) error {
	// 먼저 gate를 닫는다(C1) — 이 뒤 enter()는 전부 거절되므로, 지금 등록돼 있는 실행만 남는다.
	// 등록(inflight.Add)이 shuttingDown 확인과 같은 락 안에서 일어나 "닫힌 뒤 등록"이 불가능하다.
	s.gate.Lock()
	s.shuttingDown = true
	s.gate.Unlock()

	done := make(chan struct{})
	go func() { s.inflight.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// enter는 종료 중이 아니면 이 실행을 in-flight로 등록한다(C1). shuttingDown 확인과 inflight.Add가
// **같은 락 안에서** 원자로 일어나, WaitInFlight가 gate를 닫은 뒤에는 절대 등록되지 못한다. 등록에
// 성공하면 호출자는 반드시 leave로 짝을 맞춰야 한다. false면 종료 중이므로 새 배포를 받지 않는다.
func (s *Server) enter() bool {
	s.gate.Lock()
	defer s.gate.Unlock()
	if s.shuttingDown {
		return false
	}
	s.inflight.Add(1)
	return true
}

// leave는 in-flight 등록을 해제한다(enter 성공과 짝).
func (s *Server) leave() { s.inflight.Done() }

// handleDeploy는 배포 명령을 수신·검증·실행한다. 순서(부작용은 신선도·target 결박·멱등 통과 뒤에만):
//
//	body 상한(C7) → RPC 서명 검증(위성 자기 키) → 신선도 창(C4) → manifest 파싱 → requestId 결박
//	→ AGENT_TARGET 결박(R5) → 원장 Accept(멱등·quarantine·충돌) → background dispatch(R7) →
//	(COMPLETED,err)=UNKNOWN 정규화(C2) → terminal 내구 기록 → 응답 서명(R1).
func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// C7 — HMAC 검증 **전에** body를 상한한다(거대·slow body가 handler·FD를 무기한 점유하는 것 방지).
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "body too large or read error", http.StatusRequestEntityTooLarge)
		return
	}
	requestID := r.Header.Get(HeaderRequestID)
	ts := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)        // 조각 C R2 — 응답 canonical에 그대로 결박(replay 방어)
	attemptStr := r.Header.Get(HeaderAttempt) // 조각 C R1 — 재개 vs 중복 축(서명 canonical 결박)
	reqDigest := BodyDigest(body)

	// RPC 서명 검증(위성 자기 키). 실패면 서명 없는 401 — main은 검증 불가 응답을 UNKNOWN으로
	// 접는다(R2). 부작용 전이므로 원장을 건드리지 않는다. nonce·attempt는 canonical에 들어 있어
	// 헤더가 위조·변조되면 여기서 서명 불일치로 걸린다(H2 — attempt는 body digest와 분리 결박).
	canonical := RequestCanonical(http.MethodPost, PathDeploy, reqDigest, requestID, ts, nonce, attemptStr)
	if requestID == "" || !Verify(s.cfg.Key, canonical, r.Header.Get(HeaderSignature)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// C4 — 신선도 창. 서명이 유효해도 timestamp가 창 밖이면 거절한다(가로챈 유효 POST를 락 만료
	// 후 재생하면 원장에 없어 신규 ACCEPTED로 실행되는 stale 실행 차단). 부작용 전이다.
	if !s.freshOK(ts) {
		http.Error(w, "stale request (freshness window)", http.StatusUnauthorized)
		return
	}
	// attempt 파싱 — 서명이 통과했으므로 attemptStr은 main이 서명한 진짜 값이다(정상 main은 항상
	// 유효 10진). 그래도 방어적으로 파싱해, 정의 밖이면 부작용 전 거절한다(UNEXECUTED · 부작용0).
	attempt, aerr := strconv.Atoi(attemptStr)
	if aerr != nil || attempt < firstAttempt {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted), nonce, "attempt 헤더가 정의 밖(부작용0 거절)")
		return
	}

	// manifest 파싱(target 추출). 파싱 실패·닫힌 집합 밖 = 부작용 전 거절(서명된 UNEXECUTED).
	var env deployRequest
	if err := json.Unmarshal(body, &env); err != nil {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted), nonce, "요청 envelope 파싱 불가")
		return
	}
	m, err := deploy.ParseManifest(env.Manifest)
	if err != nil {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted), nonce, "manifest 파싱 불가: "+err.Error())
		return
	}
	// requestId 결박 — 헤더(서명 범위)의 requestId와 manifest의 requestId가 같아야 한다(DO-10 ⑴).
	if m.RequestID != requestID {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted), nonce, "manifest requestId가 서명 requestId와 불일치")
		return
	}

	// R5 — AGENT_TARGET 결박(오배선 방어). 서명이 유효해도 우리 대상이 아니면 부작용 전 거절.
	// deputy(F6): 이 결박은 오배선을 막을 뿐 서명 위조를 막지 않는다 — 위조 방어는 위 RPC 서명이다.
	if m.Target != s.cfg.Target {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted), nonce,
			fmt.Sprintf("AGENT_TARGET 결박 위반: 이 위성은 %q인데 manifest.target=%q(오배선 · 부작용0 거절)", s.cfg.Target, m.Target))
		return
	}

	// C1 — Accept **직전에** in-flight로 등록한다(ACCEPTED 기록·실행이 이 창 안에 든다). 종료
	// 중이면 등록이 거절되어(gate 닫힘) 503으로 새 배포를 받지 않는다 — 부작용 전이라 원장 무접촉.
	if !s.enter() {
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	defer s.leave()

	// 원장 Accept — 멱등·quarantine·충돌·재개 판정 + Proceed 시 ACCEPTED 내구 기록(docker 전).
	// attempt로 재개(terminal UNEXECUTED@N + N+1)와 중복(같은 attempt)·stale(N<현재)을 가른다(R1).
	dec := s.cfg.Ledger.Accept(requestID, reqDigest, attempt)
	switch {
	case dec.Err != nil:
		// ACCEPTED fsync 실패·원장 오염 = 상태를 내구 기록할 수 없다. 실행하지 않았으나 원장이
		// 손상됐을 수 있어 UNKNOWN으로 접는다(사람 개입 — fail-closed).
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnknown), nonce, "원장 기록 실패(실행 안 함): "+dec.Err.Error())
		return
	case dec.Conflict:
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted), nonce,
			"requestId 충돌: 같은 requestId에 다른 command digest(재실행 거부 · 부작용0)")
		return
	case dec.Busy:
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted), nonce,
			"target 점유·격리: 미해소 선행 배포가 있어 새 배포를 받지 않는다(quarantine · 부작용0)")
		return
	case dec.Report != "":
		// 멱등·stale·재개금지 보고(재실행 없음) — 같은 command 재수신. terminal이면 그 상태,
		// 비terminal이면 UNKNOWN. COMPLETED terminal + 재개 시도도 여기서 COMPLETED 보고다(replay 방어).
		s.respond(w, requestID, reqDigest, ActionDeploy, string(dec.Report), nonce, "멱등/stale 재수신 — 기존 상태 보고(재실행 없음)")
		return
	}

	// Proceed — ACCEPTED가 내구 기록됐다(in-flight 등록은 Accept 직전 enter로 이미 이뤄졌다 · C1).
	// 로컬 dispatch를 **background context**로 실행한다(R7): main 요청 ctx가 끊겨도(응답 타임아웃
	// 등) 이미 수락한 실행을 취소하지 않는다. 취소로 docker를 중간에 죽이면 부분 상태가 남는다 —
	// WithoutCancel로 취소 축만 끊고 ExecBudget으로 상한한다.
	execCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), s.cfg.ExecBudget)
	defer cancel()
	// infra#37 조각 B — fencing이 배선됐으면 이 dispatch의 sticky GuardSession을 만들어 execCtx에
	// 싣는다(G-2). decorate된 실행기들이 각 up/down 직전에 이 세션을 꺼내 fence 확인을 한다.
	// 세션은 dispatch 하나에 결박되며, cleanupAfterFailure의 WithoutCancel 파생도 값(세션)을
	// 보존하므로 첫 실패 뒤 cleanup down까지 같은 세션이 막는다.
	if s.cfg.Fence != nil {
		session := NewGuardSession(s.cfg.Fence, s.cfg.Target, requestID, env.FencingToken)
		execCtx = withGuardSession(execCtx, session)
	}
	state, derr := s.cfg.Dispatcher.Dispatch(execCtx, m, store.FencingToken(env.FencingToken))

	// C2 — 모순 조합 정규화(coordinator.go:265와 동일 규칙). (COMPLETED, err≠nil)은 완료와 실패를
	// 동시에 주장하는 조합이라 완료를 신뢰할 수 없다 → UNKNOWN. 이 정규화를 위성이 하지 않으면
	// main이 COMPLETED,nil로 받아 성공·락 해제해 coordinator의 같은 정규화를 우회한다(greenwashing).
	detail := "dispatch 완료"
	if state == deploy.StateCompleted && derr != nil {
		state = deploy.StateUnknown
		detail = "모순 조합(dispatch가 COMPLETED와 오류를 함께 보고) — 완료를 신뢰할 수 없다: " + derr.Error()
	} else if derr != nil {
		detail = derr.Error()
	}
	ledgerState := toLedgerState(state)

	// terminal을 내구 기록(fsync)한 **뒤에만** 응답한다. 기록 실패면 실행은 했으나 상태를 증명할
	// 수 없다 → UNKNOWN 응답(main이 락 유지·사람). crash window(dispatch 성공→기록 전 죽음)도
	// 재기동 시 ACCEPTED로 남아 UNKNOWN이 되므로, 여기 기록 실패도 같은 방향(UNKNOWN)으로 접는다.
	if ferr := s.cfg.Ledger.Finalize(requestID, reqDigest, ledgerState); ferr != nil {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnknown), nonce,
			"terminal 원장 기록 실패(실행 상태 증명 불가): "+ferr.Error()+" · dispatch="+detail)
		return
	}
	s.respond(w, requestID, reqDigest, ActionDeploy, string(ledgerState), nonce, detail)
}

// handleStatus는 requestId의 현재 상태를 조회한다(부작용 0 · 조회만 — 재개는 조각 C). 본 적 없는
// requestId는 **WireAbsent**로 보고한다(C8 — durable-UNEXECUTED와 서명 계약에서 구분).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestID := r.Header.Get(HeaderRequestID)
	ts := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce) // 조각 C R2 — 응답에 결박(과거 status 응답 replay 방어)
	emptyDigest := BodyDigest(nil)
	// status는 attempt가 없다 — canonical의 attempt 필드는 빈 문자열이다(main statusOnce와 동일).
	canonical := RequestCanonical(http.MethodGet, PathStatus, emptyDigest, requestID, ts, nonce, "")
	if requestID == "" || !Verify(s.cfg.Key, canonical, r.Header.Get(HeaderSignature)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.freshOK(ts) {
		http.Error(w, "stale request (freshness window)", http.StatusUnauthorized)
		return
	}
	state, ok := s.cfg.Ledger.Status(requestID)
	if !ok {
		// ABSENT — 이 위성이 본 적 없는 requestId. durable-UNEXECUTED(실행 후 부작용0 증명)와
		// 다른 별도 wire 상태로 서명한다(C8 · 조각 C가 재개 근거로 오인하지 않게).
		s.respond(w, requestID, emptyDigest, ActionStatus, WireAbsent, nonce, "이 위성이 본 적 없는 requestId(부작용0)")
		return
	}
	s.respond(w, requestID, emptyDigest, ActionStatus, string(state), nonce, "원장 상태 조회(조회만 · main이 재개 판정)")
}

// freshOK는 RPC timestamp를 엄격 파싱해 신선도 창 안인지 본다(C4). 로직은 freshTimestampOK
// 단일 출처에 있다(fence 핸들러와 공유 — overflow-safe: 엄격 10진·sec≤0 선거절·초 단위 int64
// 비교). |now - ts| ≤ Skew.
func (s *Server) freshOK(ts string) bool {
	return freshTimestampOK(s.cfg.now(), ts, s.cfg.Skew)
}

// respond는 서명된 응답을 쓴다(R1). 모든 인증된 응답은 HTTP 200이며 실제 결과는 state 필드가
// 나른다 — httpStatus를 서명에 결박하므로 상태코드를 일관되게 두는 편이 검증을 단순하게 한다.
// requestBodyDigest는 **수신 요청의 digest**다(응답을 그 요청에 결박 — R1). nonce는 **수신 요청의
// nonce**를 그대로 응답 canonical에 결박한다(조각 C R2 — main이 자기가 보낸 nonce로 검증해 과거
// 응답 replay를 거른다). detail에 시크릿을 담지 않는다(로그·응답 노출 금지 — 금지영역).
func (s *Server) respond(w http.ResponseWriter, requestID, requestBodyDigest, action, state, nonce, detail string) {
	const httpStatus = http.StatusOK
	canonical := ResponseCanonical(requestID, requestBodyDigest, action, strconv.Itoa(httpStatus), state, nonce)
	sig := Sign(s.cfg.Key, canonical)
	w.Header().Set(HeaderSignature, sig)
	w.Header().Set(HeaderTimestamp, strconv.FormatInt(s.cfg.now().Unix(), 10))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(deployResponse{RequestID: requestID, Action: action, State: state, Detail: detail})
}

// toLedgerState는 dispatch가 낸 deploy.RemoteState를 원장 terminal 상태로 사상한다. 정의 밖
// 상태(빈 값·미지)는 UNKNOWN으로 접는다 — UNEXECUTED로 오인해 재개를 여는 것을 막는다.
func toLedgerState(st deploy.RemoteState) LedgerState {
	switch st {
	case deploy.StateCompleted:
		return StateCompleted
	case deploy.StateUnexecuted:
		return StateUnexecuted
	default:
		return StateUnknown
	}
}

// ValidateListenAddr는 위성 RPC 리스너 주소가 LAN 전용인지 검증한다(R7·B1 · 인터넷 비노출).
// 거절: 빈 주소·wildcard(0.0.0.0·::)·hostname(literal IP가 아닌 것). 요구: literal private LAN IP
// (10/8·172.16/12·192.168/16·fc00::/7) 또는 loopback. 반환값은 net.Listen에 쓸 검증된 주소다.
// 호출자는 리스닝 후 실제 listener 주소가 이 host인지 한 번 더 확인한다(리스너 주소 확인 — R7).
func ValidateListenAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("agentrpc: AGENT_LISTEN_ADDR은 host:port 형식이어야 한다: %q (%w)", addr, err)
	}
	if host == "" {
		return "", fmt.Errorf("agentrpc: AGENT_LISTEN_ADDR host가 비어 있다(wildcard bind 금지 — LAN literal IP 필요): %q", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("agentrpc: AGENT_LISTEN_ADDR host는 literal IP여야 한다(hostname·wildcard 금지 — DNS 확장이 공개 bind로 새는 것 방지): %q", host)
	}
	if ip.IsUnspecified() {
		return "", fmt.Errorf("agentrpc: AGENT_LISTEN_ADDR이 wildcard(0.0.0.0·::)다 — 인터넷 노출 금지(literal private LAN IP 필요): %q", host)
	}
	if !ip.IsPrivate() && !ip.IsLoopback() {
		return "", fmt.Errorf("agentrpc: AGENT_LISTEN_ADDR이 private LAN·loopback이 아니다 — 위성은 인터넷 비노출이어야 한다(DO-1): %q", host)
	}
	if port == "" {
		return "", fmt.Errorf("agentrpc: AGENT_LISTEN_ADDR에 포트가 없다: %q", addr)
	}
	return addr, nil
}
