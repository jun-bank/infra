package agentrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/store"
)

// maxRequestBytes는 수신 body 상한이다(서명된 manifest+token — 동봉 compose 포함해도 작다).
const maxRequestBytes = 1 << 20

// ServerConfig는 위성 실행자(Handler)의 배선이다. main이 아니라 위성(ROLE=agent)이 조립한다.
type ServerConfig struct {
	// Target은 이 위성이 담당하는 유일 대상이다(AGENT_TARGET ∈ {settlement,ledger}). manifest의
	// target이 이것과 다르면 부작용 전에 거절한다(R5 오배선 방어).
	Target deploy.Target
	// Key는 이 위성의 개별 RPC 키다(AGENT_RPC_KEY). 수신 요청 서명 검증·응답 서명에 쓴다.
	Key []byte
	// Dispatcher는 로컬 실행 지점이다 — 위성은 internal/dispatch를 재사용하는 deploy.LocalDispatcher를
	// 주입받아 자기 호스트를 배포한다(B5/G2 · 실행 로직 중복 0). settlement/ledger는 단일 경로
	// (Gateway 없음)라 fencing token을 쓰지 않는다.
	Dispatcher deploy.Dispatcher
	// Ledger는 crash-safe 원장이다(멱등·재기동 안전·quarantine).
	Ledger *Ledger
	// ExecBudget은 요청 ctx와 분리된 background 실행의 상한이다(R7). 요청이 끊겨도 ACCEPTED 이후
	// 실행은 취소되지 않아야 하므로, 요청 ctx가 아니라 이 상한이 dispatch를 감싼다.
	ExecBudget time.Duration
	now        func() time.Time
}

// Handler는 위성 실행자의 HTTP 핸들러를 만든다: POST /agent/deploy · GET /agent/status.
// 설정 검증은 fail-closed다 — 키·dispatcher·원장·target·budget 중 하나라도 없으면 오류.
func Handler(cfg ServerConfig) (http.Handler, error) {
	if err := ValidateKey(cfg.Key); err != nil {
		return nil, err
	}
	if !cfg.Target.Valid() {
		return nil, fmt.Errorf("agentrpc: AGENT_TARGET이 닫힌 집합 밖(fail-closed): %q", cfg.Target)
	}
	if cfg.Target != deploy.TargetSettlement && cfg.Target != deploy.TargetLedger {
		// 위성은 settlement·ledger만 담당한다(core·gateway는 .9 로컬 배포다 — 오배선 방어).
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
	if cfg.now == nil {
		cfg.now = time.Now
	}
	k := make([]byte, len(cfg.Key))
	copy(k, cfg.Key)
	cfg.Key = k

	s := &server{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc(PathDeploy, s.handleDeploy)
	mux.HandleFunc(PathStatus, s.handleStatus)
	return mux, nil
}

type server struct{ cfg ServerConfig }

// handleDeploy는 배포 명령을 수신·검증·실행한다. 순서(부작용은 target 결박·멱등 통과 뒤에만):
//
//	RPC 서명 검증(위성 자기 키) → manifest 파싱 → AGENT_TARGET 결박(R5) → 원장 Accept(멱등·
//	quarantine·충돌) → background context로 로컬 dispatch(R7) → terminal 내구 기록 → 응답 서명(R1).
func (s *server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	requestID := r.Header.Get(HeaderRequestID)
	ts := r.Header.Get(HeaderTimestamp)
	reqDigest := BodyDigest(body)

	// RPC 서명 검증(위성 자기 키). 실패면 서명 없는 401 — main은 검증 불가 응답을 UNKNOWN으로
	// 접는다(R2). main은 정상적으로 이 경로를 트리거하지 않는다(같은 코드가 서명한다) — 위조·
	// 키불일치·비인가 프로세스만 여기 온다. 부작용 전이므로 원장을 건드리지 않는다.
	canonical := RequestCanonical(http.MethodPost, PathDeploy, reqDigest, requestID, ts)
	if requestID == "" || !Verify(s.cfg.Key, canonical, r.Header.Get(HeaderSignature)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// manifest 파싱(target 추출). 파싱 실패·닫힌 집합 밖 = 부작용 전 거절(서명된 UNEXECUTED).
	var env deployRequest
	if err := json.Unmarshal(body, &env); err != nil {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted), "요청 envelope 파싱 불가")
		return
	}
	m, err := deploy.ParseManifest(env.Manifest)
	if err != nil {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted), "manifest 파싱 불가: "+err.Error())
		return
	}
	// requestId 결박 — 헤더(서명 범위)의 requestId와 manifest의 requestId가 같아야 한다(DO-10 ⑴).
	if m.RequestID != requestID {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted), "manifest requestId가 서명 requestId와 불일치")
		return
	}

	// R5 — AGENT_TARGET 결박(오배선 방어). 서명이 유효해도 우리 대상이 아니면 부작용 전 거절.
	// deputy(F6): 이 결박은 오배선을 막을 뿐 서명 위조를 막지 않는다 — 위조 방어는 위 RPC 서명이다.
	if m.Target != s.cfg.Target {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted),
			fmt.Sprintf("AGENT_TARGET 결박 위반: 이 위성은 %q인데 manifest.target=%q(오배선 · 부작용0 거절)", s.cfg.Target, m.Target))
		return
	}

	// 원장 Accept — 멱등·quarantine·충돌 판정 + Proceed 시 ACCEPTED 내구 기록(docker 전).
	dec := s.cfg.Ledger.Accept(requestID, reqDigest)
	switch {
	case dec.Err != nil:
		// ACCEPTED fsync 실패 = 상태를 내구 기록할 수 없다. 실행하지 않았으나 원장이 손상됐을 수
		// 있어 UNKNOWN으로 접는다(사람 개입 — fail-closed).
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnknown), "원장 기록 실패(실행 안 함): "+dec.Err.Error())
		return
	case dec.Conflict:
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted),
			"requestId 충돌: 같은 requestId에 다른 command digest(재실행 거부 · 부작용0)")
		return
	case dec.Busy:
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnexecuted),
			"target 점유·격리: 미해소 선행 배포가 있어 새 배포를 받지 않는다(quarantine · 부작용0)")
		return
	case dec.Report != "":
		// 멱등 보고(재실행 없음) — 같은 command 재수신. terminal이면 그 상태, 비terminal이면 UNKNOWN.
		s.respond(w, requestID, reqDigest, ActionDeploy, string(dec.Report), "멱등 재수신 — 기존 상태 보고(재실행 없음)")
		return
	}

	// Proceed — ACCEPTED가 내구 기록됐다. 로컬 dispatch를 **background context**로 실행한다(R7):
	// main 요청 ctx가 끊겨도(응답 타임아웃 등) 이미 수락한 실행을 취소하지 않는다. 취소로 docker를
	// 중간에 죽이면 부분 상태가 남는다 — WithoutCancel로 취소 축만 끊고 ExecBudget으로 상한한다.
	execCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), s.cfg.ExecBudget)
	defer cancel()
	state, derr := s.cfg.Dispatcher.Dispatch(execCtx, m, store.FencingToken(env.FencingToken))

	// dispatch가 정의 밖 상태를 내면 UNKNOWN으로 접는다(coordinator와 같은 방어 — 미실행 오인 금지).
	ledgerState := toLedgerState(state)
	detail := "composePath dispatch"
	if derr != nil {
		detail = derr.Error()
	}

	// terminal을 내구 기록(fsync)한 **뒤에만** 응답한다. 기록 실패면 실행은 했으나 상태를 증명할
	// 수 없다 → UNKNOWN 응답(main이 락 유지·사람). crash window(dispatch 성공→기록 전 죽음)도
	// 재기동 시 ACCEPTED로 남아 UNKNOWN이 되므로, 여기 기록 실패도 같은 방향(UNKNOWN)으로 접는다.
	if ferr := s.cfg.Ledger.Finalize(requestID, reqDigest, ledgerState); ferr != nil {
		s.respond(w, requestID, reqDigest, ActionDeploy, string(StateUnknown),
			"terminal 원장 기록 실패(실행 상태 증명 불가): "+ferr.Error()+" · dispatch="+detail)
		return
	}
	s.respond(w, requestID, reqDigest, ActionDeploy, string(ledgerState), detail)
}

// handleStatus는 requestId의 현재 상태를 조회한다(부작용 0 · 조회만 — 재개는 조각 C). 서명
// 검증은 GET·PathStatus·빈 body digest로 한다. 없는 requestId는 UNEXECUTED로 보고한다
// (아직 이 위성이 그 요청을 본 적이 없다는 뜻 — 위성 로컬엔 부작용이 없다).
func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestID := r.Header.Get(HeaderRequestID)
	ts := r.Header.Get(HeaderTimestamp)
	emptyDigest := BodyDigest(nil)
	canonical := RequestCanonical(http.MethodGet, PathStatus, emptyDigest, requestID, ts)
	if requestID == "" || !Verify(s.cfg.Key, canonical, r.Header.Get(HeaderSignature)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	state, ok := s.cfg.Ledger.Status(requestID)
	if !ok {
		s.respond(w, requestID, emptyDigest, ActionStatus, string(StateUnexecuted), "이 위성이 본 적 없는 requestId(부작용0)")
		return
	}
	s.respond(w, requestID, emptyDigest, ActionStatus, string(state), "원장 상태 조회(조회만 · 재개 없음)")
}

// respond는 서명된 응답을 쓴다(R1). 모든 인증된 응답은 HTTP 200이며 실제 결과는 state 필드가
// 나른다 — httpStatus를 서명에 결박하므로 상태코드를 일관되게 두는 편이 검증을 단순하게 한다.
// requestBodyDigest는 **수신 요청의 digest**다(응답을 그 요청에 결박 — R1). detail에 시크릿을
// 담지 않는다(로그·응답 노출 금지 — 금지영역).
func (s *server) respond(w http.ResponseWriter, requestID, requestBodyDigest, action, state, detail string) {
	const httpStatus = http.StatusOK
	canonical := ResponseCanonical(requestID, requestBodyDigest, action, strconv.Itoa(httpStatus), state)
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
