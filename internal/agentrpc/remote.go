package agentrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/store"
)

// maxResponseBytes는 위성 응답 body의 상한이다 — 서명된 작은 JSON이므로 넉넉히 잡되
// 무한 읽기를 막는다(악의적/오작동 위성의 메모리 고갈 방지).
const maxResponseBytes = 1 << 16

// RemoteDispatcher는 main 측 원격 실행자다 — coordinator가 부르는 deploy.Dispatcher 구현이며,
// 위성 host에 `POST /agent/deploy`(서명)를 보내고 **응답 HMAC을 검증**해 3상태를 만든다.
//
// 조각 C — 1회 제한 자동 해소 사이클(R3 · 루프 없음 · 총 네트워크 op ≤ 3):
//
//	execute#1(attempt=1) → 인증 terminal → 반환
//	                     → UNKNOWN → status 조회 1회(새 nonce)
//	                         → durable UNEXECUTED **정확 문자열 일치** → 재개 execute#2(attempt=2)
//	                             → 인증 terminal 반환 / 재차 UNKNOWN → **즉시 반환**(재조회 없음)
//	                         → ABSENT·조회 실패·그 외 상태(COMPLETED·UNKNOWN 등) = 전부 UNKNOWN(M1 fail-closed)
//
// UNEXECUTED 정확 일치에만 재개하는 이유(B2): ABSENT(WireAbsent="ABSENT")는 status 조회가 execute
// 보다 먼저 처리된 것일 수 있어 **미도달 증명이 아니다**. durable UNEXECUTED("UNEXECUTED")만이 위성이
// 실제로 dispatch를 돌려 부작용0을 내구 증명한 상태다 — 두 문자열은 다른 값이라(C8) 정확 일치로 가른다.
//
// ⚠️ 재개 실익의 정직한 한계(R5): 위성 durable UNEXECUTED는 "dispatch가 실제 돌아 부작용0 거절"
// (pull 실패·preflight)이고 **대부분 결정론적**이라 재실행이 같은 거절을 재현한다. 게다가 재개는
// execute#1이 **UNKNOWN(응답 유실 — dial 후 단절·검증 실패)** 일 때만 발동한다 — 위성이 UNEXECUTED를
// **깨끗이 응답**하면 그 값이 그대로 반환돼(해소 사이클 미진입) 재개하지 않는다. 따라서 실익은
// "transient 거절 + 그 응답까지 유실"이 겹치는 **더 좁은** 창(레지스트리 일시 불통이 회복될 즈음
// 응답도 유실)뿐이다. 무의미할 수 있는 1회 재배포는 수용한다 — 무한이 아니고(op≤3) fencing
// (조각 B)이 중복 배포를 막는다.
type RemoteDispatcher struct {
	baseURL string        // 위성 base URL(예: http://10.0.0.158:9000) — 경로는 붙이지 않은 채 보관
	key     []byte        // 위성별 개별 키(AGENT_RPC_KEY_SETTLEMENT/LEDGER 중 하나)
	timeout time.Duration // 요청 전체 상한
	target  deploy.Target // 이 dispatcher가 담당하는 대상(진단·라우팅 표기용)
	now     func() time.Time
}

// 컴파일 타임 계약 확인 — RemoteDispatcher는 deploy.Dispatcher다.
var _ deploy.Dispatcher = (*RemoteDispatcher)(nil)

// NewRemoteDispatcher는 원격 실행자를 만든다. URL·키·timeout을 검증한다(fail-closed):
// 키 공백 불가, URL은 http/https absolute, timeout 양수.
func NewRemoteDispatcher(rawURL string, key []byte, timeout time.Duration, target deploy.Target) (*RemoteDispatcher, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("agentrpc: 위성 URL이 http(s) absolute가 아니다(fail-closed): %q", rawURL)
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("agentrpc: RPC timeout은 >0 이어야 한다(fail-closed): %s", timeout)
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &RemoteDispatcher{
		baseURL: strings.TrimRight(rawURL, "/"),
		key:     k,
		timeout: timeout,
		target:  target,
		now:     time.Now,
	}, nil
}

// Dispatch는 검증된 manifest를 위성에 원격 실행하고 3상태를 만든다(DO-16), UNKNOWN이면 1회 제한
// 자동 해소 사이클을 돈다(R3 — 위 struct 주석의 상태도). coordinator는 이 Dispatch가 반환할 때까지
// 락을 쥔 채 블로킹하므로, lease는 해소 사이클(execute#1 + status왕복 + execute#2)을 덮어야 한다
// (R4 — main.go leaseCoversRemote). 총 네트워크 op ≤ 3, 루프 없음.
func (d *RemoteDispatcher) Dispatch(ctx context.Context, m deploy.Manifest, token store.FencingToken) (deploy.RemoteState, error) {
	// execute#1 — 최초 배포(attempt=1). 인증 terminal이면 그대로 반환한다(UNKNOWN만 해소 사이클로).
	st, err := d.executeOnce(ctx, m, token, firstAttempt)
	if st != deploy.StateUnknown {
		return st, err
	}

	// UNKNOWN — 실상태를 status로 1회 판정한다(새 nonce). 조회 실패는 재개 근거가 없으니 UNKNOWN(M1).
	wireState, serr := d.statusOnce(ctx, m.RequestID)
	if serr != nil {
		return deploy.StateUnknown, fmt.Errorf("agentrpc: UNKNOWN 후 status 조회 실패 — 재개 근거 없음(UNKNOWN·사람): %w", serr)
	}

	// durable UNEXECUTED **정확 문자열 일치**에만 재개한다(B2 · M1). ABSENT·COMPLETED·UNKNOWN·그 외
	// 미지 문자열은 전부 재개 없이 UNKNOWN이다 — ABSENT는 미도달 증명이 아니고(조회가 execute보다
	// 먼저 처리됐을 수 있다), 그 밖의 상태도 "부작용0 내구 증명"이 아니라 재실행이 안전하지 않다.
	if wireState != string(StateUnexecuted) {
		return deploy.StateUnknown, fmt.Errorf("agentrpc: status가 durable UNEXECUTED가 아니다(wire=%q) — 재개 없이 UNKNOWN(락 유지·사람)", wireState)
	}

	// 재개 execute#2(attempt=2). 위성 원장이 (UNEXECUTED@1)+(attempt2)를 재개 ACCEPTED로 받아 다시
	// dispatch한다. 결과가 인증 terminal이면 반환, 재차 UNKNOWN이면 **즉시 반환**한다(재조회 없음 · M2).
	st2, err2 := d.executeOnce(ctx, m, token, firstAttempt+1)
	return st2, err2
}

// executeOnce는 `POST /agent/deploy` 한 번을 왕복한다(attempt·새 nonce 결박). R2 미실행/UNKNOWN
// 경계는 보수적이다: dial **전** 실패만 미실행(부작용 0 증명), dial **후** 모든 오류는 UNKNOWN이다
// (요청이 도달했을 수 있다 — 실패로 접으면 중복 배포). attempt는 요청 body(commandDigest)와 분리된
// 축으로 canonical에 결박되므로(H2), 재개(attempt+1)가 같은 manifest를 보내도 body digest는 그대로다.
func (d *RemoteDispatcher) executeOnce(ctx context.Context, m deploy.Manifest, token store.FencingToken, attempt int) (deploy.RemoteState, error) {
	// 1. 로컬 요청 구성(부작용 0 · dial 전) — 실패는 미실행이다(요청 바이트가 나가지 않았다).
	//    attempt는 body에 넣지 않는다 — commandDigest를 attempt-독립으로 유지해 재개가 충돌로
	//    오인되지 않게 한다(H2). attempt·nonce는 헤더 + 서명 canonical로만 나른다.
	mb, err := json.Marshal(m)
	if err != nil {
		return deploy.StateUnexecuted, fmt.Errorf("agentrpc: manifest marshal 실패(미실행·부작용0): %w", err)
	}
	body, err := json.Marshal(deployRequest{Manifest: mb, FencingToken: uint64(token)})
	if err != nil {
		return deploy.StateUnexecuted, fmt.Errorf("agentrpc: 요청 body marshal 실패(미실행·부작용0): %w", err)
	}
	nonce, err := newNonce()
	if err != nil {
		// CSPRNG 실패 = 약한 nonce로 replay 방어를 열지 않는다. 요청이 나가지 않았으니 미실행이다.
		return deploy.StateUnexecuted, fmt.Errorf("agentrpc: nonce 생성 실패(미실행·부작용0): %w", err)
	}
	requestID := m.RequestID
	ts := strconv.FormatInt(d.now().Unix(), 10)
	attemptStr := strconv.Itoa(attempt)
	reqDigest := BodyDigest(body)
	sig := Sign(d.key, RequestCanonical(http.MethodPost, PathDeploy, reqDigest, requestID, ts, nonce, attemptStr))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+PathDeploy, bytes.NewReader(body))
	if err != nil {
		return deploy.StateUnexecuted, fmt.Errorf("agentrpc: 요청 구성 실패(미실행·부작용0): %w", err)
	}
	req.Header.Set(HeaderRequestID, requestID)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderAttempt, attemptStr)
	req.Header.Set(HeaderSignature, sig)
	req.Header.Set("Content-Type", "application/json")

	rr, mapped, err := d.roundtrip(req, requestID, reqDigest, nonce)
	if err != nil {
		return mapped, err
	}

	// 인증된 durable 상태를 3상태로 사상. UNKNOWN이면 Dispatch가 해소 사이클을 잇는다.
	switch deploy.RemoteState(rr.State) {
	case deploy.StateCompleted:
		return deploy.StateCompleted, nil
	case deploy.StateUnexecuted:
		// 위성이 부작용 0을 내구 증명한 거절(target 불일치·quarantine·충돌 등). 오류로 사유를 운반한다.
		return deploy.StateUnexecuted, fmt.Errorf("agentrpc: 원격 위성 미실행(부작용0): %s", rr.Detail)
	case deploy.StateUnknown:
		return deploy.StateUnknown, fmt.Errorf("agentrpc: 원격 위성 UNKNOWN(락 유지·사람): %s", rr.Detail)
	default:
		// 정의 밖 상태 문자열(빈 값 포함)은 신뢰할 수 없다 → UNKNOWN(coordinator가 락 유지).
		return deploy.StateUnknown, fmt.Errorf("agentrpc: 응답 state가 정의 밖(%q — UNKNOWN)", rr.State)
	}
}

// statusOnce는 `GET /agent/status` 한 번을 왕복하고 인증된 **wire 상태 문자열**을 그대로 돌려준다
// (UNEXECUTED·COMPLETED·UNKNOWN·ABSENT). 새 nonce를 결박해 과거 status 응답 replay를 막는다(R2).
// 조회는 부작용이 없으므로 미실행/UNKNOWN 경계가 없다 — 어떤 실패든 오류로 반환하고, Dispatch가
// 이를 "재개 근거 없음(UNKNOWN)"으로 접는다.
func (d *RemoteDispatcher) statusOnce(ctx context.Context, requestID string) (string, error) {
	nonce, err := newNonce()
	if err != nil {
		return "", fmt.Errorf("agentrpc: status nonce 생성 실패: %w", err)
	}
	ts := strconv.FormatInt(d.now().Unix(), 10)
	emptyDigest := BodyDigest(nil)
	// status는 attempt가 없다 — canonical의 attempt 필드는 빈 문자열(위성 handleStatus와 동일).
	sig := Sign(d.key, RequestCanonical(http.MethodGet, PathStatus, emptyDigest, requestID, ts, nonce, ""))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+PathStatus, nil)
	if err != nil {
		return "", fmt.Errorf("agentrpc: status 요청 구성 실패: %w", err)
	}
	req.Header.Set(HeaderRequestID, requestID)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, sig)

	rr, _, err := d.roundtrip(req, requestID, emptyDigest, nonce)
	if err != nil {
		return "", err
	}
	return rr.State, nil
}

// roundtrip은 한 요청을 보내고 응답 HMAC을 검증한다(R1·R2). 반환: 검증된 응답 · (오류 시) 사상된
// 3상태(dial 전 실패=UNEXECUTED · dial 후·검증 실패=UNKNOWN) · 오류. 성공 시 err=nil이며 rr이 유효다.
// nonce는 **호출자가 이 요청에 쓴 값**이다 — 응답 canonical을 이 nonce로 재구성해 검증하므로, 과거
// 응답(옛 nonce로 서명)은 검증에 실패한다(replay 방어). 응답 body의 nonce를 신뢰하지 않는다.
func (d *RemoteDispatcher) roundtrip(req *http.Request, requestID, reqDigest, nonce string) (deployResponse, deploy.RemoteState, error) {
	// dial 성공 여부를 attempt-local로 기록한다(R2) — 오류 문자열 파싱이 아니라 DialContext가
	// 연결을 반환했는지로 미실행/UNKNOWN을 가른다. 요청마다 새 client(dialed flag가 이 한 번에 결박).
	var dialed atomic.Bool
	client := conservativeClient(&dialed, d.timeout)
	resp, err := client.Do(req)
	if err != nil {
		if !dialed.Load() {
			return deployResponse{}, deploy.StateUnexecuted, fmt.Errorf("agentrpc: dial 전 실패(연결 미수립 — 미실행·부작용0): %w", err)
		}
		return deployResponse{}, deploy.StateUnknown, fmt.Errorf("agentrpc: dial 후 전송/응답 오류(요청 도달 가능 — UNKNOWN): %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	// 여기부터는 dial 성공 이후다 — 어떤 실패도 UNKNOWN이다(미실행으로 접지 않는다).
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return deployResponse{}, deploy.StateUnknown, fmt.Errorf("agentrpc: 응답 body 읽기 실패(dial 후 — UNKNOWN): %w", err)
	}

	// 응답 HMAC 검증 — canonical = requestId + 요청bodyDigest + action + httpStatus + state + **nonce**.
	// 검증 통과한 durable 상태만 신뢰한다. 서명·requestId/digest/nonce 불일치는 전부 UNKNOWN이다.
	var rr deployResponse
	if err := json.Unmarshal(respBody, &rr); err != nil {
		return deployResponse{}, deploy.StateUnknown, fmt.Errorf("agentrpc: 응답 JSON 파싱 실패(dial 후 — UNKNOWN): %w", err)
	}
	respSig := resp.Header.Get(HeaderSignature)
	canonical := ResponseCanonical(requestID, reqDigest, rr.Action, strconv.Itoa(resp.StatusCode), rr.State, nonce)
	if respSig == "" || !Verify(d.key, canonical, respSig) {
		// 서명 없음·불일치(위조·키불일치·다른 요청의 응답·status/state 변조·**과거 nonce replay**) = UNKNOWN.
		return deployResponse{}, deploy.StateUnknown, errors.New("agentrpc: 응답 HMAC 검증 실패(위조·키불일치·요청/nonce 결박 불일치 — UNKNOWN)")
	}
	// requestId 결박은 canonical에 이미 들어 있지만(불일치면 위 Verify가 실패), 방어적으로 한 번 더.
	if rr.RequestID != requestID {
		return deployResponse{}, deploy.StateUnknown, fmt.Errorf("agentrpc: 응답 requestId 불일치(기대=%q 수신=%q — UNKNOWN)", requestID, rr.RequestID)
	}
	return rr, deploy.StateUnknown, nil
}

// conservativeClient는 R2 전용 클라이언트를 만든다: proxy off·redirect 거절·keep-alive off
// (요청마다 새 연결)·DialContext 성공을 attempt-local flag에 기록. 요청마다 새 클라이언트를
// 만드는 이유는 dialed flag가 이 한 번의 시도에만 결박돼야 하기 때문이다(execute 1회).
func conservativeClient(dialed *atomic.Bool, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, // 프록시 off(환경변수 프록시 무시) — 중간자·리다이렉트 표면 제거
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				dialed.Store(true) // 연결이 반환된 순간부터 요청이 나갔을 수 있다 → 이후 실패는 UNKNOWN
			}
			return c, err
		},
		DisableKeepAlives:   true, // 요청마다 새 연결(재사용 연결의 잔여 상태 배제)
		MaxIdleConns:        0,
		MaxConnsPerHost:     1,
		TLSHandshakeTimeout: timeout,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// redirect 거절 — 위성은 리다이렉트하지 않는다. 리다이렉트 응답은 dial 후이므로 UNKNOWN이 된다.
			return errors.New("agentrpc: redirect 거절(전용 transport)")
		},
	}
}
