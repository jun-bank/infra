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
// execute 정확히 1회다: UNKNOWN이면 그대로 반환하고 **자동 status 조회·재개를 하지 않는다**
// (조각 C). coordinator의 기존 UNKNOWN 경로(락 유지·사람)가 받는다.
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

// Dispatch는 검증된 manifest를 위성에 원격 실행하고 3상태를 만든다(DO-16). 미실행/UNKNOWN
// 경계는 보수적이다(R2): dial **전** 실패만 미실행(부작용 0 증명), dial **후** 모든 오류는
// UNKNOWN이다(요청이 도달했을 수 있다 — 실패로 접으면 중복 배포).
func (d *RemoteDispatcher) Dispatch(ctx context.Context, m deploy.Manifest, token store.FencingToken) (deploy.RemoteState, error) {
	// 1. 로컬 요청 구성(부작용 0 · dial 전) — 실패는 미실행이다(요청 바이트가 나가지 않았다).
	mb, err := json.Marshal(m)
	if err != nil {
		return deploy.StateUnexecuted, fmt.Errorf("agentrpc: manifest marshal 실패(미실행·부작용0): %w", err)
	}
	body, err := json.Marshal(deployRequest{Manifest: mb, FencingToken: uint64(token)})
	if err != nil {
		return deploy.StateUnexecuted, fmt.Errorf("agentrpc: 요청 body marshal 실패(미실행·부작용0): %w", err)
	}
	requestID := m.RequestID
	ts := strconv.FormatInt(d.now().Unix(), 10)
	reqDigest := BodyDigest(body)
	sig := Sign(d.key, RequestCanonical(http.MethodPost, PathDeploy, reqDigest, requestID, ts))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+PathDeploy, bytes.NewReader(body))
	if err != nil {
		return deploy.StateUnexecuted, fmt.Errorf("agentrpc: 요청 구성 실패(미실행·부작용0): %w", err)
	}
	req.Header.Set(HeaderRequestID, requestID)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, sig)
	req.Header.Set("Content-Type", "application/json")

	// 2. 전송. dial 성공 여부를 attempt-local로 기록한다(R2) — 오류 문자열 파싱이 아니라
	//    DialContext가 연결을 반환했는지로 미실행/UNKNOWN을 가른다.
	var dialed atomic.Bool
	client := conservativeClient(&dialed, d.timeout)
	resp, err := client.Do(req)
	if err != nil {
		if !dialed.Load() {
			// dial 전 실패(DNS·connect refused·connect timeout) = 요청이 나가지 않았다 = 미실행.
			return deploy.StateUnexecuted, fmt.Errorf("agentrpc: dial 전 실패(연결 미수립 — 미실행·부작용0): %w", err)
		}
		// dial 후 실패(RST·write·응답 header/body 단절·ctx timeout·redirect) = 요청 도달 가능 = UNKNOWN.
		return deploy.StateUnknown, fmt.Errorf("agentrpc: dial 후 전송/응답 오류(요청 도달 가능 — UNKNOWN): %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	// 여기부터는 dial 성공 이후다 — 어떤 실패도 UNKNOWN이다(미실행으로 접지 않는다).
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return deploy.StateUnknown, fmt.Errorf("agentrpc: 응답 body 읽기 실패(dial 후 — UNKNOWN): %w", err)
	}

	// 3. 응답 HMAC 검증(R1) — canonical = requestId + **요청** bodyDigest + action + httpStatus + state.
	//    검증 통과한 durable 상태만 신뢰한다. 서명·requestId/digest 불일치는 전부 UNKNOWN이다.
	var rr deployResponse
	if err := json.Unmarshal(respBody, &rr); err != nil {
		return deploy.StateUnknown, fmt.Errorf("agentrpc: 응답 JSON 파싱 실패(dial 후 — UNKNOWN): %w", err)
	}
	respSig := resp.Header.Get(HeaderSignature)
	canonical := ResponseCanonical(requestID, reqDigest, rr.Action, strconv.Itoa(resp.StatusCode), rr.State)
	if respSig == "" || !Verify(d.key, canonical, respSig) {
		// 응답 서명 없음·불일치(위조·키불일치·다른 요청의 응답·status/state 변조) = UNKNOWN(R1·R2).
		return deploy.StateUnknown, errors.New("agentrpc: 응답 HMAC 검증 실패(위조·키불일치·요청 결박 불일치 — UNKNOWN)")
	}
	// requestId 결박은 canonical에 이미 들어 있지만(불일치면 위 Verify가 실패), 방어적으로 한 번 더.
	if rr.RequestID != requestID {
		return deploy.StateUnknown, fmt.Errorf("agentrpc: 응답 requestId 불일치(기대=%q 수신=%q — UNKNOWN)", requestID, rr.RequestID)
	}

	// 4. 인증된 durable 상태를 3상태로 사상. UNKNOWN이면 그대로 반환한다 — 자동 조회·재개 없음(조각 C).
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
