package agentrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
)

// maxFenceResponseBytes는 fence 응답 body 상한이다 — 서명된 작은 JSON이므로 넉넉하되 무한
// 읽기를 막는다(악의적/오작동 main의 메모리 고갈 방지).
const maxFenceResponseBytes = 1 << 16

// FenceClient는 위성 측 역방향 실행자다 — 각 mutation 직전에 main의 `/fence/confirm`으로
// "이 token·holder의 lease가 아직 살아있나?"를 서명해 묻고, main의 서명 응답을 검증해
// HELD/deny를 만든다(infra#37 조각 B · B1 · G-1). 위성엔 .9 배포 DB가 없으므로(DT-10) 이
// 역방향 RPC가 유일한 확인 경로다.
//
// Confirm은 fail-closed다: 전송 실패·응답 서명 불일치·confirmId 불일치·verdict≠HELD는 전부
// 오류(deny)로 접힌다 — main이 서명한 HELD가 검증까지 통과했을 때에만 nil(진행 허가)이다.
type FenceClient struct {
	baseURL string        // main fence base URL(예: http://10.0.0.9:9443) — 경로는 붙이지 않은 채 보관
	key     []byte        // 위성별 개별 키(cfg.Key와 같은 키 — G-1 위성별 키 재사용)
	timeout time.Duration // 확인 한 번의 상한(부모 Up/Down deadline 잔여 안에 들도록 sizing — G-6)
	now     func() time.Time
}

// NewFenceClient는 역방향 확인 클라이언트를 만든다. URL·키·timeout을 검증한다(fail-closed):
// 키 공백 불가, URL은 http/https absolute, timeout 양수.
func NewFenceClient(rawURL string, key []byte, timeout time.Duration) (*FenceClient, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("agentrpc: fence-confirm URL이 http(s) absolute가 아니다(fail-closed): %q", rawURL)
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("agentrpc: fence-confirm timeout은 >0 이어야 한다(fail-closed): %s", timeout)
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &FenceClient{baseURL: strings.TrimRight(rawURL, "/"), key: k, timeout: timeout, now: time.Now}, nil
}

// Confirm은 한 mutation의 fence 확인을 왕복한다(G-1). 매 호출마다 CSPRNG confirmId를 새로
// 만들어 요청을 결박하므로, 과거 HELD 응답은 이 확인에 재사용될 수 없다(replay 무효).
// nil이면 mutation 진행 허가(HELD 검증 통과), 오류면 deny다(호출자 GuardSession이 영구 고정).
//
// ctx는 부모 Up/Down이 넘긴 것이다 — 그 deadline이 남은 예산의 상한이고, 여기에 클라이언트
// 자체 timeout을 겹쳐 **둘 중 먼저 만료되는 쪽**으로 상한한다(G-6 — fence RPC가 부모 잔여를
// 넘지 않게). 늦은 응답은 ctx timeout으로 deny가 되고, sticky guard가 이후 mutation을 막는다.
func (c *FenceClient) Confirm(ctx context.Context, target deploy.Target, requestID string, token uint64) error {
	confirmID, err := newConfirmID()
	if err != nil {
		return err // CSPRNG 실패 = fail-closed deny(약한 nonce로 진행하지 않는다)
	}
	issuedAt := c.now().Unix()
	ts := strconv.FormatInt(issuedAt, 10)

	body, err := json.Marshal(fenceRequest{
		Target:    string(target),
		RequestID: requestID,
		Token:     token,
		ConfirmID: confirmID,
		IssuedAt:  issuedAt,
	})
	if err != nil {
		return fmt.Errorf("agentrpc: fence 요청 marshal 실패(deny): %w", err)
	}
	reqDigest := BodyDigest(body)
	sig := Sign(c.key, FenceRequestCanonicalV1(string(target), requestID, token, confirmID, issuedAt))

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.baseURL+PathFenceConfirm, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("agentrpc: fence 요청 구성 실패(deny): %w", err)
	}
	req.Header.Set(HeaderRequestID, requestID)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, sig)
	req.Header.Set("Content-Type", "application/json")

	// 프록시 off·redirect 거절·keep-alive off — deploy RemoteDispatcher와 같은 보수 전송(중간자·
	// 리다이렉트 표면 제거). fence 확인은 도달 여부로 미실행/UNKNOWN을 가르지 않으므로(어느 실패든
	// deny), dialed 추적은 필요 없다.
	client := &http.Client{
		Timeout: c.timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DisableKeepAlives:   true,
			MaxIdleConns:        0,
			MaxConnsPerHost:     1,
			TLSHandshakeTimeout: c.timeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("agentrpc: fence redirect 거절")
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("agentrpc: fence-confirm 전송 실패(deny · fail-closed): %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxFenceResponseBytes))
	if err != nil {
		return fmt.Errorf("agentrpc: fence 응답 읽기 실패(deny): %w", err)
	}
	var rr fenceResponse
	if err := json.Unmarshal(respBody, &rr); err != nil {
		return fmt.Errorf("agentrpc: fence 응답 파싱 실패(deny): %w", err)
	}

	// 서명 검증(G-1) — canonical = 도메인 + **요청**bodyDigest + confirmId + verdict. 통과한
	// HELD만 신뢰한다. 서명 없음·불일치는 전부 deny다.
	respSig := resp.Header.Get(HeaderSignature)
	canonical := FenceResponseCanonicalV1(reqDigest, confirmID, rr.Verdict)
	if respSig == "" || !Verify(c.key, canonical, respSig) {
		return errors.New("agentrpc: fence 응답 서명 검증 실패(위조·키불일치·confirmId/digest 불일치 — deny)")
	}
	// confirmId 결박은 canonical에 이미 들어 있지만(불일치면 위 Verify 실패), 방어적으로 한 번 더 —
	// 과거 확인의 응답이 현재 confirmId로 위장해 끼어드는 것을 명시적으로 거른다.
	if rr.ConfirmID != confirmID {
		return fmt.Errorf("agentrpc: fence 응답 confirmId 불일치(기대=%s 수신=%s — replay 방어 deny)", confirmID, rr.ConfirmID)
	}
	if rr.Verdict != FenceVerdictHeld {
		// STALE(만료·인계·holder/token 불일치) 또는 판정 불가 — mutation 금지.
		return fmt.Errorf("agentrpc: fence 판정이 HELD가 아니다(verdict=%q · lease 상실·확인 실패 — mutation 금지): %s", rr.Verdict, rr.Detail)
	}
	return nil // HELD 검증 통과 — 이 mutation 진행 허가
}
