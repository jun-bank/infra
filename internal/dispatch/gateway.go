package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 라우트 전환 클라이언트(CD-4 ⑤) — 블루-그린 전환 수단은 내부 게이트웨이(SCG)의 라우트
// 전환이다(ADR-031 BG-1). 이 파일은 그 게이트웨이가 노출하는 두 엔드포인트를 감싼다:
// 현재 라우트 조회(GET · 부작용 0)와 슬롯 전환(POST · 불가역 단계).
//
// 계약(게이트웨이 쪽이 정본 — 이 코드는 재해석하지 않는다):
//
//	GET  {base}/internal/routes/core         → 200 {"service","activeSlot","uri","lastAcceptedToken"}
//	POST {base}/internal/routes/core/switch  ← {"targetSlot":"green","fencingToken":7}
//	                                          → 200 전환 성공 / 409 stale token / 그 밖 = 실패
//
// fencingToken을 요청에 싣는 이유는 BG-4 ⓐ다 — 락 재확인과 라우트 write 사이의 창에서
// lease를 잃은 stale 실행자의 write가 최종 라우트로 남지 않도록, 게이트웨이(sink)가
// 토큰을 검증해 낡은 요청을 409로 거절한다. 즉 이 클라이언트는 토큰을 "전달"할 뿐
// 판정하지 않는다 — 판정 주체는 게이트웨이다.
//
// ⚠️ [구현 검증] BG-5/IV-44: 게이트웨이가 이 갱신을 무중단으로·원자적으로 해내는지는
// 실물 접촉에서 판정한다. 계약(검증된 slot으로 원자 전환)은 고정, 수단은 미확정이다.

// routeService는 이 게이트웨이가 소유한 블루-그린 라우트의 서비스 이름이다. 경로가
// 계약으로 고정돼 있어 설정에서 받지 않는다 — 사람 채널 앞단의 코어 라우트 하나다
// (전문·배치는 게이트웨이를 지나지 않는다 — BG-3 ⑴).
const routeService = "core"

// ErrStaleFencingToken은 게이트웨이가 409로 거절했을 때다 — 이 실행자의 fencing token이
// 게이트웨이가 이미 받아들인 토큰보다 낡았다(다른 배포가 락을 가져갔다). 전환은 일어나지
// 않았으므로 호출자는 미전환으로 접는다(CD-4 ⑤ 실패 전이).
var ErrStaleFencingToken = errors.New("dispatch: 게이트웨이가 fencing token을 거절했다(409 stale) — 라우트 미전환")

// GatewayClient는 게이트웨이 라우트 API의 HTTP 클라이언트다. deploy.SlotGateway를
// 만족한다(ActiveSlot·Switch).
type GatewayClient struct {
	base *url.URL
	http httpDoer
}

// routeState는 GET 응답이다(게이트웨이 계약 그대로).
type routeState struct {
	Service           string `json:"service"`
	ActiveSlot        string `json:"activeSlot"`
	URI               string `json:"uri"`
	LastAcceptedToken uint64 `json:"lastAcceptedToken"`
}

// switchRequest는 POST 본문이다(게이트웨이 계약 그대로).
type switchRequest struct {
	TargetSlot   string `json:"targetSlot"`
	FencingToken uint64 `json:"fencingToken"`
}

// NewGatewayClient는 base URL(예: http://127.0.0.1:8090)로 클라이언트를 만든다. timeout은
// 각 요청의 상한이며 lease 하한식의 입력이다(전환 단계가 무한정 늘어지면 락이 만료된다).
// base가 절대 http(s) URL이 아니거나 timeout이 0 이하면 조립 시점에 거부한다(fail-closed).
func NewGatewayClient(base string, timeout time.Duration) (*GatewayClient, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("dispatch: 게이트웨이 요청 타임아웃은 >0 이어야 한다: %s", timeout)
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return nil, fmt.Errorf("dispatch: 게이트웨이 URL 파싱 불가 %q: %w", base, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("dispatch: 게이트웨이 URL은 절대 http(s) URL이어야 한다: %q", base)
	}
	return &GatewayClient{base: u, http: &http.Client{Timeout: timeout}}, nil
}

// routeURL은 라우트 엔드포인트 URL을 만든다(suffix는 "" 또는 "/switch").
func (g *GatewayClient) routeURL(suffix string) string {
	return g.base.String() + "/internal/routes/" + routeService + suffix
}

// ActiveSlot은 지금 트래픽을 받는 슬롯을 조회한다(부작용 없는 GET). 비2xx·파싱 불가·빈
// activeSlot은 오류다 — 조회를 못 했는데 슬롯을 추측하면 살아 있는 쪽에 배포하게 된다.
func (g *GatewayClient) ActiveSlot(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.routeURL(""), nil)
	if err != nil {
		return "", fmt.Errorf("dispatch: 라우트 조회 요청 조립 실패: %w", err)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("dispatch: 라우트 조회 실패(게이트웨이 미응답): %w", err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxGatewayBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("dispatch: 라우트 조회 실패 — HTTP %d · 본문=%s", resp.StatusCode, snippet(body))
	}
	if rerr != nil {
		return "", fmt.Errorf("dispatch: 라우트 조회 본문 읽기 실패: %w", rerr)
	}
	var st routeState
	if err := json.Unmarshal(body, &st); err != nil {
		return "", fmt.Errorf("dispatch: 라우트 조회 응답 파싱 불가(본문=%s): %w", snippet(body), err)
	}
	if st.ActiveSlot == "" {
		return "", fmt.Errorf("dispatch: 라우트 조회 응답에 activeSlot이 없다(본문=%s)", snippet(body))
	}
	return st.ActiveSlot, nil
}

// Switch는 라우트를 targetSlot으로 옮긴다(CD-4 ⑤). 2xx = 전환 성공, 409 =
// ErrStaleFencingToken(미전환), 그 밖의 응답·전송 실패 = 오류(미전환으로 접는다).
// ⚠️ 전송 실패(타임아웃·연결 끊김)는 "전환되지 않았다"를 증명하지 못한다 — 요청이 닿아
// 처리됐는데 응답만 유실됐을 수 있다. 호출자는 이 오류에서 green을 정리해 미전환으로
// 되돌리며(CD-4 ⑤ 전이), 그 정리 자체가 라우트가 옮겨진 뒤였다면 헬스가 죽은 대상을
// 가리키게 된다 — 그래서 정리 실패·불명은 UNKNOWN으로 접히고 사람이 본다.
func (g *GatewayClient) Switch(ctx context.Context, targetSlot string, fencingToken uint64) error {
	payload, err := json.Marshal(switchRequest{TargetSlot: targetSlot, FencingToken: fencingToken})
	if err != nil {
		return fmt.Errorf("dispatch: 전환 요청 본문 조립 실패: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.routeURL("/switch"), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("dispatch: 전환 요청 조립 실패: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.http.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch: 전환 요청 실패(게이트웨이 미응답 — 전환 여부 불명): %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxGatewayBody))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusConflict:
		return fmt.Errorf("%w (slot=%s token=%d · 본문=%s)", ErrStaleFencingToken, targetSlot, fencingToken, snippet(body))
	default:
		return fmt.Errorf("dispatch: 전환 거절 — HTTP %d (slot=%s token=%d · 본문=%s)", resp.StatusCode, targetSlot, fencingToken, snippet(body))
	}
}

// maxGatewayBody는 게이트웨이 응답 본문을 읽는 상한이다 — 오작동·악성 응답이 메모리를
// 끌어올리지 못하게 한다(오류 메시지에 쓰는 용도라 이 정도면 충분하다).
const maxGatewayBody = 8 << 10

// snippet은 오류 메시지에 실을 본문 조각이다(길면 자른다 · 개행은 공백으로).
func snippet(b []byte) string {
	s := strings.TrimSpace(strings.ReplaceAll(string(b), "\n", " "))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
