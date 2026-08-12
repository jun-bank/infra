package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
//	                                          → 200 전환 성공
//	                                            409 stale token (미전환 — state가 있으면 NOT_ATTEMPTED)
//	                                            500 {"error","state":"ROLLED_BACK"|"INDETERMINATE"}
//	                                            그 밖(202 포함) = 실패 · 실상태 보증 없음
//
// 성공은 **정확히 200**뿐이다 — 202 같은 다른 2xx는 "받아는 뒀다"일 뿐 라우트가 옮겨졌다는
// 보증이 아니므로 성공으로 접으면 미전환이 COMPLETED로 위장한다.
//
// 실패 응답의 state는 게이트웨이가 자기 실상태에 대해 주는 유일한 보증이며, 이 클라이언트는
// 그것을 파싱해 반환 오류(*SwitchError)에 그대로 싣는다 — 호출자는 그 보증에 따라 정리(down)
// 여부를 가른다(보증 없으면 정리하지 않는다). 재조회로 이를 대신하지 않는다: GET도 registry
// 기준이라 실상태 보증이 아니다.
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

// 전환 실패 응답의 state 값(게이트웨이 계약 그대로 — 이 클라이언트는 판정하지 않고 옮긴다).
// 호출자는 이 값으로 "정리(down)해도 되는가"를 가른다: 미전환이 보증된 값에서만 정리한다.
const (
	// SwitchStateNotAttempted은 전환을 시도조차 하지 않았다는 보증이다(409 stale 포함).
	SwitchStateNotAttempted = "NOT_ATTEMPTED"
	// SwitchStateRolledBack은 전환을 시도했으나 되돌렸다는 보증이다 — 라우트는 구 slot이다.
	SwitchStateRolledBack = "ROLLED_BACK"
	// SwitchStateIndeterminate은 게이트웨이 스스로 실상태를 모른다는 뜻이다 — 보증 없음.
	SwitchStateIndeterminate = "INDETERMINATE"
)

// maxFencingToken은 요청에 실을 수 있는 fencing token의 상한이다 — 계약상 토큰은 int64
// 양수(≥1)이며, uint64의 상위 절반은 게이트웨이 쪽에서 음수로 접히거나 거절된다. 넘는
// 값은 요청을 보내기 전에 거부한다(부작용 0 — 전송했다가 애매한 실패를 만들지 않는다).
const maxFencingToken = uint64(math.MaxInt64)

// SwitchError는 ⑤ 라우트 전환 실패의 구조화 오류다. 호출자가 문자열을 뒤지지 않고
// "게이트웨이가 무엇을 보증했는가"를 읽을 수 있어야 정리(down) 여부를 안전하게 가른다:
//
//   - Stale(409)      → 이 실행자는 소유권을 잃었다. 승자의 슬롯을 건드리면 안 된다.
//   - State=ROLLED_BACK → 미전환이 보증됐다. 올린 slot을 정리해 net-0으로 되돌려도 된다.
//   - 그 밖(INDETERMINATE·전송 실패·파싱 불가) → 실상태 불명. 정리는 금지(사람이 본다).
//
// SwitchState()·StaleToken() 메서드는 소비 지점(internal/deploy)이 이 패키지를 import하지
// 않고도 갈래를 읽게 하는 구조적 계약이다(IA-5 닫힌 import).
type SwitchError struct {
	Msg    string // 사람이 읽는 전체 메시지(단계·상태·본문 조각 포함)
	Status int    // HTTP 상태 코드(0 = 응답을 받지 못했다 — 전송 실패·타임아웃)
	State  string // 실패 응답의 state("" = 없음·파싱 불가 = 보증 없음)
	Stale  bool   // true = 409 fencing token 거절(소유권 상실)
	Err    error  // 감싼 원인(전송 오류 · stale 센티널)
}

func (e *SwitchError) Error() string { return e.Msg }

// Unwrap은 errors.Is(err, ErrStaleFencingToken)·전송 오류 매칭을 보존한다.
func (e *SwitchError) Unwrap() error { return e.Err }

// SwitchState는 게이트웨이가 보증한 실상태다(빈 문자열 = 보증 없음).
func (e *SwitchError) SwitchState() string { return e.State }

// StaleToken은 이 실패가 fencing token 거절(409 — 소유권 상실)인지다.
func (e *SwitchError) StaleToken() bool { return e.Stale }

// switchFailureBody는 실패 응답 본문이다(게이트웨이 계약 — 500은 state를 싣는다).
type switchFailureBody struct {
	Error string `json:"error"`
	State string `json:"state"`
}

// parseSwitchState는 실패 응답 본문에서 state를 읽는다. 파싱 불가·필드 부재·계약 밖의
// 값은 전부 ""(보증 없음)다 — 모르는 값을 보증으로 승격시키지 않는다(fail-closed).
func parseSwitchState(body []byte) string {
	var b switchFailureBody
	if err := json.Unmarshal(body, &b); err != nil {
		return ""
	}
	switch b.State {
	case SwitchStateNotAttempted, SwitchStateRolledBack, SwitchStateIndeterminate:
		return b.State
	default:
		return ""
	}
}

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

// ActiveSlot은 지금 트래픽을 받는 슬롯을 조회한다(부작용 없는 GET). 200이 아닌 응답·파싱
// 불가·빈 activeSlot은 오류다 — 조회를 못 했는데 슬롯을 추측하면 살아 있는 쪽에 배포하게
// 된다. 성공은 정확히 200뿐이다: 202·204 같은 다른 2xx는 조회 결과를 담고 있지 않다.
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
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dispatch: 라우트 조회 실패 — HTTP %d(200만 성공이다) · 본문=%s", resp.StatusCode, snippet(body))
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

// Switch는 라우트를 targetSlot으로 옮긴다(CD-4 ⑤). 200 = 전환 성공, 그 밖은 전부 실패이며
// 실패는 *SwitchError로 돌아온다 — 그 안의 Stale·State가 호출자의 정리(down) 판단 근거다.
//
//	409          → Stale=true(소유권 상실 · 미전환) · errors.Is(err, ErrStaleFencingToken)
//	500 + state  → State=ROLLED_BACK(미전환 보증) 또는 INDETERMINATE(보증 없음)
//	그 밖·전송 실패 → State=""(보증 없음)
//
// ⚠️ 전송 실패(타임아웃·연결 끊김)는 "전환되지 않았다"를 증명하지 못한다 — 요청이 닿아
// 처리됐는데 응답만 유실됐을 수 있다. 그래서 이 클라이언트는 그런 실패에 아무 보증도 싣지
// 않으며(State=""), 호출자는 보증 없는 실패에서 정리하지 않고 UNKNOWN으로 접는다.
func (g *GatewayClient) Switch(ctx context.Context, targetSlot string, fencingToken uint64) error {
	// 계약 위반 토큰은 보내기 전에 거른다(부작용 0 — 전송 후 애매한 실패를 만들지 않는다).
	if fencingToken == 0 || fencingToken > maxFencingToken {
		return &SwitchError{
			Msg:   fmt.Sprintf("dispatch: fencing token이 계약 범위를 벗어났다(1..%d의 int64 양수여야 한다 · 요청 미전송 · 부작용 0): token=%d", maxFencingToken, fencingToken),
			State: SwitchStateNotAttempted,
		}
	}
	payload, err := json.Marshal(switchRequest{TargetSlot: targetSlot, FencingToken: fencingToken})
	if err != nil {
		return &SwitchError{Msg: fmt.Sprintf("dispatch: 전환 요청 본문 조립 실패(요청 미전송): %v", err), State: SwitchStateNotAttempted, Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.routeURL("/switch"), bytes.NewReader(payload))
	if err != nil {
		return &SwitchError{Msg: fmt.Sprintf("dispatch: 전환 요청 조립 실패(요청 미전송): %v", err), State: SwitchStateNotAttempted, Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.http.Do(req)
	if err != nil {
		// 응답을 받지 못했다 = 실상태 보증 없음(State 비움) — 요청이 닿았을 수 있다.
		return &SwitchError{
			Msg: fmt.Sprintf("dispatch: 전환 요청 실패(게이트웨이 미응답 — 전환 여부 불명 · 보증 없음): %v", err),
			Err: err,
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxGatewayBody))
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusConflict:
		// 409는 계약상 "쓰기를 시도조차 하지 않았다"이다 — 본문에 state가 없어도 그 보증은
		// 상태 코드가 준다. 다만 호출자는 stale에서 정리를 하지 않는다(승자의 슬롯이다).
		state := parseSwitchState(body)
		if state == "" {
			state = SwitchStateNotAttempted
		}
		return &SwitchError{
			Msg:    fmt.Sprintf("%v (slot=%s token=%d · state=%s · 본문=%s)", ErrStaleFencingToken, targetSlot, fencingToken, state, snippet(body)),
			Status: resp.StatusCode,
			State:  state,
			Stale:  true,
			Err:    ErrStaleFencingToken,
		}
	default:
		state := parseSwitchState(body)
		return &SwitchError{
			Msg:    fmt.Sprintf("dispatch: 전환 거절 — HTTP %d(200만 성공이다) (slot=%s token=%d · state=%q · 본문=%s)", resp.StatusCode, targetSlot, fencingToken, state, snippet(body)),
			Status: resp.StatusCode,
			State:  state,
		}
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
