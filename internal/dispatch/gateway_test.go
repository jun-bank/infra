// 라우트 전환 클라이언트의 단위 테스트 — 실제 게이트웨이 대신 httptest 서버로 계약을
// 검증한다. 치명 실패는 ⑴ 전환되지 않았는데 성공으로 보고하는 것(409·5xx를 삼키는 것)과
// ⑵ 조회 실패를 슬롯 추측으로 메우는 것이다.
package dispatch

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.Handler) (*GatewayClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewGatewayClient(srv.URL, 2*time.Second)
	if err != nil {
		t.Fatalf("클라이언트 조립 실패: %v", err)
	}
	return c, srv
}

// GET은 계약 경로로 가고 activeSlot을 그대로 준다.
func TestGatewayActiveSlot(t *testing.T) {
	var gotPath, gotMethod string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"service":"core","activeSlot":"blue","uri":"http://127.0.0.1:8081","lastAcceptedToken":6}`))
	}))

	slot, err := c.ActiveSlot(context.Background())
	if err != nil || slot != "blue" {
		t.Fatalf("ActiveSlot=%q err=%v, \"blue\"·nil 기대", slot, err)
	}
	if gotMethod != http.MethodGet || gotPath != "/internal/routes/core" {
		t.Fatalf("요청 %s %s, GET /internal/routes/core 기대(계약 경로)", gotMethod, gotPath)
	}
}

// 조회가 서지 않으면 추측하지 않는다 — 비2xx·깨진 JSON·빈 activeSlot은 전부 오류다.
func TestGatewayActiveSlotFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"정상", 200, `{"activeSlot":"green"}`, false},
		{"5xx", 500, `boom`, true},
		{"404", 404, `not found`, true},
		// 200 외의 2xx는 조회 결과가 아니다 — 슬롯을 담고 있지 않은 응답을 성공으로 접으면
		// 그 다음이 슬롯 추측이 된다.
		{"202", 202, `{"activeSlot":"green"}`, true},
		{"204", 204, ``, true},
		{"깨진 JSON", 200, `{활성`, true},
		{"activeSlot 없음", 200, `{"service":"core"}`, true},
		{"빈 activeSlot", 200, `{"activeSlot":""}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			_, err := c.ActiveSlot(context.Background())
			if tc.wantErr != (err != nil) {
				t.Fatalf("%s: err=%v, wantErr=%v", tc.name, err, tc.wantErr)
			}
		})
	}
}

// 게이트웨이가 응답하지 않으면(서버 닫힘) 오류다 — 무응답을 조회 성공으로 접지 않는다.
func TestGatewayActiveSlotUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	c, err := NewGatewayClient(srv.URL, time.Second)
	if err != nil {
		t.Fatalf("클라이언트 조립 실패: %v", err)
	}
	srv.Close()
	if _, err := c.ActiveSlot(context.Background()); err == nil {
		t.Fatal("게이트웨이 미응답인데 오류가 아니다(fail-closed 위반)")
	}
}

// POST는 계약 경로·본문(targetSlot·fencingToken)으로 간다 — 토큰은 게이트웨이가 stale
// write를 거절하는 근거이므로 반드시 실려야 한다(BG-4 ⓐ).
func TestGatewaySwitchSendsContract(t *testing.T) {
	var gotPath, gotMethod, gotType string
	var gotBody switchRequest
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotType = r.URL.Path, r.Method, r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))

	if err := c.Switch(context.Background(), "green", 7); err != nil {
		t.Fatalf("전환 성공 응답인데 오류: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/internal/routes/core/switch" {
		t.Fatalf("요청 %s %s, POST /internal/routes/core/switch 기대(계약 경로)", gotMethod, gotPath)
	}
	if gotType != "application/json" {
		t.Fatalf("Content-Type=%q, application/json 기대", gotType)
	}
	if gotBody.TargetSlot != "green" || gotBody.FencingToken != 7 {
		t.Fatalf("본문 targetSlot=%q fencingToken=%d, green·7 기대", gotBody.TargetSlot, gotBody.FencingToken)
	}
}

// 409 = stale token = 미전환(소유권 상실). 호출자가 이 갈래를 구분할 수 있어야 한다 —
// errors.Is(센티널)와 구조화 필드(StaleToken·SwitchState) 양쪽으로.
func TestGatewaySwitchStaleToken(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"stale fencing token","lastAcceptedToken":9}`))
	}))
	err := c.Switch(context.Background(), "green", 7)
	if !errors.Is(err, ErrStaleFencingToken) {
		t.Fatalf("409 응답: err=%v, ErrStaleFencingToken 기대", err)
	}
	var se *SwitchError
	if !errors.As(err, &se) {
		t.Fatalf("409 응답: err=%v, *SwitchError 기대(호출자가 갈래를 구조로 읽는다)", err)
	}
	// 409는 계약상 "쓰기를 시도조차 하지 않았다" — 본문에 state가 없어도 그 보증은 상태
	// 코드가 준다.
	if !se.StaleToken() || se.SwitchState() != SwitchStateNotAttempted || se.Status != http.StatusConflict {
		t.Fatalf("409 분류: stale=%v state=%q status=%d, true·%s·409 기대", se.StaleToken(), se.SwitchState(), se.Status, SwitchStateNotAttempted)
	}
}

// 200이 아닌 응답은 전부 실패다 — 202처럼 "받아는 뒀다"를 성공으로 접으면 라우트가 안 바뀐
// 채 배포가 COMPLETED가 된다(2xx 전체를 성공으로 보던 구멍).
func TestGatewaySwitchRejectsNon200(t *testing.T) {
	for _, status := range []int{
		http.StatusAccepted, http.StatusNoContent, // 200 아닌 2xx = 전환 보증 아님
		http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusBadGateway,
	} {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		err := c.Switch(context.Background(), "green", 7)
		if err == nil {
			t.Fatalf("HTTP %d인데 전환 성공으로 접혔다", status)
		}
		if errors.Is(err, ErrStaleFencingToken) {
			t.Fatalf("HTTP %d가 stale token으로 분류됐다(409만 stale이다)", status)
		}
		// 보증이 없는 실패다 — state를 지어내면 호출자가 정리(down)를 실행한다.
		var se *SwitchError
		if !errors.As(err, &se) || se.SwitchState() != "" {
			t.Fatalf("HTTP %d: state=%q, 빈 문자열(보증 없음) 기대", status, se.SwitchState())
		}
	}
}

// 실패 응답의 state는 게이트웨이가 주는 유일한 보증이다 — 그대로 실어 나르고, 계약 밖의
// 값·깨진 본문은 "보증 없음"("")으로 접는다(모르는 값을 보증으로 승격시키지 않는다).
func TestGatewaySwitchCarriesFailureState(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"ROLLED_BACK", `{"error":"switch failed","state":"ROLLED_BACK"}`, SwitchStateRolledBack},
		{"INDETERMINATE", `{"error":"switch failed","state":"INDETERMINATE"}`, SwitchStateIndeterminate},
		{"state 없음", `{"error":"switch failed"}`, ""},
		{"계약 밖 값", `{"error":"x","state":"MAYBE"}`, ""},
		{"깨진 JSON", `{상태`, ""},
		{"빈 본문", ``, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(tc.body))
			}))
			err := c.Switch(context.Background(), "green", 7)
			var se *SwitchError
			if !errors.As(err, &se) {
				t.Fatalf("%s: err=%v, *SwitchError 기대", tc.name, err)
			}
			if se.SwitchState() != tc.want {
				t.Fatalf("%s: state=%q, %q 기대", tc.name, se.SwitchState(), tc.want)
			}
			if se.StaleToken() {
				t.Fatalf("%s: 500이 stale로 분류됐다", tc.name)
			}
		})
	}
}

// P1a: state를 신뢰하는 코드는 500뿐이다 — 계약 밖 상태 코드(202·400·502…)가 ROLLED_BACK
// body를 갖고 와도 보증으로 승격되면 안 된다. 승격되면 호출자가 그것을 근거로 idle slot을
// down하고, 라우트가 실제로 옮겨진 뒤였다면 트래픽이 가는 쪽을 끊는다(엣지·프록시 위조).
func TestGatewaySwitchTrustsStateOnlyFrom500(t *testing.T) {
	const rolledBackBody = `{"error":"switch failed","state":"ROLLED_BACK"}`
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusInternalServerError, SwitchStateRolledBack}, // 계약 안 — 보증 성립
		{http.StatusAccepted, ""},                               // 계약 밖 — 보증 없음
		{http.StatusBadRequest, ""},
		{http.StatusBadGateway, ""}, // 프록시가 만든 응답
		{http.StatusServiceUnavailable, ""},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(rolledBackBody))
			}))
			err := c.Switch(context.Background(), "green", 7)
			var se *SwitchError
			if !errors.As(err, &se) {
				t.Fatalf("HTTP %d: err=%v, *SwitchError 기대", tc.status, err)
			}
			if se.SwitchState() != tc.want {
				t.Fatalf("HTTP %d + ROLLED_BACK 본문: state=%q, %q 기대(계약상 state는 500만 싣는다)", tc.status, se.SwitchState(), tc.want)
			}
		})
	}
	// 409는 그대로다 — 상태 코드 자체가 미전환 보증이고, stale 갈래가 먼저 가져간다.
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"stale fencing token"}`))
	}))
	err := c.Switch(context.Background(), "green", 7)
	var se *SwitchError
	if !errors.As(err, &se) || !se.StaleToken() || se.SwitchState() != SwitchStateNotAttempted {
		t.Fatalf("409: err=%v, stale·NOT_ATTEMPTED 기대(기존 처리 유지)", err)
	}
}

// 전송 실패(응답 없음)는 "전환되지 않았다"를 증명하지 못한다 — 보증 없음("")으로 남겨야
// 호출자가 정리(down)를 하지 않고 사람에게 넘긴다.
func TestGatewaySwitchTransportFailureHasNoGuarantee(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	c, err := NewGatewayClient(srv.URL, time.Second)
	if err != nil {
		t.Fatalf("클라이언트 조립 실패: %v", err)
	}
	srv.Close()
	serr := c.Switch(context.Background(), "green", 7)
	var se *SwitchError
	if !errors.As(serr, &se) {
		t.Fatalf("전송 실패: err=%v, *SwitchError 기대", serr)
	}
	if se.SwitchState() != "" || se.StaleToken() || se.Status != 0 {
		t.Fatalf("전송 실패 분류: state=%q stale=%v status=%d, \"\"·false·0 기대(보증 없음)", se.SwitchState(), se.StaleToken(), se.Status)
	}
}

// fencing token은 계약상 int64 양수(≥1)다 — 범위 밖이면 요청 자체를 보내지 않는다(부작용 0).
// 직렬화 형태는 그대로다(uint64 JSON 숫자).
func TestGatewaySwitchRejectsOutOfRangeToken(t *testing.T) {
	for _, tok := range []uint64{0, uint64(math.MaxInt64) + 1, ^uint64(0)} {
		requests := 0
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests++
			w.WriteHeader(http.StatusOK)
		}))
		err := c.Switch(context.Background(), "green", tok)
		if err == nil {
			t.Fatalf("token=%d인데 통과 — 계약 범위 밖 토큰이 전송됐다", tok)
		}
		if requests != 0 {
			t.Fatalf("token=%d: 요청 %d회 전송됨, 0 기대(부작용 0)", tok, requests)
		}
	}
	// 상한 경계값(MaxInt64)은 정상 전송된다 — 유효 범위를 좁히지 않는다.
	var got switchRequest
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	if err := c.Switch(context.Background(), "green", uint64(math.MaxInt64)); err != nil {
		t.Fatalf("token=MaxInt64인데 거부: %v", err)
	}
	if got.FencingToken != uint64(math.MaxInt64) {
		t.Fatalf("직렬화된 token=%d, MaxInt64 기대(형태 불변)", got.FencingToken)
	}
}

// base URL 조립: 절대 http(s)만 받고, 끝의 슬래시는 경로를 깨뜨리지 않는다.
func TestNewGatewayClientValidatesBase(t *testing.T) {
	bad := []string{"", "127.0.0.1:8090", "/internal", "ftp://host", "gateway"}
	for _, b := range bad {
		if _, err := NewGatewayClient(b, time.Second); err == nil {
			t.Fatalf("base=%q인데 통과(fail-closed 위반)", b)
		}
	}
	if _, err := NewGatewayClient("http://127.0.0.1:8090", 0); err == nil {
		t.Fatal("timeout=0인데 통과 — 상한 없는 전환은 lease를 넘긴다")
	}
	c, err := NewGatewayClient("http://127.0.0.1:8090/", time.Second)
	if err != nil {
		t.Fatalf("정상 base인데 거부: %v", err)
	}
	if got := c.routeURL("/switch"); got != "http://127.0.0.1:8090/internal/routes/core/switch" {
		t.Fatalf("전환 URL=%q(끝 슬래시가 경로를 깨뜨렸다)", got)
	}
}
