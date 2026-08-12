// 라우트 전환 클라이언트의 단위 테스트 — 실제 게이트웨이 대신 httptest 서버로 계약을
// 검증한다. 치명 실패는 ⑴ 전환되지 않았는데 성공으로 보고하는 것(409·5xx를 삼키는 것)과
// ⑵ 조회 실패를 슬롯 추측으로 메우는 것이다.
package dispatch

import (
	"context"
	"encoding/json"
	"errors"
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

// 409 = stale token = 미전환. 호출자가 이 갈래를 구분할 수 있어야 한다(errors.Is).
func TestGatewaySwitchStaleToken(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"stale fencing token","lastAcceptedToken":9}`))
	}))
	err := c.Switch(context.Background(), "green", 7)
	if !errors.Is(err, ErrStaleFencingToken) {
		t.Fatalf("409 응답: err=%v, ErrStaleFencingToken 기대", err)
	}
}

// 4xx·5xx는 전부 실패다 — 조용히 성공으로 접으면 라우트가 안 바뀐 채 배포가 COMPLETED가 된다.
func TestGatewaySwitchRejectsNon2xx(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusBadGateway} {
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
