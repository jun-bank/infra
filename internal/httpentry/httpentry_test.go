// httpentry 진입 층의 전송 수준 계약을 다루는 단위 테스트.
// 실제 판정(서명·OIDC)은 아직 없으므로, 여기서 검증하는 것은 라우팅과 전송 제한이다:
//   - 배포 엔드포인트는 POST만 받고 그 외 method는 405로 거절한다(DO-15 ⑴).
//   - 본문이 상한을 넘으면 413으로 거절한다(DO-15 ⑵).
//   - 상한 안의 POST는 미들웨어 체인을 통과해 종단 핸들러에 도달한다(지금은 501).
package httpentry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testConfig는 리스너를 열지 않는 인메모리 핸들러용 설정이다(주소는 쓰이지 않는다).
func testConfig(maxBody int64) Config {
	return Config{ListenAddr: "127.0.0.1:0", MaxBodyBytes: maxBody}
}

// TestNonPostRejected405는 배포 엔드포인트가 POST 아닌 method를 405로 거절하고
// Allow 헤더에 POST를 알리는지 확인한다(DO-15 ⑴ · Go 1.22+ 메서드 라우팅).
func TestNonPostRejected405(t *testing.T) {
	h := NewHandler(testConfig(DefaultMaxBodyBytes))

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/deploy", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /deploy: 코드 = %d, 기대 = 405", method, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); !strings.Contains(allow, http.MethodPost) {
			t.Errorf("%s /deploy: Allow 헤더 = %q, POST 포함 기대", method, allow)
		}
	}
}

// TestBodyOverLimitRejected413은 본문이 상한을 넘으면 413으로 거절하는지 확인한다
// (DO-15 ⑵). 상한을 작게(16바이트) 두고 그보다 큰 본문을 보낸다.
func TestBodyOverLimitRejected413(t *testing.T) {
	const limit = 16
	h := NewHandler(testConfig(limit))

	body := strings.NewReader(strings.Repeat("A", limit+1))
	req := httptest.NewRequest(http.MethodPost, "/deploy", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("상한 초과 본문: 코드 = %d, 기대 = 413", rec.Code)
	}
}

// TestBodyWithinLimitReachesReceiver는 상한 안의 POST가 미들웨어 체인을 통과해
// 종단 핸들러에 도달하는지 확인한다. 실제 처리는 아직 미구현이므로 501이 온다 —
// 405도 413도 아니라는 점이 라우팅·전송 제한을 통과했음을 증명한다.
func TestBodyWithinLimitReachesReceiver(t *testing.T) {
	const limit = 1024
	h := NewHandler(testConfig(limit))

	body := strings.NewReader(strings.Repeat("A", limit/2))
	req := httptest.NewRequest(http.MethodPost, "/deploy", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("상한 안 본문: 코드 = %d, 기대 = 501 (종단 핸들러 도달)", rec.Code)
	}
}

// TestLoadConfig는 fail-closed 설정 로딩을 다룬다: 주소가 없으면 오류, 잘못된 상한이면
// 오류, 상한 미지정이면 기본값을 쓴다.
func TestLoadConfig(t *testing.T) {
	t.Run("주소 없으면 오류", func(t *testing.T) {
		t.Setenv("AGENT_LISTEN_ADDR", "")
		if _, err := LoadConfig(); err == nil {
			t.Error("AGENT_LISTEN_ADDR 없이 LoadConfig가 성공했다 (fail-closed 기대)")
		}
	})

	t.Run("상한 미지정이면 기본값", func(t *testing.T) {
		t.Setenv("AGENT_LISTEN_ADDR", "127.0.0.1:0")
		t.Setenv("AGENT_MAX_BODY_BYTES", "")
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig 오류: %v", err)
		}
		if cfg.MaxBodyBytes != DefaultMaxBodyBytes {
			t.Errorf("MaxBodyBytes = %d, 기대 = %d (기본값)", cfg.MaxBodyBytes, DefaultMaxBodyBytes)
		}
	})

	t.Run("잘못된 상한이면 오류", func(t *testing.T) {
		t.Setenv("AGENT_LISTEN_ADDR", "127.0.0.1:0")
		t.Setenv("AGENT_MAX_BODY_BYTES", "-1")
		if _, err := LoadConfig(); err == nil {
			t.Error("음수 상한으로 LoadConfig가 성공했다 (fail-closed 기대)")
		}
	})
}
