// Package httpentry는 deploy-agent의 HTTP 진입 층이다 — agent 두 층 중 ⑴번
// (ADR-029 IA-4 ⑴: HTTP 진입 미들웨어 = Go http.Handler 체인). 여기서는 요청을
// 받아 전송 수준 제한(method·body 크기)을 강제하고, 서명·검증·멱등을 끼울 미들웨어
// 체인의 뼈대만 세운다. 실제 판정(서명·OIDC)과 오케스트레이션은 이 층 밖이다.
//
// 계약 출처(정본 — 이 코드는 이를 재해석하지 않는다):
//   - ADR-027 DO-1   (외부 진입은 엔드포인트 하나 — 엣지가 전달, agent가 수신;
//     조회·토글 경로는 이 표면에 없다 — CI 수신 전용)
//   - ADR-027 DO-15  (deploy 전용 제한: method=POST 한정 ⑴, body 크기 상한 ⑵,
//     forwarded 값 불신 ⑹, 출발지 제한 ⑺ — 값 전부 [구현 검증])
//   - ADR-029 IA-4 ⑴ (HTTP 진입 미들웨어는 http.Handler 체인 · 오케스트레이션과 분리)
//   - ADR-029 IA-5   (Go 관용구 — 평평한 패키지·소비 지점 인터페이스, 클린 4겹 이식 금지)
//
// IA-4 ⑵의 상태 있는 오케스트레이션(락·트랜잭션 경계)은 internal/deploy가 소유한다;
// 미들웨어의 선형성이 그 경계를 가리지 않도록 두 층을 분리한다.
package httpentry

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
)

// DefaultMaxBodyBytes는 AGENT_MAX_BODY_BYTES가 없을 때 쓰는 배포 요청 본문 상한이다.
// ⚠️ 이 값은 [구현 검증]이다(DO-15 ⑵) — 정상 배포 요청 1건이 걸리지 않으면서
// flood를 자르는 실측 값은 엣지 제한과 함께 정해진다. 여기 상수는 안전한 기본값일
// 뿐이며 시크릿·사설 정보가 아니다(env로 덮어쓴다).
const DefaultMaxBodyBytes int64 = 64 << 10 // 64 KiB

// Config는 진입 층의 전송 수준 설정이다. 주소·상한은 전부 환경에서 온다(포트·주소
// 하드코딩 금지 — .env.example 참조).
type Config struct {
	// ListenAddr는 리스너 바인딩 주소다(LAN 측 — DO-15 ⑺). 구체 값은 .env에만 있다.
	ListenAddr string
	// MaxBodyBytes는 배포 요청 본문의 바이트 상한이다(DO-15 ⑵ · [구현 검증]).
	MaxBodyBytes int64
}

// LoadConfig는 환경에서 진입 층 설정을 읽는다. 필수 값이 없으면 오류를 반환해
// 기동을 막는다(fail-closed — 주소 없이 리스너를 열지 않는다).
func LoadConfig() (Config, error) {
	addr := os.Getenv("AGENT_LISTEN_ADDR")
	if addr == "" {
		return Config{}, errors.New("AGENT_LISTEN_ADDR 미설정 (리스너 주소는 .env에서 온다)")
	}

	maxBody := DefaultMaxBodyBytes
	if raw := os.Getenv("AGENT_MAX_BODY_BYTES"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			return Config{}, errors.New("AGENT_MAX_BODY_BYTES 값이 올바르지 않다 (양의 정수여야 한다)")
		}
		maxBody = n
	}

	return Config{ListenAddr: addr, MaxBodyBytes: maxBody}, nil
}

// middleware는 하나의 http.Handler를 감싸 다음 핸들러로 잇는 함수다. 체인의 각 고리가
// 이 형태이며, 순서 자체가 계약이다(전송 제한 → 인증 → 검증 → 멱등 → 수신).
type middleware func(http.Handler) http.Handler

// chain은 미들웨어들을 등록 순서대로 요청이 통과하도록 h를 감싼다. 앞에 적은 것이
// 바깥(먼저 실행)이 되도록 역순으로 두른다.
func chain(h http.Handler, mws ...middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// NewHandler는 진입 층의 라우터를 만든다. 배포 요청 수신 엔드포인트 하나만 등록하며
// (DO-1: CI 수신 전용), method 패턴 "POST /deploy"로 그 외 method는 ServeMux가
// 405 + Allow 헤더로 자동 거절한다(Go 1.22+ 메서드 라우팅 — DO-15 ⑴).
func NewHandler(cfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /deploy", chain(
		deployReceiver(),
		withBodyLimit(cfg.MaxBodyBytes), // 전송 제한(DO-15 ⑵) — 바깥에서 body를 캡
		withAuth,                        // 게이트 1 슬롯(통과 스텁) — DO-2·DO-10·DO-11
		withValidate,                    // 요청 형태 검증 슬롯(통과 스텁)
		withIdempotency,                 // requestId 멱등 슬롯(통과 스텁) — DO-10 ⑶⑷
	))
	return mux
}

// withBodyLimit은 요청 본문을 상한 바이트로 감싼다(DO-15 ⑵). 상한을 넘으면 body를
// 읽는 하류에서 *http.MaxBytesError가 나며, 수신 핸들러가 413으로 거절한다.
func withBodyLimit(max int64) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}

// withAuth는 게이트 1(HMAC 서명·신선도·OIDC 클레임 매트릭스)이 들어갈 자리다.
// 지금은 아무 판정도 하지 않고 통과시키는 스텁이다.
//
// TODO(DO-2·DO-10·DO-11, S1-2/S1-3): internal/auth.Verifier를 여기서 호출하고,
// 실패하면 거절 사유를 기록(RL-8)한 뒤 차단한다 — 통과시키지 않는다(fail-closed).
func withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// withValidate는 요청 형태(필수 헤더·manifest 구조)를 검증할 자리다. 지금은 통과 스텁.
//
// TODO: 서명 범위 밖의 값은 판정에 쓰지 않는다(DO-10 ⑴) · forwarded 헤더 불신(DO-15 ⑹).
func withValidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// withIdempotency는 requestId 멱등 단락이 들어갈 자리다. 지금은 통과 스텁.
//
// TODO(DO-10 ⑶⑷): requestId/jti 예약은 internal/store가 소유하는 지속 부작용으로,
// 락 획득과 같은 트랜잭션에서 일어난다(IA-4 ⑵). 이 슬롯은 그 예약 결과를 읽어 재생을
// 조기 단락하는 자리이며, 예약 자체를 여기서 하지 않는다.
func withIdempotency(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// deployReceiver는 체인의 종단 핸들러다. 미들웨어를 모두 통과한 요청의 본문을 상한
// 안에서 읽고, 이후 단계(서명 검증 → 오케스트레이션)가 붙기 전까지는 처리하지 않는다.
func deployReceiver() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "요청 본문이 상한을 초과했다", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "요청 본문을 읽지 못했다", http.StatusBadRequest)
			return
		}

		// TODO(S1-2 이후): 게이트 1(withAuth)이 실제 판정을 하게 되면, 통과한 요청을
		// internal/deploy 오케스트레이터에 넘긴다(IA-4 ⑵). 지금은 수신 골격만 서 있고
		// 실제 배포 처리는 미구현이므로 요란하게 실패한다(fail-closed — 조용한 성공 위장 금지).
		http.Error(w, "배포 처리 미구현 (S1-2 이후)", http.StatusNotImplemented)
	})
}
