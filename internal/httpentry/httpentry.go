// Package httpentry는 deploy-agent의 HTTP 진입 층이다 — agent 두 층 중 ⑴번
// (ADR-029 IA-4 ⑴: HTTP 진입 미들웨어 = Go http.Handler 체인). 여기서는 요청을
// 받아 전송 수준 제한(method·body 크기)을 강제하고, 게이트 1(HMAC)·게이트 2(OIDC)·멱등을
// 미들웨어 체인으로 엮는다. 상태 있는 오케스트레이션(락·트랜잭션)은 이 층 밖이다.
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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/jun-bank/infra/internal/auth"
	"github.com/jun-bank/infra/internal/store"
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

// 서명 대상 필드를 나르는 요청 헤더 이름(DO-10 ⑴). 본문은 digest로만 서명 범위에
// 들어가고, 나머지 서명 필드(requestId·issuedAt·expiresAt)와 서명 자체는 헤더로 온다.
// ⚠️ 이 헤더 이름·서명 인코딩(hex)·digest 형식("sha256:"+hex)은 [구현 검증]이다 —
// CI 서명 워크플로와 짝을 맞춘 실제 계약이며 한쪽만 바꾸면 모든 서명이 불일치한다.
const (
	headerRequestID = "X-Deploy-Request-Id"
	headerIssuedAt  = "X-Deploy-Issued-At"
	headerExpiresAt = "X-Deploy-Expires-At"
	headerSignature = "X-Deploy-Signature"  // hex 인코딩된 HMAC
	headerOIDCToken = "X-Deploy-Oidc-Token" // GitHub Actions OIDC ID 토큰(JWT) — 게이트 2
)

// OIDCGate는 게이트 2다(OIDC claim 행렬 — DO-11). 소비 지점 인터페이스로 두어 이 층이
// auth의 구체 타입에 묶이지 않게 한다(IA-5 Go 관용구). 토큰 문자열을 받아 서명·claim을
// 판정하고, 통과 시 선점할 jti와 자기 신고 표식을 담은 결정을 낸다.
type OIDCGate interface {
	Verify(ctx context.Context, rawToken string) auth.OIDCDecision
}

// Deps는 진입 층이 판정을 위임하는 협력자들이다. 전부 인터페이스이며(auth.Verifier ·
// store 인터페이스), 이 층은 그것들을 구성하지 않는다 — main이 실제 verifier·DB store를
// 조립해 주입한다(DO-14 ⑸ 프로세스 경계: 진입 층은 키·자격을 직접 보유하지 않는다).
type Deps struct {
	// Verifier는 게이트 1(HMAC + 신선도)이다. nil이면 NewHandler가 기동을 거부한다.
	Verifier auth.Verifier
	// OIDC는 게이트 2(OIDC claim 행렬 — DO-11)다. nil이면 NewHandler가 기동을 거부한다
	// (검증자 없이 진입 층을 세우는 것은 fail-open).
	OIDC OIDCGate
	// Ledger는 requestId 멱등 선점 원장이다(DO-10 ⑶⑷).
	Ledger store.LedgerStore
	// History는 거절·예약 이력을 기록하고(RL-8) 재생 시 현재 상태를 읽는다(DO-10 ⑷).
	History store.HistoryStore
}

// ctxKey는 미들웨어 사이에서 검증된 요청을 나르는 컨텍스트 키의 사설 타입이다.
type ctxKey int

const verifiedRequestKey ctxKey = 0

// verifiedRequest는 게이트들이 검증을 통과시킨 요청을 담아 하류(withIdempotency)로
// 넘긴다. 하류는 이 값을 재파싱·재검증하지 않는다 — 게이트 1·2의 판정을 신뢰한다.
type verifiedRequest struct {
	req auth.Request
	jti string // OIDC jti — 게이트 2가 검증된 토큰에서 실어 넣는다(부작용 전 선점 · DO-10 ⑶)
	// selfReport는 운영 승인이 자기 신고임을 나타낸다(게이트 2 · 잔여-5). 신규 예약을
	// 이력에 남길 때 이 사실을 함께 적는다.
	selfReport bool
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
//
// deps는 게이트 1(Verifier)과 멱등 원장·이력(store)을 주입한다. Verifier가 nil이면
// panic한다 — 검증자 없이 진입 층을 세우는 것은 fail-open이며, 조립 시점의 프로그래밍
// 오류이므로 요란하게 실패한다(요청 시점에 조용히 통과시키지 않는다).
func NewHandler(cfg Config, deps Deps) http.Handler {
	if deps.Verifier == nil {
		panic("httpentry: Verifier가 nil이다 (검증자 없이 진입 층을 세울 수 없다 — fail-closed)")
	}
	if deps.OIDC == nil {
		panic("httpentry: OIDC 게이트가 nil이다 (신원 검증 없이 진입 층을 세울 수 없다 — fail-closed)")
	}
	mux := http.NewServeMux()
	mux.Handle("POST /deploy", chain(
		deployReceiver(),
		withBodyLimit(cfg.MaxBodyBytes), // 전송 제한(DO-15 ⑵) — 바깥에서 body를 캡
		withAuth(deps),                  // 게이트 1 — HMAC + 신선도(DO-2·DO-10 ⑴⑵)
		withOIDC(deps),                  // 게이트 2 — OIDC claim 행렬(DO-11) · HMAC과 AND
		withValidate,                    // 요청 형태 검증 슬롯(통과 스텁)
		withIdempotency(deps),           // requestId·jti 멱등 선점·3분기(DO-10 ⑶⑷)
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

// withAuth는 게이트 1이다: 본문을 상한 안에서 읽어 digest를 계산하고, 서명 필드를
// 헤더에서 파싱해 auth.Verifier로 HMAC + 신선도를 판정한다(DO-2·DO-10 ⑴⑵). 실패하면
// 거절 사유를 이력에 기록(RL-8)한 뒤 차단한다 — 절대 통과시키지 않는다(fail-closed).
// 통과한 요청은 검증된 형태로 컨텍스트에 실어 하류로 넘기고, 본문은 다시 읽을 수 있게
// 되돌린다.
//
// jti는 여기서 빈 값으로 둔다 — 게이트 2(withOIDC)가 서명 검증된 OIDC 토큰에서 실어
// 넣는다. 스푸핑 가능한 클라이언트 헤더를 jti로 신뢰하지 않는다.
func withAuth(d Deps) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					http.Error(w, "요청 본문이 상한을 초과했다", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "요청 본문을 읽지 못했다", http.StatusBadRequest)
				return
			}

			sig, err := hex.DecodeString(r.Header.Get(headerSignature))
			if err != nil || len(sig) == 0 {
				// 서명이 없거나 hex가 깨졌다 = 검증 불가 = 거절(RL-8).
				d.rejectUnverified(r.Context(), r.Header.Get(headerRequestID), "서명 헤더 부재·형식 오류")
				http.Error(w, "서명 검증 실패", http.StatusUnauthorized)
				return
			}

			areq := auth.Request{
				Method:     r.Method,
				Path:       r.URL.Path,
				BodyDigest: bodyDigest(body),
				RequestID:  r.Header.Get(headerRequestID),
				IssuedAt:   r.Header.Get(headerIssuedAt),
				ExpiresAt:  r.Header.Get(headerExpiresAt),
				Signature:  sig,
			}

			dec, err := d.Verifier.Verify(areq)
			if err != nil {
				// 검증 자체가 오류(내부 오류)면 fail-closed로 막는다(통과 금지).
				http.Error(w, "서명 검증 중 오류", http.StatusInternalServerError)
				return
			}
			if !dec.Accepted {
				d.rejectUnverified(r.Context(), areq.RequestID, dec.Reason)
				http.Error(w, "서명 검증 실패", http.StatusUnauthorized)
				return
			}

			// 통과 — 검증된 요청을 컨텍스트에 싣고 본문을 되돌린다. jti는 S1-3까지 빈 값.
			r.Body = io.NopCloser(bytes.NewReader(body))
			ctx := context.WithValue(r.Context(), verifiedRequestKey, verifiedRequest{req: areq, jti: ""})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bodyDigest는 raw body의 서명용 digest를 만든다("sha256:"+hex — [구현 검증] 형식).
func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// rejectUnverified는 거절을 이력에 기록한다(RL-8). requestId는 검증 전이라 신뢰할 수
// 없는 값이지만, 감사 목적의 거절 행에는 있는 그대로 남긴다. 기록 실패는 삼키되 —
// 거절 자체는 이미 확정이므로 통과로 뒤집지 않는다(fail-closed).
func (d Deps) rejectUnverified(ctx context.Context, requestID, reason string) {
	if d.History == nil {
		return
	}
	_ = d.History.AppendEvent(ctx, store.HistoryEvent{
		RequestID:    requestID,
		EventType:    "REJECTED",
		RejectReason: reason,
	})
}

// withOIDC는 게이트 2다: 게이트 1을 통과한 요청에 대해 OIDC ID 토큰을 헤더에서 읽어
// claim 행렬로 신원을 판정한다(DO-11 — HMAC과 AND). 실패하면 거절 사유를 이력에
// 기록(RL-8)하고 401로 막는다 — 절대 통과시키지 않는다(fail-closed). 통과하면 서명
// 검증된 토큰의 jti를 verifiedRequest에 실어 하류가 부작용 전에 선점하게 하고(DO-10 ⑶),
// 운영 승인이 자기 신고임을 selfReport로 표시해 신규 예약 이력에 남긴다(잔여-5).
//
// OIDC 토큰은 HMAC 서명 범위 밖이다(DO-10 ⑴ "서명 밖의 값") — 그래도 판정에 쓰는 것은
// 이 토큰이 발급자 서명으로 스스로를 증명하기 때문이고, 재전송은 jti 일회성 선점이 막는다.
func withOIDC(d Deps) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vr, ok := r.Context().Value(verifiedRequestKey).(verifiedRequest)
			if !ok {
				// 게이트 1을 거치지 않고 도달 = 조립 오류. 통과시키지 않는다(fail-closed).
				http.Error(w, "검증되지 않은 요청 (내부 순서 오류)", http.StatusInternalServerError)
				return
			}

			token := r.Header.Get(headerOIDCToken)
			if strings.TrimSpace(token) == "" {
				// OIDC 토큰 부재 = 신원 검증 불가 = 거절(RL-8).
				d.rejectUnverified(r.Context(), vr.req.RequestID, "OIDC 토큰 부재")
				http.Error(w, "OIDC 검증 실패", http.StatusUnauthorized)
				return
			}

			dec := d.OIDC.Verify(r.Context(), token)
			if !dec.Accepted {
				d.rejectUnverified(r.Context(), vr.req.RequestID, "OIDC: "+dec.Reason)
				http.Error(w, "OIDC 검증 실패", http.StatusUnauthorized)
				return
			}

			// 통과 — 선점할 jti와 자기 신고 표식을 실어 하류로 넘긴다.
			vr.jti = dec.JTI
			vr.selfReport = dec.SelfReport
			ctx := context.WithValue(r.Context(), verifiedRequestKey, vr)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// withValidate는 요청 형태(필수 헤더·manifest 구조)를 검증할 자리다. 지금은 통과 스텁.
//
// TODO: 서명 범위 밖의 값은 판정에 쓰지 않는다(DO-10 ⑴) · forwarded 헤더 불신(DO-15 ⑹).
func withValidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// withIdempotency는 requestId를 부작용 전에 선점하고 재생을 3분기한다(DO-10 ⑶⑷).
// 검증된 요청(withAuth가 컨텍스트에 실은 것)만 여기 도달한다 — 인증되지 않은 요청은
// 이미 게이트 1에서 막혔다. 선점은 store가 소유하는 지속 부작용이며(append-only 원장),
// 이 슬롯은 그 결과로 흐름을 가른다:
//   - 신규            → 예약을 이력에 남기고 하류(수신)로 진행.
//   - 동일 id·동일 digest(또는 jti 재사용) → 재실행하지 않고 현재 상태를 반환.
//   - 동일 id·다른 digest → 거절·기록(409).
func withIdempotency(d Deps) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v, ok := r.Context().Value(verifiedRequestKey).(verifiedRequest)
			if !ok {
				// 게이트 1을 거치지 않고 도달 = 조립 오류. 통과시키지 않는다(fail-closed).
				http.Error(w, "검증되지 않은 요청 (내부 순서 오류)", http.StatusInternalServerError)
				return
			}
			if d.Ledger == nil {
				http.Error(w, "멱등 원장 미구성", http.StatusInternalServerError)
				return
			}

			err := d.Ledger.Reserve(r.Context(), v.req.RequestID, v.jti, v.req.BodyDigest)
			switch {
			case err == nil:
				// 신규 예약 — 이력에 RESERVED를 남기고 하류로 진행한다. 게이트 2가 운영
				// 승인을 자기 신고로만 확인했으면(잔여-5) 그 한계를 이 행에 함께 적는다 —
				// "우리 파이프라인에서 왔다"까지만 증명됐고 "운영 승인됐다"는 자기 신고다.
				if d.History != nil {
					ev := store.HistoryEvent{
						RequestID:      v.req.RequestID,
						EventType:      "RESERVED",
						ManifestDigest: v.req.BodyDigest,
					}
					if v.selfReport {
						ev.Result = "OPERATIONAL_APPROVAL_SELF_REPORTED"
					}
					_ = d.History.AppendEvent(r.Context(), ev)
				}
				next.ServeHTTP(w, r)

			case errors.Is(err, store.ErrReplay):
				// 재전송 — 재실행 금지. 그 요청의 현재 상태를 반환한다(DO-10 ⑷).
				d.replayCurrentState(w, r, v.req.RequestID)

			case errors.Is(err, store.ErrDigestConflict):
				// 같은 멱등 키로 다른 내용 — 거절·기록(RL-8).
				d.rejectUnverified(r.Context(), v.req.RequestID, "동일 requestId + 다른 body digest")
				http.Error(w, "requestId 충돌 (다른 본문)", http.StatusConflict)

			default:
				// 원장 쓰기 실패 = 부작용을 열 수 없다 = fail-closed(DO-17 ⑷).
				http.Error(w, "멱등 선점 실패", http.StatusInternalServerError)
			}
		})
	}
}

// replayCurrentState는 재전송된 요청에 대해 재실행 없이 현재 상태를 반환한다. 이력이
// 있으면 마지막 event_type을, 없으면 예약만 된 상태로 응답한다. 어느 쪽이든 하류(수신)를
// 호출하지 않는다 — 재전송이 두 번째 배포를 일으키지 않는 것이 이 경로의 핵심이다.
func (d Deps) replayCurrentState(w http.ResponseWriter, r *http.Request, requestID string) {
	status := "RESERVED"
	if d.History != nil {
		if ev, err := d.History.ReadLatest(r.Context(), requestID); err == nil && ev.EventType != "" {
			status = ev.EventType
		}
	}
	w.Header().Set("X-Deploy-Idempotent-Replay", "true")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "이미 수신된 요청 (재실행 없음) 상태="+status+"\n")
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
