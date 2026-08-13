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
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/jun-bank/infra/internal/auth"
	"github.com/jun-bank/infra/internal/deploy"
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
	// History는 거절·예약 이력을 기록하고(RL-8) 재생 시 현재 상태를 읽는다(DO-10 ⑷ · DO-16).
	History store.HistoryStore
	// Deploy는 상태 있는 오케스트레이션 층이다(IA-4 ⑵) — 게이트·멱등을 통과한 요청을
	// 모드·락·manifest 검증을 거쳐 실행 지점까지 엮는다. nil이면 NewHandler가 기동을 거부한다.
	Deploy deploy.Coordinator
}

// 진입 층이 내는 기계 판독 거절 코드다(이력의 ReasonCode — 게이트 2의 코드는 auth가
// 소유한다). 사람이 읽는 사유는 문면이 바뀌지만 코드는 계약이므로, 코드별 집계·알림이
// 문자열 매칭에 기대지 않게 한다.
const (
	// ReasonTargetForbidden은 신원↔대상 결박 위반이다 — 등재된 저장소가 자기 허용 대상이
	// 아닌 것을 배포하려 했다(manifest 형식 오류와 구분된다).
	ReasonTargetForbidden = "TARGET_FORBIDDEN"
	// ReasonInternalBindingError는 게이트 2가 통과시켰는데 허용 대상이 없거나 닫힌 집합
	// 밖인 상태다 — 요청자의 잘못이 아니라 정책 로딩·배선의 결함이며, 코드가 붙어야
	// "권한 없는 요청이 많다"와 "우리 배선이 깨졌다"가 이력에서 갈린다.
	ReasonInternalBindingError = "INTERNAL_BINDING_ERROR"
)

// ctxKey는 미들웨어 사이에서 검증된 요청을 나르는 컨텍스트 키의 사설 타입이다.
type ctxKey int

const verifiedRequestKey ctxKey = 0

// verifiedRequest는 게이트들이 검증을 통과시킨 요청을 담아 하류(withIdempotency)로
// 넘긴다. 하류는 이 값을 재파싱·재검증하지 않는다 — 게이트 1·2의 판정을 신뢰한다.
type verifiedRequest struct {
	req  auth.Request
	jti  string // OIDC jti — 게이트 2가 검증된 토큰에서 실어 넣는다(부작용 전 선점 · DO-10 ⑶)
	body []byte // 서명·인증된 원본 body(manifest) — 오케스트레이션에 그대로 넘긴다
	// selfReport는 운영 승인이 자기 신고임을 나타낸다(게이트 2 · 잔여-5). 신규 예약을
	// 이력에 남길 때 이 사실을 함께 적는다.
	selfReport bool
	// allowedTarget은 게이트 2가 판정한 이 신원의 허용 배포 대상이다(allowlist 항목의
	// target). withValidate가 요청 대상과 대조해 결박을 세운다 — 하류는 이 값을 다시
	// 판정하지 않는다(게이트 판정 신뢰 계약).
	allowedTarget deploy.Target
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
	if deps.Deploy == nil {
		panic("httpentry: Deploy 오케스트레이터가 nil이다 (오케스트레이션 없이 수신을 열 수 없다 — fail-closed)")
	}
	mux := http.NewServeMux()
	mux.Handle("POST /deploy", chain(
		deployReceiver(deps),
		withBodyLimit(cfg.MaxBodyBytes), // 전송 제한(DO-15 ⑵) — 바깥에서 body를 캡
		withAuth(deps),                  // 게이트 1 — HMAC + 신선도(DO-2·DO-10 ⑴⑵)
		withOIDC(deps),                  // 게이트 2 — OIDC claim 행렬(DO-11) · HMAC과 AND
		withValidate(deps),              // repo↔target 결박 — 게이트 2의 허용 target과 요청 대상 대조
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

			// 통과 — 검증된 요청과 인증된 원본 body를 컨텍스트에 싣는다. body는 오케스트레이션이
			// manifest로 파싱할 서명·인증된 바이트다(하류가 재검증하지 않는다). jti는 게이트 2가 채운다.
			r.Body = io.NopCloser(bytes.NewReader(body))
			ctx := context.WithValue(r.Context(), verifiedRequestKey, verifiedRequest{req: areq, jti: "", body: body})
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
	d.rejectCoded(ctx, requestID, "", reason)
}

// rejectCoded는 기계 판독 코드를 함께 남기는 거절 기록이다(RL-8 + ReasonCode). 코드는
// 운영 대응이 갈리는 거절에만 붙는다 — 사유 문장은 문면이 바뀌면 집계가 조용히 깨지므로,
// 코드별 질의·알림이 그 문장에 기대지 않게 한다.
func (d Deps) rejectCoded(ctx context.Context, requestID, code, reason string) {
	if d.History == nil {
		return
	}
	_ = d.History.AppendEvent(ctx, store.HistoryEvent{
		RequestID:    requestID,
		EventType:    "REJECTED",
		RejectReason: reason,
		ReasonCode:   code,
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
				// 사유는 이력에만 남기고 응답은 "검증 실패"까지다 — 어느 칸이 왜 어긋났는지
				// (예: 등재된 저장소 이름)를 응답에 실으면 정책 내용이 밖으로 샌다.
				d.rejectCoded(r.Context(), vr.req.RequestID, dec.ReasonCode, "OIDC: "+dec.Reason)
				http.Error(w, "OIDC 검증 실패", http.StatusUnauthorized)
				return
			}

			// 통과 — 선점할 jti·자기 신고 표식과 이 신원의 허용 배포 대상을 실어 넘긴다.
			// 허용 target의 검증(빈 값·닫힌 집합)은 결박을 세우는 withValidate가 한다.
			vr.jti = dec.JTI
			vr.selfReport = dec.SelfReport
			vr.allowedTarget = dec.AllowedTarget
			ctx := context.WithValue(r.Context(), verifiedRequestKey, vr)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// withValidate는 신원↔대상 결박을 세운다: 게이트 2가 판정한 "이 저장소가 배포할 수 있는
// 대상"과 요청이 실제로 배포하려는 대상을 대조한다(A2). 등재된 저장소라도 자기 target
// 하나만 배포할 수 있다 — core의 정상 토큰으로 gateway를 배포하는 것이 여기서 끊긴다.
//
// ★ 자리가 여기인 이유(design rev.2 변경 ①): 대조는 **멱등 선점 이전**이어야 한다.
//   - 선점 뒤에 대조하면 권한 없는 요청이 requestId·jti를 소모한다(원장에 남고, 같은
//     토큰의 정당한 재시도가 재전송으로 취급된다). 여기서 끊으면 부작용이 0이다.
//   - 오케스트레이션(coordinator)에서 대조하면 재전송 경로(REPORT·ESCALATE)가 그 층을
//     지나지 않아 결박이 통째로 우회된다. 미들웨어는 모든 경로가 지난다.
//
// 대상 추출은 target 필드 하나만 부분 디코드한다(deploy.TargetOf) — manifest 완전성
// 검증은 여전히 VerifyManifest 하나가 소유한다(검증 정본을 둘로 만들지 않는다).
//
// 응답은 셋으로 갈린다:
//   - 게이트 2가 통과시켰는데 허용 target이 비었거나 닫힌 집합 밖 = **내부 배선 오류**다.
//     요청자의 잘못이 아니므로 4xx로 돌려주지 않고 500으로 요란하게 닫는다(fail-closed —
//     결박 없이 배포를 열지 않는다).
//   - target을 추출할 수 없음(JSON 파싱 불가·필드 부재·빈 값) = manifest 형식 오류 계열
//     422. 결박 위반이 아니라 요청이 배포 요청의 형태를 갖추지 못한 것이다.
//   - 추출한 대상 ≠ 허용 대상 = 403(권한 밖 대상). 닫힌 집합 밖의 값도 여기 걸린다.
//
// TODO: 이 슬롯이 원래 함께 지고 있던 요청 형태 검증(forwarded 헤더 불신 — DO-15 ⑹)은
// 아직 없다. 서명 범위 밖의 값은 판정에 쓰지 않는다(DO-10 ⑴)는 계약은 지금도 유효하다 —
// 여기서 쓰는 두 값은 서명된 body와 게이트 2의 판정 결과뿐이다.
func withValidate(d Deps) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v, ok := r.Context().Value(verifiedRequestKey).(verifiedRequest)
			if !ok {
				// 게이트를 거치지 않고 도달 = 조립 오류. 통과시키지 않는다(fail-closed).
				http.Error(w, "검증되지 않은 요청 (내부 순서 오류)", http.StatusInternalServerError)
				return
			}
			if !v.allowedTarget.Valid() {
				// 게이트 2가 통과시켰는데 허용 target이 없다 = 정책 로딩·배선이 깨진 것이다.
				// 이 상태에서 통과시키면 결박 없는 배포가 조용히 열린다. 500으로 닫되 —
				// 조용히 닫지는 않는다: 운영자가 원인을 찾을 수 있게 로그와 이력에 남긴다
				// (요청자 잘못이 아니므로 응답 본문은 일반 문구까지다).
				log.Printf("httpentry: 내부 배선 오류 — 인증된 요청에 허용 target이 없다(값=%q · requestId=%q). 게이트 2 정책 로딩·배선을 확인하라",
					v.allowedTarget, v.req.RequestID)
				d.rejectCoded(r.Context(), v.req.RequestID, ReasonInternalBindingError,
					"게이트 2가 통과시킨 요청에 허용 target이 없다(값="+string(v.allowedTarget)+") — 정책 로딩·배선 오류")
				http.Error(w, "내부 오류로 요청을 처리할 수 없다 (fail-closed)", http.StatusInternalServerError)
				return
			}

			target, err := deploy.TargetOf(v.body)
			if err != nil || target == "" {
				d.rejectUnverified(r.Context(), v.req.RequestID, "manifest target 추출 불가 (JSON 파싱 불가·target 필드 부재)")
				http.Error(w, "manifest 검증 실패: target을 읽을 수 없다", http.StatusUnprocessableEntity)
				return
			}
			if target != v.allowedTarget {
				// RL-8 — 이력에는 두 값을 남긴다. 오설정(워크플로가 남의 대상을 배포)과 침입
				// (탈취 토큰으로 다른 대상 배포)을 사후에 가르려면 무엇을 요구했는지가 필요하다.
				// 응답에는 남기지 않는다 — 허용 대상을 돌려주면 토큰을 쥔 쪽이 "무엇을 배포할
				// 수 있는지"를 응답만으로 알아낸다(정책 탐색). 진단은 이력의 몫이다.
				d.rejectCoded(r.Context(), v.req.RequestID, ReasonTargetForbidden,
					"target 불일치 (허용="+string(v.allowedTarget)+" 요청="+string(target)+") — 이 저장소는 그 대상을 배포할 수 없다")
				http.Error(w, "허용되지 않은 배포 대상", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// withIdempotency는 requestId를 부작용 전에 선점하고 재생을 3분기한다(DO-10 ⑶⑷).
// 검증된 요청(withAuth가 컨텍스트에 실은 것)만 여기 도달한다 — 인증되지 않은 요청은
// 이미 게이트 1에서 막혔다. 선점은 store가 소유하는 지속 부작용이며(append-only 원장),
// 이 슬롯은 그 결과로 흐름을 가른다:
//   - 신규            → 예약을 이력에 남기고 하류(오케스트레이션)로 진행.
//   - 재전송(ErrReplay) → 현재 이력 상태로 재개/상태 반환/에스컬레이션을 가른다(handleReplay).
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
				// 재전송 — 현재 이력 상태로 처리를 가른다(#9 · DO-16 ⑵). 완료면 재실행 없이
				// 상태 반환, 미완(미실행·예약만)이면 같은 requestId로 재개해 완주시키고,
				// UNKNOWN이면 무턱대고 재시도하지 않고 사람에게 올린다.
				d.handleReplay(w, r, v, next)

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

// handleReplay는 이미 예약된(재전송) 요청을 현재 이력 상태로 가른다(#9 갭 차단 · DO-16 ⑵).
// 예약(RESERVED) 뒤 수신 실패로 미완이 된 배포가 ErrReplay로 영영 단락되던 갭을 닫는다:
//   - 재개(REEXECUTE)  → 같은 requestId로 오케스트레이션 재진입해 완주시킨다(미실행=부작용 0
//     증명이므로 중복 부작용 없음 — dispatcher는 requestId 단위 멱등).
//   - 상태 반환(REPORT) → 이미 완료 — 재실행 없이 현재 상태만 반환한다(DO-10 ⑷).
//   - 에스컬레이션(ESCALATE) → 직전 시도가 UNKNOWN — 무턱대고 재시도하지 않고 사람에게 올린다.
func (d Deps) handleReplay(w http.ResponseWriter, r *http.Request, v verifiedRequest, next http.Handler) {
	var latest store.HistoryEvent
	if d.History != nil {
		ev, err := d.History.ReadLatest(r.Context(), v.req.RequestID)
		if err != nil {
			// 재전송 분류의 근거 이력을 읽지 못했다 = 재개/보고/에스컬레이션 판정 불가.
			// empty로 간주해 200을 내면 완료된 배포를 미예약으로 오판하므로, 읽기 오류는
			// fail-closed(500 · 재시도 금지 판정 불가)로 닫는다.
			http.Error(w, "재전송 이력 조회 실패 — 판정 불가(fail-closed)", http.StatusInternalServerError)
			return
		}
		latest = ev
	}
	switch deploy.ClassifyReplay(latest) {
	case deploy.ResumeReexecute:
		// 미완 배포를 완주시킨다 — 종단 수신 핸들러(next)를 다시 태워 같은 requestId로
		// 오케스트레이션을 재진입한다. 검증된 요청(v)은 이미 컨텍스트에 있으므로 그대로 태운다.
		next.ServeHTTP(w, r)
	case deploy.ResumeReport:
		d.replayCurrentState(w, latest)
	default: // ResumeEscalate
		w.Header().Set("X-Deploy-Idempotent-Replay", "true")
		http.Error(w, "직전 시도가 UNKNOWN 상태 — 자동 재시도 금지, 사람 개입 필요(DO-16 ⑵)", http.StatusConflict)
	}
}

// replayCurrentState는 재전송된 요청에 대해 재실행 없이 현재 상태를 반환한다(완료 경로).
// handleReplay가 이미 읽은 latest를 그대로 받는다 — 여기서 다시 읽지 않는다(중복 조회·같은
// 읽기 오류 무음 삼킴 방지). event_type이 있으면 그것을, 없으면 예약만 된 상태로 응답한다.
// 하류(수신)를 호출하지 않는다 — 완료된 배포를 재전송이 두 번 일으키지 않는 것이 핵심이다.
func (d Deps) replayCurrentState(w http.ResponseWriter, latest store.HistoryEvent) {
	status := "RESERVED"
	if latest.EventType != "" {
		status = latest.EventType
	}
	w.Header().Set("X-Deploy-Idempotent-Replay", "true")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "이미 수신된 요청 (재실행 없음) 상태="+status+"\n")
}

// deployReceiver는 체인의 종단 핸들러다. 게이트·멱등을 모두 통과한 검증된 요청을 상태
// 있는 오케스트레이션 층(internal/deploy)에 넘긴다(IA-4 ⑵). body는 withAuth가 서명 검증과
// 함께 인증한 원본이며(재검증하지 않는다), 오케스트레이터가 그것을 manifest로 파싱해
// 모드·락·검증을 거쳐 실행 지점까지 엮는다. 결과는 전송 무관 Outcome이며 여기서 상태
// 코드로 사상한다.
func deployReceiver(d Deps) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := r.Context().Value(verifiedRequestKey).(verifiedRequest)
		if !ok {
			// 게이트를 거치지 않고 도달 = 조립 오류. 통과시키지 않는다(fail-closed).
			http.Error(w, "검증되지 않은 요청 (내부 순서 오류)", http.StatusInternalServerError)
			return
		}
		res := d.Deploy.Orchestrate(r.Context(), deploy.Request{
			RequestID: v.req.RequestID,
			Body:      v.body,
		})
		writeOutcome(w, res)
	})
}

// writeOutcome은 오케스트레이션 결과를 HTTP 상태로 사상한다. 실행 지점 도달(dispatch
// 미구현)은 501로 요란하게 드러낸다 — 조용한 성공 위장을 하지 않는다(#15 전까지 배포는
// 완료되지 않는다). 거절·fail-closed는 각각의 4xx/5xx로 닫는다.
func writeOutcome(w http.ResponseWriter, res deploy.Result) {
	switch res.Outcome {
	case deploy.OutcomeReachedDispatch:
		http.Error(w, "오케스트레이션 통과·실행 지점 도달 — 배포 실행 미구현(#15)", http.StatusNotImplemented)
	case deploy.OutcomeManifestInvalid:
		http.Error(w, "manifest 검증 실패: "+res.Detail, http.StatusUnprocessableEntity)
	case deploy.OutcomeLockContended:
		http.Error(w, "배포 창 락 경합 — 다른 배포·배치 진행 중", http.StatusConflict)
	case deploy.OutcomeModeChanged:
		http.Error(w, "적용 직전 모드 토글 — 요청 거절(토글-요청 race)", http.StatusConflict)
	case deploy.OutcomeFailClosed:
		// 503 — 인프라 축(저장 접근·락·mode version·fencing)이 막았다. "지금은 받을 수 없다"다.
		http.Error(w, "fail-closed: "+res.Detail, http.StatusServiceUnavailable)
	case deploy.OutcomeExecutionFailed:
		// 502 — 실행 계층(dispatch: pull·up·헬스)이 실패했다. 우리가 위임한 하류(docker·레지스트리·
		// 배포 대상 프로세스)가 요청을 완수하지 못한 것이므로 Bad Gateway가 의미상 맞고, 503(인프라
		// fail-closed — 우리가 시작조차 못 했다)과 코드로 갈려야 워크플로 로그·DO-6 관제에서 두
		// 범주가 구별된다. Detail은 그대로 싣는다(어느 단계가 왜 실패했는지가 유일한 단서다).
		// ⚠️ 앞단 프록시·엣지가 내는 502(agent에 닿지도 못한 경우)와는 코드만으로 구분되지 않는다 —
		// 구분자는 본문 접두어("배포 실행 실패")다. 코드로만 분기하는 소비자는 그 접두어를 함께 본다.
		http.Error(w, "배포 실행 실패: "+res.Detail, http.StatusBadGateway)
	case deploy.OutcomeStorageIntegrity:
		// 500 — 동봉 compose의 candidate 기록·재해시가 어긋났다(G-14). 요청은 옳았고 이 호스트의
		// 저장 계층이 잘못했으므로 4xx로 돌려 CI가 자기 산출물을 의심하게 만들지 않는다. 코드를
		// 본문 접두어로 실어 워크플로 로그·관제가 문자열 매칭 없이 이 범주를 집계할 수 있게 한다.
		http.Error(w, string(deploy.OutcomeStorageIntegrity)+": "+res.Detail, http.StatusInternalServerError)
	case deploy.OutcomeCompleted:
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "배포 완료\n")
	case deploy.OutcomeUnknown:
		// Detail에 dispatch 오류 단서를 실어 보낸다 — 워크플로 로그에서 바로 원인이 보이게(무음 금지).
		msg := "원격 실행 UNKNOWN — 사람 개입 필요(락 유지)"
		if res.Detail != "" {
			msg = res.Detail
		}
		http.Error(w, msg, http.StatusConflict)
	default:
		http.Error(w, "알 수 없는 오케스트레이션 결과", http.StatusInternalServerError)
	}
}
