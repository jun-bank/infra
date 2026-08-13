package agentrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/store"
)

// maxFenceBodyBytes는 fence 요청 body 상한이다(작은 서명 JSON — slow/거대 body 방어).
const maxFenceBodyBytes int64 = 1 << 14

// LeaseChecker는 main fence 핸들러가 소비하는 read-only 락 판정 표면이다(G-4). store.SQLStore가
// FencingLeaseHeld로 구현한다 — 소비 지점 인터페이스로 두어 핸들러가 store 구체 타입·DB에
// 직접 묶이지 않게 하고, 테스트가 페이크로 판정을 관측할 수 있게 한다. 판정은 **DB 시각**으로
// 하며 Go 시계 비교를 쓰지 않는다(FencingLeaseHeld 주석).
type LeaseChecker interface {
	FencingLeaseHeld(ctx context.Context, holderID string, token store.FencingToken) (bool, error)
}

// FenceHandlerConfig는 main 측 fence-confirm 수신 핸들러의 배선이다(infra#37 조각 B · G-5).
// CI /deploy 수신과 **합치지 않고** 별도 listener에 붙는다(B2 — LAN 내부 표면).
type FenceHandlerConfig struct {
	// Keys는 target별 위성 개별 키다(main이 위성에 명령을 보낼 때 쓰는 AGENT_RPC_KEY_* 와 같은
	// 키). 요청의 target으로 이 표에서 키를 골라 서명을 검증한다 — target에 키가 없으면 검증
	// 불가로 거절한다(키 검증 전 store read 금지 · G-5).
	Keys map[deploy.Target][]byte
	// Lease는 DB시각 lease 판정기다(G-4).
	Lease LeaseChecker
	// HolderID는 이 main coordinator의 락 holder 식별자다(CD-3 · buildCoordinator와 같은 값).
	// 위성은 token만 보내고, main은 자기 holderID로 "이 lock이 여전히 내 것인가"를 판정한다.
	HolderID string
	// Skew는 fence 요청 신선도 허용 창이다(가로챈 유효 요청의 락 만료 후 재생 완화 · fail-closed).
	Skew time.Duration
	// AllowedSources는 허용된 출발지 IP 집합이다(위성 .158/.164 — G-5 출발지 제한). 비면 검사
	// 생략(방화벽이 1차 방어 · "가능 범위"). 설정되면 그 밖의 출발지는 부작용·검증 전에 거절한다.
	AllowedSources map[string]bool
	now            func() time.Time
}

// FenceHandler는 위성의 fence-confirm 요청을 수신·검증·판정·서명 응답한다(G-5). 순서(부작용·판정은
// 출발지·키·서명·신선도를 통과한 뒤에만):
//
//	body 상한 → 출발지 제한(설정 시) → body 파싱(target 추출) → target으로 위성별 키 결정
//	→ 서명 검증(위성 키) → 신선도 창 → **여기서부터** store lease 판정(EXISTS) → 서명 응답
//
// store read는 키 검증 뒤에만 한다(G-5) — 미인증 요청이 DB를 두드리지 못하게 한다. 판정
// 불가(store 오류)·held=false는 전부 STALE로 서명한다(fail-closed — 위성이 deny로 접는다).
type FenceHandler struct {
	cfg FenceHandlerConfig
}

// 컴파일 타임 계약 확인 — FenceHandler는 http.Handler다.
var _ http.Handler = (*FenceHandler)(nil)

// NewFenceHandler는 fence 핸들러를 만든다. 키·판정기·holderID·skew를 검증한다(fail-closed).
func NewFenceHandler(cfg FenceHandlerConfig) (*FenceHandler, error) {
	if len(cfg.Keys) == 0 {
		return nil, fmt.Errorf("agentrpc: fence 핸들러에 위성 키가 하나도 없다(fail-closed)")
	}
	for t, k := range cfg.Keys {
		if !t.Valid() {
			return nil, fmt.Errorf("agentrpc: fence 키 target이 닫힌 집합 밖이다: %q", t)
		}
		if err := ValidateKey(k); err != nil {
			return nil, fmt.Errorf("agentrpc: fence 키(%s)가 비어 있다(fail-closed): %w", t, err)
		}
	}
	if cfg.Lease == nil {
		return nil, fmt.Errorf("agentrpc: fence lease 판정기가 nil(fail-closed)")
	}
	if cfg.HolderID == "" {
		return nil, fmt.Errorf("agentrpc: fence holderID가 비어 있다(fail-closed)")
	}
	if cfg.Skew <= 0 {
		return nil, fmt.Errorf("agentrpc: fence skew는 >0 이어야 한다(신선도 창 · fail-closed): %s", cfg.Skew)
	}
	// 키 방어 복사(호출자가 나중에 원본 슬라이스를 바꿔도 검증이 흔들리지 않게).
	keys := make(map[deploy.Target][]byte, len(cfg.Keys))
	for t, k := range cfg.Keys {
		cp := make([]byte, len(k))
		copy(cp, k)
		keys[t] = cp
	}
	cfg.Keys = keys
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &FenceHandler{cfg: cfg}, nil
}

func (h *FenceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 출발지 제한(G-5 · 설정 시) — 부작용·판정 전에 위성 IP가 아니면 거절한다. 방화벽이 1차
	// 방어이고 이것은 "가능 범위" 2차 방어다.
	if len(h.cfg.AllowedSources) > 0 && !h.sourceAllowed(r.RemoteAddr) {
		http.Error(w, "forbidden source", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFenceBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "body too large or read error", http.StatusRequestEntityTooLarge)
		return
	}

	// body 파싱 — target을 여기서 뽑는다(키 결정의 축). 파싱 불가면 검증 불가이므로 무서명 400.
	var req fenceRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad fence request", http.StatusBadRequest)
		return
	}

	// target으로 위성별 키 결정(G-5) — 키가 없으면 검증 불가 = 무서명 401. **store read 이전**이다.
	key, ok := h.cfg.Keys[deploy.Target(req.Target)]
	if !ok {
		http.Error(w, "unknown target", http.StatusUnauthorized)
		return
	}

	// 서명 검증(위성 키) — canonical은 요청 필드(도메인·target·requestId·token·confirmId·issuedAt)로
	// 재구성한다. 필드 변조는 canonical을 바꿔 검증을 깨뜨린다. **여기까지 통과해야** store를 읽는다.
	canonical := FenceRequestCanonicalV1(req.Target, req.RequestID, req.Token, req.ConfirmID, req.IssuedAt)
	if req.RequestID == "" || req.ConfirmID == "" || !Verify(key, canonical, r.Header.Get(HeaderSignature)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// 신선도 창 — 서명에 든 issuedAt(헤더 아님 · 서명 대상)이 창 안인지 본다. 창 밖이면 무서명 401.
	if !freshTimestampOK(h.cfg.now(), strconv.FormatInt(req.IssuedAt, 10), h.cfg.Skew) {
		http.Error(w, "stale fence request", http.StatusUnauthorized)
		return
	}

	// --- 인증 통과 · 여기서부터만 store를 읽는다(G-5) ---
	// DB시각 lease 판정(G-4). store 오류·held=false는 전부 STALE로 서명한다(fail-closed) —
	// 위성이 deny로 접어 mutation을 멈춘다. HELD는 살아있음이 증명됐을 때만 서명한다.
	verdict := FenceVerdictStale
	detail := "lease 상실(만료·인계·holder/token 불일치) 또는 판정 불가 — mutation 금지"
	held, cerr := h.cfg.Lease.FencingLeaseHeld(r.Context(), h.cfg.HolderID, store.FencingToken(req.Token))
	switch {
	case cerr != nil:
		detail = "store lease 판정 오류(fail-closed STALE — 사람 개입 가능)"
	case held:
		verdict = FenceVerdictHeld
		detail = "lease 살아있음(DB시각 기준 · 같은 holder·token)"
	}
	h.respond(w, key, body, req.ConfirmID, req.RequestID, verdict, detail)
}

// respond는 서명된 fence 응답을 쓴다(G-1). 서명은 요청 bodyDigest·confirmId·verdict를 결박하므로
// (FenceResponseCanonicalV1), 응답이 그 한 번의 확인에만 유효하다. detail에 시크릿을 담지 않는다.
func (h *FenceHandler) respond(w http.ResponseWriter, key, requestBody []byte, confirmID, requestID, verdict, detail string) {
	reqDigest := BodyDigest(requestBody)
	sig := Sign(key, FenceResponseCanonicalV1(reqDigest, confirmID, verdict))
	w.Header().Set(HeaderSignature, sig)
	w.Header().Set(HeaderTimestamp, strconv.FormatInt(h.cfg.now().Unix(), 10))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(fenceResponse{RequestID: requestID, ConfirmID: confirmID, Verdict: verdict, Detail: detail})
}

// sourceAllowed는 원격 주소의 host가 허용 집합에 있는지 본다(G-5). host:port 분리 실패 시엔
// 원문 그대로도 대조한다(테스트·특이 주소 대비). 파싱 불가는 거절이다(fail-closed).
func (h *FenceHandler) sourceAllowed(remoteAddr string) bool {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h.cfg.AllowedSources[host]
	}
	return h.cfg.AllowedSources[remoteAddr]
}

// freshTimestampOK는 서명에 든 Unix 초 timestamp가 신선도 창 안인지 본다(overflow-safe · C4와
// 같은 축). Server.freshOK와 같은 로직을 한 곳에 둔 것이다 — 엄격 10진(재직렬화 일치)·sec≤0
// 선거절로 int64 wrap을 없애고, 초 단위 int64 비교로 Duration 곱셈 overflow도 피한다.
// |now - sec| ≤ skew(초)일 때만 참.
func freshTimestampOK(now time.Time, ts string, skew time.Duration) bool {
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if strconv.FormatInt(sec, 10) != ts {
		return false // 앞자리 0·부호·공백 등 canonical과 어긋나는 표기 거절
	}
	if sec <= 0 {
		return false // 유효 unix 타임스탬프는 양수 — 음수·0·MinInt64 차단(overflow 방어의 뿌리)
	}
	nowSec := now.Unix()
	var diff int64
	if nowSec >= sec {
		diff = nowSec - sec // 양수 − 양수 → overflow 없음
	} else {
		diff = sec - nowSec
	}
	return diff <= int64(skew/time.Second)
}
