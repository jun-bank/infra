// 이 파일은 게이트 2(oidc.go)의 KeySet 경계를 실제 네트워크로 채운다: 발급자
// (GitHub Actions OIDC)의 JWKS 공개키를 HTTPS로 페치·캐시하고 키 회전을 따라간다.
// oidc.go의 jwksTokenVerifier는 kid로 키만 받으면 되고(RS256 고정·alg 혼동 방어는
// 이미 거기 있다), 이 파일은 그 kid → RSA 공개키 조회만 소유한다.
//
// 계약(정본): ADR-027 DO-11(서명 전제)·잔여-5. 개념: docs/study 보안/jwks.
//
// 흐름은 세 단계다:
//
//	⑴ discovery: <issuer>/.well-known/openid-configuration 를 GET → jwks_uri 추출.
//	   issuer·jwks_uri 둘 다 https를 강제한다(평문이면 MITM이 키를 바꿔치기해 위조
//	   토큰을 통과시킬 수 있다 — 페치 자체가 신뢰의 뿌리이므로 전송 보안이 전제다).
//	⑵ JWK Set 페치: jwks_uri 를 GET → keys[] 를 kid별 rsa.PublicKey 맵으로 파싱.
//	   JWK RSA는 n·e를 base64url(RawURLEncoding)로 싣는다 — 외부 JWK 라이브러리 없이
//	   stdlib(math/big)로 수동 파싱한다(C-08 최소주의).
//	⑶ VerificationKey(kid): 캐시가 신선하고 kid가 있으면 반환. 미지 kid나 캐시 만료면
//	   재페치(회전 추적) 후 다시 조회 — 그래도 없으면 오류(fail-closed).
//
// fail-closed가 뼈대다: discovery·페치·파싱 실패, 미지 kid, 빈 kid는 모두 오류이며
// 키를 얻지 못하면 oidc.go가 서명을 검증할 수 없어 거절로 이어진다(기존 계약).
//
// 남용 방어: ⓐ 빈 kid는 페치 없이 즉시 거절(공짜 요청이 발급자를 두드리지 못하게),
// ⓑ 미지 kid 재페치는 최소 간격으로 제한(fetch storm — 침해·오설정 시 발급자를 홍수
// 요청으로 두드리지 않게), ⓒ 응답 크기 상한·클라이언트 timeout(악의적 거대·지연 응답).
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// wellKnownPath는 OIDC discovery 문서의 표준 경로다(issuer에 이어 붙인다).
	wellKnownPath = "/.well-known/openid-configuration"
	// maxJWKSBytes는 discovery·JWKS 응답 본문의 상한이다(악의적 거대 응답 방어).
	// GitHub JWKS는 수 KB이므로 1MiB는 정상 응답을 자르지 않으면서 홍수를 끊는다.
	maxJWKSBytes = 1 << 20
	// defaultHTTPTimeout은 discovery·JWKS 각 GET의 상한이다(지연 응답으로 인한
	// 요청 처리 정체 방어). env가 아닌 코드 상수 — 페치 경로 내부값이다.
	defaultHTTPTimeout = 10 * time.Second
	// defaultMinRefetchInterval은 미지 kid로 인한 재페치의 최소 간격이다(fetch storm
	// 방지). 무작위 kid 홍수가 매 요청마다 발급자를 두드리지 못하게 한다. [구현 검증].
	defaultMinRefetchInterval = 30 * time.Second
	// maxExponentBytes는 JWK 지수(e)의 바이트 상한이다. RSA 공개 지수는 보통 65537
	// (AQAB · 3바이트)이라 4바이트면 충분하다 — 비정상적으로 큰 e를 파싱 전에 거절한다.
	// 4로 좁혀 uint64 조립·범위 검사와 합쳐 32비트에서도 int 오버플로 없이 안전 거절한다.
	maxExponentBytes = 4
)

// ErrJWKSKeyNotFound는 재페치 후에도 kid에 해당하는 키가 없음을 나타낸다(미지 kid).
// 빈 kid·페치 실패와 구분해 거절 사유를 정확히 남긴다(fail-closed).
var ErrJWKSKeyNotFound = errors.New("auth: JWKS에 해당 kid의 공개키가 없다 (미지 kid — fail-closed)")

// ErrJWKSStale은 캐시가 TTL을 넘겨 만료됐고 재페치가 갱신에 실패(storm throttle 창 안 또는
// 페치 실패)해 최신 키를 확보하지 못했음을 나타낸다. 이때 만료된 캐시의 키를 반환하면
// 회전으로 철회됐을 수 있는 키로 무기한 검증하는 fail-open이 되므로, TTL을 staleness
// 상한으로 삼아 거절한다(fail-closed).
var ErrJWKSStale = errors.New("auth: JWKS 캐시가 만료됐고 재페치가 갱신하지 못했다 (stale 키 거절 · fail-closed)")

// httpKeySet은 발급자 JWKS를 HTTPS로 페치·캐시하는 KeySet 구현이다. kid → RSA 공개키
// 맵을 캐시하고, 미지 kid나 TTL 만료 시 재페치해 키 회전을 따라간다. 동시 호출에
// 안전하며(mu), 재페치는 한 번에 하나만 나가고(fetchMu — single-flight) 최소 간격으로
// 제한된다(minRefetch — fetch storm 방지).
type httpKeySet struct {
	issuer     string        // OIDC_ISSUER — discovery base(https 강제, 뒤 슬래시 정규화)
	ttl        time.Duration // 캐시 신선도 — 지나면 known kid라도 재페치(회전 추적)
	minRefetch time.Duration // 재페치 최소 간격(fetch storm 방지)
	httpClient *http.Client
	clock      Clock

	// fetchMu는 네트워크 페치를 직렬화한다(single-flight) — 동시 미지 kid가 각자 페치를
	// 내보내지 않게. 데이터 락(mu)과 분리해, 네트워크 대기 중 캐시 조회가 막히지 않는다.
	fetchMu sync.Mutex

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey // kid → 공개키(마지막 성공 페치 결과)
	fetchedAt   time.Time                 // 마지막 성공 페치 시각(TTL 기준)
	lastAttempt time.Time                 // 마지막 페치 시도 시각(성공·실패 불문 — storm 기준)
}

// HTTPKeySetOption은 httpKeySet의 테스트·튜닝 주입점이다(http 클라이언트·시계·재페치 간격).
type HTTPKeySetOption func(*httpKeySet)

// WithHTTPClient는 페치에 쓸 http.Client를 주입한다(테스트는 httptest 서버로 향하게).
func WithHTTPClient(c *http.Client) HTTPKeySetOption {
	return func(k *httpKeySet) { k.httpClient = c }
}

// WithClock은 TTL·storm 판정에 쓸 시계를 주입한다(테스트는 고정·전진 시계로 결정론).
func WithClock(c Clock) HTTPKeySetOption {
	return func(k *httpKeySet) { k.clock = c }
}

// WithMinRefetchInterval은 미지 kid 재페치 최소 간격을 바꾼다(fetch storm 방지 튜닝).
func WithMinRefetchInterval(d time.Duration) HTTPKeySetOption {
	return func(k *httpKeySet) { k.minRefetch = d }
}

// NewHTTPKeySet은 발급자 JWKS를 HTTPS로 페치·캐시하는 KeySet을 만든다. issuer가 비었거나
// https가 아니면 오류다(fail-closed — 평문 발급자는 MITM에 노출돼 검증의 뿌리가 무너진다).
// ttl<=0도 오류다(신선도 기준이 없으면 캐시·회전 계약이 성립하지 않는다).
func NewHTTPKeySet(issuer string, ttl time.Duration, opts ...HTTPKeySetOption) (KeySet, error) {
	if err := requireHTTPS(issuer, "OIDC_ISSUER"); err != nil {
		return nil, err
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("auth: JWKS 캐시 TTL은 >0 이어야 한다 (fail-closed): %s", ttl)
	}
	ks := &httpKeySet{
		issuer:     strings.TrimRight(issuer, "/"),
		ttl:        ttl,
		minRefetch: defaultMinRefetchInterval,
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
		clock:      SystemClock{},
		keys:       map[string]*rsa.PublicKey{},
	}
	for _, o := range opts {
		o(ks)
	}
	// 리다이렉트 각 hop의 scheme을 https로 강제한다 — 정적 문자열 검사(requireHTTPS)만으론
	// https discovery/jwks_uri가 302로 http(또는 공격자 https)로 다운그레이드하는 것을 못
	// 막는다. 주입된 클라이언트(WithHTTPClient)에도 반드시 걸리도록 조립 지점에서 강제하되,
	// http.Client를 값 복사해 호출자의 클라이언트에 부작용을 주지 않는다.
	c := *ks.httpClient
	c.CheckRedirect = checkHTTPSRedirect
	ks.httpClient = &c
	return ks, nil
}

// checkHTTPSRedirect는 리다이렉트 각 hop이 https가 아니면 거절한다(평문·다운그레이드 차단 ·
// MITM 방어). CheckRedirect를 지정하면 http.Client 기본 10-hop 상한이 사라지므로 여기서
// 함께 건다(무한 리다이렉트 방어).
func checkHTTPSRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("auth: 리다이렉트가 10 hop을 넘었다 (fail-closed)")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("auth: 리다이렉트가 https가 아니다 (평문 다운그레이드 거절 · MITM 방어): scheme=%q", req.URL.Scheme)
	}
	return nil
}

// VerificationKey는 kid에 해당하는 RSA 공개키를 반환한다(KeySet 계약). 빈 kid는 페치
// 없이 즉시 거절하고, 캐시가 신선하면 반환하며, 미지 kid·만료면 재페치 후 다시 조회한다
// — 그래도 없으면 오류(fail-closed).
func (ks *httpKeySet) VerificationKey(ctx context.Context, kid string) (any, error) {
	// 빈 kid는 페치 없이 즉시 거절한다 — 키를 특정할 수 없는 요청이 발급자를 두드리게
	// 두지 않는다(남용 방어 ⓐ). RS256 GitHub OIDC 토큰은 항상 kid를 싣는다.
	if kid == "" {
		return nil, errors.New("auth: 빈 kid — 검증 키를 특정할 수 없다 (페치 없이 거절 · fail-closed)")
	}

	// 캐시가 신선하고 kid가 있으면 곧바로 반환한다(네트워크 없이).
	if key, ok := ks.cachedFresh(kid); ok {
		return key, nil
	}

	// 미지 kid이거나 캐시가 만료됐다 — 재페치로 회전을 따라간다(storm 제한 하에).
	if err := ks.refetch(ctx); err != nil {
		return nil, err
	}

	// 재페치가 nil을 냈다고 해서 "방금 신선히 페치했다"는 보장은 없다 — storm throttle
	// 창 안이면 refetch는 갱신 없이 nil을 낸다. 따라서 keys[kid]를 반환하기 전에 freshness를
	// 재확인한다: 캐시가 여전히 만료 상태면 그 키는 stale(회전으로 철회됐을 수 있다)이므로
	// 거절한다(TTL = staleness 상한 · fail-closed). fresh면 존재 여부로 판정한다 — 있으면
	// 반환, 없으면 진짜 미지 kid다.
	ks.mu.Lock()
	fresh := ks.clock.Now().Sub(ks.fetchedAt) < ks.ttl
	key, ok := ks.keys[kid]
	ks.mu.Unlock()
	if !fresh {
		return nil, ErrJWKSStale
	}
	if !ok {
		return nil, ErrJWKSKeyNotFound
	}
	return key, nil
}

// cachedFresh는 캐시가 TTL 안이고 kid가 있으면 그 키를 반환한다. 만료됐거나 미지 kid면
// (false)를 돌려 호출자가 재페치하게 한다.
func (ks *httpKeySet) cachedFresh(kid string) (*rsa.PublicKey, bool) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.clock.Now().Sub(ks.fetchedAt) >= ks.ttl {
		return nil, false // 만료 — 회전 추적을 위해 재페치
	}
	key, ok := ks.keys[kid]
	return key, ok
}

// refetch는 JWKS를 다시 페치해 캐시를 교체한다. fetchMu로 직렬화해(single-flight) 동시
// 호출이 각자 네트워크를 내보내지 않게 하고, minRefetch로 시도 빈도를 제한한다(fetch
// storm 방지). 대기 중 다른 goroutine이 방금 시도했으면 재조회로 넘어간다.
func (ks *httpKeySet) refetch(ctx context.Context) error {
	ks.fetchMu.Lock()
	defer ks.fetchMu.Unlock()

	// 이중 확인: fetchMu를 기다리는 동안 다른 goroutine이 방금 시도했다면(그 사이 minRefetch
	// 안이면) 다시 두드리지 않는다 — 캐시는 그 시도 결과를 이미 반영한다.
	ks.mu.Lock()
	now := ks.clock.Now()
	if !ks.lastAttempt.IsZero() && now.Sub(ks.lastAttempt) < ks.minRefetch {
		ks.mu.Unlock()
		return nil // storm 방지 — 최근 시도가 있었으므로 재조회로 넘어간다
	}
	ks.mu.Unlock()

	// 네트워크는 데이터 락 밖에서 한다(페치 지연이 캐시 조회를 막지 않게).
	keys, err := ks.fetchAll(ctx)

	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.lastAttempt = ks.clock.Now() // 성공·실패 불문 기록 — 실패도 storm 창을 연다
	if err != nil {
		return err // fail-closed — 페치 실패는 오류로 전파(키 갱신 없음)
	}
	ks.keys = keys
	ks.fetchedAt = ks.clock.Now()
	return nil
}

// discoveryDoc는 OIDC discovery 문서에서 우리가 쓰는 필드다(jwks_uri 하나).
type discoveryDoc struct {
	JwksURI string `json:"jwks_uri"`
}

// jwkSet·jwk는 JWKS 응답의 RSA 공개키를 담는다. RFC 7517/7518 — RSA는 modulus(n)·
// exponent(e)를 base64url로 싣고, use=sig는 서명용 키를 뜻한다.
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"` // 키 유형 — RSA만 받는다
	Use string `json:"use"` // 용도 — 있으면 sig만(enc는 건너뛴다)
	Kid string `json:"kid"` // 키 ID — 맵 키
	N   string `json:"n"`   // modulus(base64url)
	E   string `json:"e"`   // exponent(base64url)
}

// fetchAll은 discovery → JWKS 순으로 GET해 kid → RSA 공개키 맵을 만든다. 각 단계의
// https 강제·크기 상한·상태 코드 검사는 fail-closed의 일부다 — 하나라도 어긋나면 오류다.
func (ks *httpKeySet) fetchAll(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	// ⑴ discovery — issuer의 well-known에서 jwks_uri를 얻는다.
	var doc discoveryDoc
	if err := ks.getJSON(ctx, ks.issuer+wellKnownPath, &doc); err != nil {
		return nil, fmt.Errorf("OIDC discovery 실패: %w", err)
	}
	if doc.JwksURI == "" {
		return nil, errors.New("auth: discovery 문서에 jwks_uri가 없다 (fail-closed)")
	}
	// jwks_uri도 https여야 한다 — 평문 JWKS는 키 바꿔치기(MITM)에 노출된다.
	if err := requireHTTPS(doc.JwksURI, "jwks_uri"); err != nil {
		return nil, err
	}

	// ⑵ JWK Set 페치·파싱.
	var set jwkSet
	if err := ks.getJSON(ctx, doc.JwksURI, &set); err != nil {
		return nil, fmt.Errorf("JWKS 페치 실패: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue // RSA만 — EC 등 다른 kty는 이 게이트의 RS256과 무관하다
		}
		if k.Use != "" && k.Use != "sig" {
			continue // use가 명시됐고 서명용이 아니면 건너뛴다(enc 키 등)
		}
		if k.Kid == "" {
			continue // kid 없는 키는 조회 불가 — 맵에 담지 않는다
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			return nil, fmt.Errorf("JWK 파싱 실패(kid=%s): %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("auth: JWKS에 쓸 수 있는 RSA 서명 키가 없다 (fail-closed)")
	}
	return keys, nil
}

// getJSON은 url을 GET해 본문을 JSON으로 디코드한다. context·timeout(클라이언트)·크기 상한·
// 200 검사를 함께 건다 — 지연·거대·오류 응답을 fail-closed로 끊는다.
func (ks *httpKeySet) getJSON(ctx context.Context, rawURL string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("요청 생성: %w", err)
	}
	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: 상태 %d (200 아님)", rawURL, resp.StatusCode)
	}
	// 크기 상한: maxJWKSBytes+1까지 읽어 초과 여부를 판별한다(거대 응답 방어).
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("본문 읽기: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return fmt.Errorf("응답 본문이 상한(%d바이트)을 넘었다 (거대 응답 방어)", maxJWKSBytes)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("JSON 디코드: %w", err)
	}
	return nil
}

// parseRSAPublicKey는 JWK의 n·e(base64url·RawURLEncoding)를 rsa.PublicKey로 만든다.
// 외부 JWK 라이브러리 없이 stdlib로 수동 파싱한다 — n은 modulus 정수, e는 공개 지수다.
func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	if nB64 == "" || eB64 == "" {
		return nil, errors.New("RSA JWK의 n·e가 비었다")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("modulus(n) base64url 디코드: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("exponent(e) base64url 디코드: %w", err)
	}
	if len(eBytes) == 0 || len(eBytes) > maxExponentBytes {
		return nil, fmt.Errorf("exponent(e) 길이 비정상: %d바이트", len(eBytes))
	}
	// e는 빅엔디언 정수다. uint64로 조립해 조립 중 wrap을 없애고(플랫폼 int 폭 무관), int
	// 변환 전에 MaxInt32 상한을 걸어 32비트에서도 거대 e가 정상 양수로 wrap돼 통과하는 것을
	// 막는다. RSA 공개 지수는 작으므로(65537) 이 상한은 정상 키를 자르지 않는다.
	var e uint64
	for _, b := range eBytes {
		e = e<<8 | uint64(b)
	}
	if e < 2 || e > math.MaxInt32 {
		return nil, fmt.Errorf("exponent(e) 값 비정상: %d", e)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}, nil
}

// requireHTTPS는 rawURL이 https scheme인지 강제한다(평문 거절 — MITM 방어). 파싱 불가·
// http·scheme 부재는 모두 오류다(fail-closed).
func requireHTTPS(rawURL, label string) error {
	if strings.TrimSpace(rawURL) == "" {
		return fmt.Errorf("auth: %s가 비었다 (fail-closed)", label)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("auth: %s URL 파싱 실패: %w", label, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("auth: %s는 https여야 한다 (평문 거절 · MITM 방어): scheme=%q", label, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("auth: %s에 host가 없다 (fail-closed)", label)
	}
	return nil
}
