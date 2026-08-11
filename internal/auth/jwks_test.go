// httpKeySet(jwks.go)의 단위 테스트. 실 네트워크·docker 없이 httptest TLS 서버로
// 합성 discovery + 합성 JWKS + 합성 RS256 토큰을 서빙해 검증한다. https 강제 때문에
// 평문 httptest가 아니라 NewTLSServer를 쓰고, 그 서버의 신뢰 클라이언트를 주입한다.
//
// 거절·남용 방어 경로를 우선 밟는다(red-first): 빈 kid 즉시 거절·미지 kid fail-closed·
// http jwks_uri 거절·fetch storm 제한·캐시 히트. 정상 경로(유효 kid 서명 검증)도 못박아
// 과잉 거절을 잡는다.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// advClock은 주입한 시각을 반환하고 전진시킬 수 있는 테스트 시계다(TTL·storm 경계를
// 결정론적으로 밟는다). 동시 호출 테스트를 위해 잠금을 건다.
type advClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *advClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *advClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// jwksTestServer는 discovery·JWKS를 서빙하며 히트를 센다. 키 집합·실패 모드를 테스트가
// 주입해 회전·파싱 실패·discovery 실패·http jwks_uri를 재현한다.
type jwksTestServer struct {
	srv *httptest.Server

	mu            sync.Mutex
	keys          map[string]*rsa.PublicKey // kid → JWKS에 실을 공개키
	discoveryHits int
	jwksHits      int

	jwksURIOverride string // 비면 srv.URL+"/jwks"; 설정하면 그대로(http 거절 재현)
	discoveryStatus int    // 0이면 200; 아니면 그 상태로 응답(discovery 실패 재현)
	rawJWKSBody     string // 설정하면 /jwks가 이 원문을 그대로 서빙(파싱 실패 재현)
}

func newJWKSTestServer() *jwksTestServer {
	ts := &jwksTestServer{keys: map[string]*rsa.PublicKey{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", ts.handleDiscovery)
	mux.HandleFunc("/jwks", ts.handleJWKS)
	ts.srv = httptest.NewTLSServer(mux)
	return ts
}

func (ts *jwksTestServer) close() { ts.srv.Close() }

// client는 이 TLS 서버의 자기서명 인증서를 신뢰하는 http.Client다(timeout 부여).
func (ts *jwksTestServer) client() *http.Client {
	c := ts.srv.Client()
	c.Timeout = 5 * time.Second
	return c
}

func (ts *jwksTestServer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	ts.mu.Lock()
	ts.discoveryHits++
	status := ts.discoveryStatus
	jwksURI := ts.jwksURIOverride
	ts.mu.Unlock()

	if status != 0 && status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if jwksURI == "" {
		jwksURI = ts.srv.URL + "/jwks"
	}
	_ = json.NewEncoder(w).Encode(discoveryDoc{JwksURI: jwksURI})
}

func (ts *jwksTestServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	ts.mu.Lock()
	ts.jwksHits++
	raw := ts.rawJWKSBody
	keys := make(map[string]*rsa.PublicKey, len(ts.keys))
	for k, v := range ts.keys {
		keys[k] = v
	}
	ts.mu.Unlock()

	if raw != "" {
		_, _ = w.Write([]byte(raw))
		return
	}
	set := jwkSet{}
	for kid, pub := range keys {
		set.Keys = append(set.Keys, rsaToJWK(kid, pub))
	}
	_ = json.NewEncoder(w).Encode(set)
}

func (ts *jwksTestServer) setKey(kid string, pub *rsa.PublicKey) {
	ts.mu.Lock()
	ts.keys[kid] = pub
	ts.mu.Unlock()
}

func (ts *jwksTestServer) hits() (discovery, jwks int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.discoveryHits, ts.jwksHits
}

// rsaToJWK는 RSA 공개키를 JWK로 직렬화한다(n·e를 base64url RawURLEncoding으로).
func rsaToJWK(kid string, pub *rsa.PublicKey) jwk {
	return jwk{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// signWithKid는 주어진 kid로 RS256 서명한 토큰을 만든다(합성 벡터).
func signWithKid(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("테스트 토큰 서명 실패: %v", err)
	}
	return s
}

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA 키 생성 실패: %v", err)
	}
	return key
}

// newTestKeySet은 서버·시계를 주입한 httpKeySet을 만든다(TTL 기본 10분).
func newTestKeySet(t *testing.T, ts *jwksTestServer, clock Clock, opts ...HTTPKeySetOption) KeySet {
	t.Helper()
	base := []HTTPKeySetOption{WithHTTPClient(ts.client()), WithClock(clock)}
	ks, err := NewHTTPKeySet(ts.srv.URL, 10*time.Minute, append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewHTTPKeySet 오류: %v", err)
	}
	return ks
}

// TestJWKSValidKidEndToEnd는 유효 kid의 키를 페치해 실제 RS256 서명 검증이 서는지
// 엔드투엔드로 못박는다(키 반환 → jwksTokenVerifier 서명 검증 통과). claim 판정은 별개.
func TestJWKSValidKidEndToEnd(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	key := genKey(t)
	ts.setKey("kid-1", &key.PublicKey)

	clock := &advClock{t: time.Now()}
	ks := newTestKeySet(t, ts, clock)

	// 직접 조회 — 서버의 공개키가 그대로 온다.
	got, err := ks.VerificationKey(context.Background(), "kid-1")
	if err != nil {
		t.Fatalf("유효 kid 조회 실패: %v", err)
	}
	pub, ok := got.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.PublicKey.N) != 0 || pub.E != key.PublicKey.E {
		t.Fatalf("반환 키가 서버 공개키와 다르다: %+v", got)
	}

	// 엔드투엔드 — 그 개인키로 서명한 토큰이 이 KeySet으로 검증된다.
	raw := signWithKid(t, key, "kid-1", jwt.MapClaims{"iss": "x", "jti": "j1"})
	tv := NewJWKSTokenVerifier(ks)
	claims, err := tv.VerifyToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("유효 서명 토큰이 거절됐다: %v", err)
	}
	if claims.JTI != "j1" {
		t.Errorf("claim 디코드 어긋남: %+v", claims)
	}
}

// TestJWKSEmptyKidRejectedNoFetch는 빈 kid를 페치 없이 즉시 거절하는지 확인한다
// (서버 히트 0 — 키를 특정 못하는 요청이 발급자를 두드리지 못하게).
func TestJWKSEmptyKidRejectedNoFetch(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	ts.setKey("kid-1", &genKey(t).PublicKey)
	ks := newTestKeySet(t, ts, &advClock{t: time.Now()})

	if _, err := ks.VerificationKey(context.Background(), ""); err == nil {
		t.Fatal("빈 kid가 통과했다 (거절 기대)")
	}
	if d, j := ts.hits(); d != 0 || j != 0 {
		t.Errorf("빈 kid가 서버를 두드렸다: discovery=%d jwks=%d (0 기대)", d, j)
	}
}

// TestJWKSUnknownKidRefetchThenError는 미지 kid가 재페치를 유발하고, 그래도 없으면
// ErrJWKSKeyNotFound로 거절하는지 확인한다(fail-closed).
func TestJWKSUnknownKidRefetchThenError(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	ts.setKey("kid-1", &genKey(t).PublicKey)
	ks := newTestKeySet(t, ts, &advClock{t: time.Now()})

	_, err := ks.VerificationKey(context.Background(), "kid-unknown")
	if !errors.Is(err, ErrJWKSKeyNotFound) {
		t.Fatalf("미지 kid 오류가 ErrJWKSKeyNotFound가 아니다: %v", err)
	}
	if _, j := ts.hits(); j < 1 {
		t.Errorf("미지 kid가 재페치를 유발하지 않았다 (jwks 히트=%d)", j)
	}
}

// TestJWKSRotation은 서버가 새 kid를 추가하면, 미지 kid 요청이 재페치로 새 키를 집는지
// 확인한다(캐시하되 미지 kid면 재페치 = 회전 계약). 재페치는 storm 최소 간격 뒤에 선다.
func TestJWKSRotation(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	key1 := genKey(t)
	ts.setKey("kid-1", &key1.PublicKey)
	clock := &advClock{t: time.Now()}
	ks := newTestKeySet(t, ts, clock)

	if _, err := ks.VerificationKey(context.Background(), "kid-1"); err != nil {
		t.Fatalf("초기 kid-1 조회 실패: %v", err)
	}

	// 발급자가 키를 회전 — 새 kid-2 추가. storm 최소 간격을 넘겨 재페치가 서게 한다.
	key2 := genKey(t)
	ts.setKey("kid-2", &key2.PublicKey)
	clock.advance(defaultMinRefetchInterval + time.Second)

	got, err := ks.VerificationKey(context.Background(), "kid-2")
	if err != nil {
		t.Fatalf("회전된 kid-2를 재페치로 집지 못했다: %v", err)
	}
	if pub := got.(*rsa.PublicKey); pub.N.Cmp(key2.PublicKey.N) != 0 {
		t.Error("kid-2 반환 키가 새 키와 다르다")
	}
}

// TestJWKSRejectsHTTPJwksURI는 discovery가 http jwks_uri를 줄 때 거절하는지 확인한다
// (https 강제 — 평문 JWKS는 MITM에 노출된다).
func TestJWKSRejectsHTTPJwksURI(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	ts.jwksURIOverride = "http://token.actions.example/jwks" // 평문
	ks := newTestKeySet(t, ts, &advClock{t: time.Now()})

	_, err := ks.VerificationKey(context.Background(), "kid-1")
	if err == nil {
		t.Fatal("http jwks_uri가 통과했다 (https 강제 — 거절 기대)")
	}
}

// TestJWKSDiscoveryFailureFailClosed는 discovery가 실패(비-200)하면 fail-closed로
// 오류를 내는지 확인한다.
func TestJWKSDiscoveryFailureFailClosed(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	ts.discoveryStatus = http.StatusInternalServerError
	ks := newTestKeySet(t, ts, &advClock{t: time.Now()})

	if _, err := ks.VerificationKey(context.Background(), "kid-1"); err == nil {
		t.Fatal("discovery 실패인데 통과했다 (fail-closed 기대)")
	}
}

// TestJWKSParseFailure는 JWKS 본문이 깨졌으면 오류를 내는지 확인한다(무음 통과 금지).
func TestJWKSParseFailure(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	ts.rawJWKSBody = "{ this is not valid json"
	ks := newTestKeySet(t, ts, &advClock{t: time.Now()})

	if _, err := ks.VerificationKey(context.Background(), "kid-1"); err == nil {
		t.Fatal("JWKS 파싱 실패인데 통과했다 (오류 기대)")
	}
}

// TestJWKSCacheWithinTTL는 TTL 안 반복 호출이 재페치하지 않는지 확인한다(서버 히트 불변).
func TestJWKSCacheWithinTTL(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	key := genKey(t)
	ts.setKey("kid-1", &key.PublicKey)
	ks := newTestKeySet(t, ts, &advClock{t: time.Now()}) // 시계 전진 없음 → TTL 안

	if _, err := ks.VerificationKey(context.Background(), "kid-1"); err != nil {
		t.Fatalf("1차 조회 실패: %v", err)
	}
	d1, j1 := ts.hits()
	for i := 0; i < 5; i++ {
		if _, err := ks.VerificationKey(context.Background(), "kid-1"); err != nil {
			t.Fatalf("캐시 조회 실패: %v", err)
		}
	}
	d2, j2 := ts.hits()
	if d2 != d1 || j2 != j1 {
		t.Errorf("TTL 안 반복 호출이 재페치했다: discovery %d→%d jwks %d→%d", d1, d2, j1, j2)
	}
}

// TestJWKSFetchStormThrottled는 연속 미지 kid가 매번 페치하지 않는지 확인한다(storm
// 최소 간격 — 침해·오설정 시 발급자를 홍수 요청으로 두드리지 않게).
func TestJWKSFetchStormThrottled(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	ts.setKey("kid-1", &genKey(t).PublicKey)
	ks := newTestKeySet(t, ts, &advClock{t: time.Now()}) // 시계 고정 → storm 창 안

	// 1차 미지 kid → 재페치 1회.
	_, _ = ks.VerificationKey(context.Background(), "unknown-a")
	_, j1 := ts.hits()
	if j1 < 1 {
		t.Fatalf("1차 미지 kid가 페치하지 않았다 (jwks=%d)", j1)
	}
	// 2차 미지 kid(같은 시각) → storm 제한으로 추가 페치 없음.
	_, _ = ks.VerificationKey(context.Background(), "unknown-b")
	_, j2 := ts.hits()
	if j2 != j1 {
		t.Errorf("storm 제한 실패: 연속 미지 kid가 재페치했다 (jwks %d→%d)", j1, j2)
	}
}

// TestJWKSConcurrent는 동시 호출이 안전한지 확인한다(-race). 유효·미지 kid를 섞어
// 캐시 mutex·single-flight가 데이터 경합 없이 도는지 본다.
func TestJWKSConcurrent(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	key := genKey(t)
	ts.setKey("kid-1", &key.PublicKey)
	ks := newTestKeySet(t, ts, &advClock{t: time.Now()})

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			kid := "kid-1"
			if i%3 == 0 {
				kid = fmt.Sprintf("unknown-%d", i)
			}
			_, _ = ks.VerificationKey(context.Background(), kid)
		}(i)
	}
	wg.Wait()
}

// TestJWKSExpiredThrottledRejectsStale는 캐시가 TTL을 넘겨 만료됐는데 재페치가 storm
// throttle 창 안이라 갱신되지 못할 때, known kid를 stale 키로 반환하지 않고 거절하는지
// 못박는다(fail-open 방어 — TTL이 staleness 상한). 회전으로 철회됐을 수 있는 만료 키가
// outage 동안 무기한 검증되면 인증 뿌리가 fail-open이다.
func TestJWKSExpiredThrottledRejectsStale(t *testing.T) {
	ts := newJWKSTestServer()
	defer ts.close()
	key := genKey(t)
	ts.setKey("kid-1", &key.PublicKey)
	clock := &advClock{t: time.Now()}
	// TTL(1분) < minRefetch(1시간) — 만료됐지만 throttle 창 안인 상태를 만든다.
	ks, err := NewHTTPKeySet(ts.srv.URL, time.Minute,
		WithHTTPClient(ts.client()), WithClock(clock), WithMinRefetchInterval(time.Hour))
	if err != nil {
		t.Fatalf("NewHTTPKeySet 오류: %v", err)
	}

	// ⑴ 성공 경로 — 캐시 fresh면 known kid 통과.
	if _, err := ks.VerificationKey(context.Background(), "kid-1"); err != nil {
		t.Fatalf("fresh 캐시에서 kid-1 조회 실패: %v", err)
	}

	// ⑵ TTL 너머로 전진(만료) — 단 minRefetch 창 안(재페치 throttle).
	clock.advance(2 * time.Minute)
	_, err = ks.VerificationKey(context.Background(), "kid-1")
	if !errors.Is(err, ErrJWKSStale) {
		t.Fatalf("만료+throttle에서 stale 키를 거절하지 않았다: %v (ErrJWKSStale 기대)", err)
	}

	// ⑶ outage 회복 — minRefetch 창 밖으로 전진하면 재페치가 서고 다시 통과.
	clock.advance(2 * time.Hour)
	if _, err := ks.VerificationKey(context.Background(), "kid-1"); err != nil {
		t.Fatalf("회복 후 재페치가 서지 않았다: %v", err)
	}
}

// TestNewHTTPKeySetValidation은 생성 시 https·TTL 불변식을 못박는다(fail-closed 뿌리).
func TestNewHTTPKeySetValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		issuer string
		ttl    time.Duration
	}{
		{"http issuer 거절", "http://token.actions.example", time.Minute},
		{"빈 issuer 거절", "", time.Minute},
		{"scheme 없는 issuer 거절", "token.actions.example", time.Minute},
		{"TTL 0 거절", "https://token.actions.example", 0},
		{"TTL 음수 거절", "https://token.actions.example", -time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewHTTPKeySet(tc.issuer, tc.ttl); err == nil {
				t.Errorf("%s: 오류 기대인데 통과했다", tc.name)
			}
		})
	}
}
