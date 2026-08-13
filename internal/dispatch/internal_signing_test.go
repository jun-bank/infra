// canonical-v1 서명자의 단위 + 골든 벡터 테스트. 게이트웨이(Kotlin) 검증기와 바이트 동일한
// canonical·HMAC hex를 만드는지가 유일한 치명 계약이다(B2 — 한쪽만 갈라지면 전건 불일치).
// 아래 goldenVectors의 canonical·sig 값은 이 Go signer가 산출한 것이며, gateway repo의
// InternalCanonicalV1GoldenTest가 **같은 상수**를 독립 재현한다(교차 repo 대조).
package dispatch

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// goldenKey는 골든 벡터 전용 키다(시크릿 아님 — 공유 테스트 벡터).
var goldenKey = []byte("golden-vector-key-not-a-secret")

// goldenVector는 canonical-v1 계약을 못박는 고정 케이스다. canonical·sig는 Go signer 산출값
// 이고, 양 repo 테스트가 이 상수를 재현한다.
type goldenVector struct {
	name       string
	method     string
	path       string
	timestamp  string
	body       string
	wantDigest string
	wantCanon  string
	wantSig    string
}

// canonical-v1 골든 벡터 3케이스(GET 조회 / POST 전환 / 빈-body 경계). ⚠️ 이 값들은
// **설계 design.md rev.2.1(R5)의 canonical-v1 규격값**이며 규격의 단일 출처는 그 문서다.
// gateway repo의 InternalCanonicalV1GoldenTest와 **바이트 동일**해야 한다 — 두 구현(Go·Kotlin)이
// 언어 경계로 갈려 있어 진짜 단일 컴파일 단위가 아니므로, 규격 문서 + 양쪽 독립 재현 + 아래
// 상수 공유로 계약을 닫는다. (Go 바이너리→Kotlin 실행의 완전 자동 교차는 언어 경계라 잔여다 —
// 대신 InternalAuthGoldenInteropTest가 Go 산출 hex를 Kotlin 필터에 먹여 통과를 실증한다.)
var goldenVectors = []goldenVector{
	{
		name:       "GET status (empty body)",
		method:     "GET",
		path:       "/internal/routes/core",
		timestamp:  "1755050000",
		body:       "",
		wantDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		wantCanon:  "GET\n/internal/routes/core\nsha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1755050000",
		wantSig:    "cd4e29bcaff88b9915f607c8ff3f9c89a7ff424c8a0d6e3f612a38bebcee71a1",
	},
	{
		name:       "POST switch (json body)",
		method:     "POST",
		path:       "/internal/routes/core/switch",
		timestamp:  "1755050000",
		body:       `{"targetSlot":"green","fencingToken":7}`,
		wantDigest: "sha256:13c0ade8002a2054041c551b3998c2ac1b93ef6e7218df154666a663b332fed6",
		wantCanon:  "POST\n/internal/routes/core/switch\nsha256:13c0ade8002a2054041c551b3998c2ac1b93ef6e7218df154666a663b332fed6\n1755050000",
		wantSig:    "b81aec98fe19ee02287a8063b6ba34729ea5987a4cd735ecb008cc76c924fabe",
	},
	{
		name:       "POST empty-body boundary + ts=1",
		method:     "POST",
		path:       "/internal/routes/core/switch",
		timestamp:  "1",
		body:       "",
		wantDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		wantCanon:  "POST\n/internal/routes/core/switch\nsha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1",
		wantSig:    "106a1e105151d164f02c8c5f0b938a39cd6d60e64e1277a3a64781ea47c96aed",
	},
}

func TestCanonicalV1GoldenVectors(t *testing.T) {
	s, err := NewInternalSigner(goldenKey)
	if err != nil {
		t.Fatalf("NewInternalSigner: %v", err)
	}
	for _, v := range goldenVectors {
		t.Run(v.name, func(t *testing.T) {
			digest := internalBodyDigest([]byte(v.body))
			if digest != v.wantDigest {
				t.Fatalf("digest=%s, want %s", digest, v.wantDigest)
			}
			canon := canonicalV1(v.method, v.path, digest, v.timestamp)
			if string(canon) != v.wantCanon {
				t.Fatalf("canonical=%q, want %q", string(canon), v.wantCanon)
			}
			sig := s.signCanonicalV1(canon)
			if sig != v.wantSig {
				t.Fatalf("sig=%s, want %s", sig, v.wantSig)
			}
		})
	}
}

// 빈 body digest는 sha256(빈 바이트)의 고정 hex다 — nil과 빈 슬라이스가 같아야 한다.
func TestInternalBodyDigestEmpty(t *testing.T) {
	const want = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := internalBodyDigest(nil); got != want {
		t.Fatalf("nil body digest=%s, want %s", got, want)
	}
	if got := internalBodyDigest([]byte{}); got != want {
		t.Fatalf("empty body digest=%s, want %s", got, want)
	}
}

// canonical-v1은 4필드 · 필드 사이만 "\n" · 끝 개행 없음 · method 대문자 정규화.
func TestCanonicalV1Shape(t *testing.T) {
	c := string(canonicalV1("get", "/p", "sha256:d", "123"))
	want := "GET\n/p\nsha256:d\n123"
	if c != want {
		t.Fatalf("canonical=%q, want %q (4필드·대문자·끝 개행 없음)", c, want)
	}
}

// signer는 키 없이 만들어지지 않는다(fail-closed · 무서명 폴백 제거). C4: 공백뿐인 키도 거부.
func TestNewInternalSignerRejectsEmptyKey(t *testing.T) {
	for _, k := range [][]byte{nil, {}, []byte("   "), []byte("\t\n"), []byte(" \t ")} {
		if _, err := NewInternalSigner(k); err == nil {
			t.Fatalf("키=%q인데 signer가 만들어졌다(fail-closed 위반 — 공백뿐 키는 키 없음과 동일)", k)
		}
	}
	// 앞뒤 공백이 있어도 실제 내용이 있으면 수락하고 키 바이트는 원문 그대로 유지한다.
	if _, err := NewInternalSigner([]byte("  k  ")); err != nil {
		t.Fatalf("내용 있는 키인데 거부: %v", err)
	}
}

// headersFor는 타임스탬프를 엄격 10진으로 만들고 서명은 그 timestamp를 canonical에 verbatim
// 으로 싣는다.
func TestHeadersForConsistency(t *testing.T) {
	s, err := NewInternalSigner(goldenKey)
	if err != nil {
		t.Fatalf("NewInternalSigner: %v", err)
	}
	sig, ts := s.headersFor("POST", "/internal/routes/core/switch", []byte(`{"targetSlot":"green","fencingToken":7}`), 1755050000)
	if ts != "1755050000" {
		t.Fatalf("timestamp=%s, want 1755050000", ts)
	}
	if sig != "b81aec98fe19ee02287a8063b6ba34729ea5987a4cd735ecb008cc76c924fabe" {
		t.Fatalf("sig=%s, 골든 벡터2와 불일치", sig)
	}
}

// signer가 배선되면 GET·POST가 실제로 canonical-v1 헤더를 붙이고, 그 서명이 서버가 받은
// 경로·본문·timestamp로 재계산한 값과 일치한다(= 게이트웨이 검증기가 통과시킬 형태).
func TestGatewayClientAttachesSignature(t *testing.T) {
	signer, err := NewInternalSigner(goldenKey)
	if err != nil {
		t.Fatalf("NewInternalSigner: %v", err)
	}

	check := func(t *testing.T, method, wantPath string, wantBody []byte, do func(c *GatewayClient) error) {
		t.Helper()
		var gotSig, gotTS, gotPath, gotMethod string
		var gotBody []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSig = r.Header.Get(HeaderInternalSignature)
			gotTS = r.Header.Get(HeaderInternalTimestamp)
			gotPath, gotMethod = r.URL.Path, r.Method
			gotBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"service":"core","activeSlot":"blue","uri":"http://x","lastAcceptedToken":1}`))
		}))
		defer srv.Close()
		c, err := NewGatewayClient(srv.URL, 2*time.Second, WithInternalSigner(signer))
		if err != nil {
			t.Fatalf("클라이언트 조립: %v", err)
		}
		if err := do(c); err != nil {
			t.Fatalf("요청 실패: %v", err)
		}
		if gotMethod != method || gotPath != wantPath {
			t.Fatalf("요청 %s %s, %s %s 기대", gotMethod, gotPath, method, wantPath)
		}
		if gotSig == "" || gotTS == "" {
			t.Fatalf("서명 헤더 누락: sig=%q ts=%q", gotSig, gotTS)
		}
		// 서버가 받은 그대로 재계산 — 클라이언트 서명이 수신 경로·본문·timestamp를 덮는지.
		digest := internalBodyDigest(gotBody)
		if len(wantBody) == 0 && len(gotBody) != 0 {
			t.Fatalf("body=%q, 빈 body 기대", gotBody)
		}
		canon := canonicalV1(method, gotPath, digest, gotTS)
		want := signer.signCanonicalV1(canon)
		if gotSig != want {
			t.Fatalf("수신 서명=%s, 재계산=%s (canonical 불일치)", gotSig, want)
		}
		if _, derr := hex.DecodeString(gotSig); derr != nil {
			t.Fatalf("서명이 hex가 아니다: %v", derr)
		}
	}

	t.Run("GET", func(t *testing.T) {
		check(t, http.MethodGet, "/internal/routes/core", nil, func(c *GatewayClient) error {
			_, err := c.ActiveSlot(context.Background())
			return err
		})
	})
	t.Run("POST", func(t *testing.T) {
		check(t, http.MethodPost, "/internal/routes/core/switch", []byte(`{"targetSlot":"green","fencingToken":7}`), func(c *GatewayClient) error {
			return c.Switch(context.Background(), "green", 7)
		})
	})
}

// signer 미배선 클라이언트는 서명 헤더를 붙이지 않는다(테스트 전용 무서명 경로 — 운영은
// main이 항상 주입한다).
func TestGatewayClientWithoutSignerSendsNoHeaders(t *testing.T) {
	var sig, ts string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get(HeaderInternalSignature)
		ts = r.Header.Get(HeaderInternalTimestamp)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"activeSlot":"blue"}`))
	}))
	defer srv.Close()
	c, err := NewGatewayClient(srv.URL, 2*time.Second)
	if err != nil {
		t.Fatalf("클라이언트 조립: %v", err)
	}
	if _, err := c.ActiveSlot(context.Background()); err != nil {
		t.Fatalf("요청 실패: %v", err)
	}
	if sig != "" || ts != "" {
		t.Fatalf("무서명 클라이언트인데 헤더가 붙었다: sig=%q ts=%q", sig, ts)
	}
}
