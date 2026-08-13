package agentrpc

import (
	"net/http"
	"strings"
	"testing"
)

// TestSignVerifyRoundtrip은 서명·검증이 같은 함수로 왕복하고, 키·필드가 하나라도 다르면
// 검증이 실패함을 본다(interop 단일 출처).
func TestSignVerifyRoundtrip(t *testing.T) {
	key := []byte("satellite-key-settlement")
	canonical := RequestCanonical(http.MethodPost, PathDeploy, BodyDigest([]byte("body")), "req-1", "1700000000", "nonce-a", "1")
	sig := Sign(key, canonical)
	if !Verify(key, canonical, sig) {
		t.Fatal("같은 키·canonical인데 검증 실패")
	}
	// 다른 키 = 실패(위성별 키 불일치).
	if Verify([]byte("other-key"), canonical, sig) {
		t.Fatal("다른 키인데 검증 통과(위성별 키 결박 붕괴)")
	}
	// canonical 한 필드 변조 = 실패.
	tampered := RequestCanonical(http.MethodPost, PathDeploy, BodyDigest([]byte("body")), "req-2", "1700000000", "nonce-a", "1")
	if Verify(key, tampered, sig) {
		t.Fatal("requestId 변조인데 검증 통과")
	}
}

// TestRequestCanonicalBindsNonceAndAttempt는 조각 C R1·R2·H2다: nonce·attempt가 요청 서명에
// 결박돼, 둘 중 하나만 달라도 검증이 실패함을 본다 — nonce 변조(replay)·attempt 위장(재개 사칭)이
// 서명 경계에서 걸린다. attempt는 bodyDigest와 **분리된** 필드라 body를 바꾸지 않고도 결박된다(H2).
func TestRequestCanonicalBindsNonceAndAttempt(t *testing.T) {
	key := []byte("k")
	digest := BodyDigest([]byte("same-body")) // 같은 command digest(재개도 body 불변)
	base := RequestCanonical(http.MethodPost, PathDeploy, digest, "req-1", "1700000000", "nonce-1", "1")
	sig := Sign(key, base)

	// nonce만 다르면(과거 nonce로 replay) 불일치.
	if Verify(key, RequestCanonical(http.MethodPost, PathDeploy, digest, "req-1", "1700000000", "nonce-2", "1"), sig) {
		t.Fatal("nonce 변조인데 검증 통과(R2 replay 결박 붕괴)")
	}
	// attempt만 다르면(같은 body digest로 재개 사칭) 불일치 — H2 핵심(digest 불변, attempt 결박).
	if Verify(key, RequestCanonical(http.MethodPost, PathDeploy, digest, "req-1", "1700000000", "nonce-1", "2"), sig) {
		t.Fatal("attempt 변조인데 검증 통과(H2 재개 축 결박 붕괴 — body digest만으론 재개를 못 가른다)")
	}
}

// TestVerifyRejectsMalformedSig는 hex가 아닌·빈 서명을 false로 거절함을 본다(타이밍 누출 없이).
func TestVerifyRejectsMalformedSig(t *testing.T) {
	key := []byte("k")
	canonical := RequestCanonical("GET", PathStatus, BodyDigest(nil), "r", "1", "n", "")
	for _, bad := range []string{"", "zzzz", "abc"} {
		if Verify(key, canonical, bad) {
			t.Fatalf("잘못된 서명 hex(%q)인데 통과", bad)
		}
	}
}

// TestResponseCanonicalBindsRequest는 응답 canonical이 요청 bodyDigest·status·state에 결박됨을
// 본다(R1) — 하나라도 다르면 서명이 달라져 응답 재사용·변조가 차단된다.
func TestResponseCanonicalBindsRequest(t *testing.T) {
	key := []byte("k")
	base := ResponseCanonical("req-1", "sha256:aaa", ActionDeploy, "200", "COMPLETED", "nonce-1")
	sig := Sign(key, base)

	// 요청 digest가 다르면(다른 요청의 응답 재사용) 불일치.
	if Verify(key, ResponseCanonical("req-1", "sha256:bbb", ActionDeploy, "200", "COMPLETED", "nonce-1"), sig) {
		t.Fatal("요청 bodyDigest 결박이 깨졌다")
	}
	// status 변조(200→500)면 불일치.
	if Verify(key, ResponseCanonical("req-1", "sha256:aaa", ActionDeploy, "500", "COMPLETED", "nonce-1"), sig) {
		t.Fatal("httpStatus 결박이 깨졌다")
	}
	// state 변조(COMPLETED→UNEXECUTED = 가짜 미실행 → 중복 배포 유발)면 불일치.
	if Verify(key, ResponseCanonical("req-1", "sha256:aaa", ActionDeploy, "200", "UNEXECUTED", "nonce-1"), sig) {
		t.Fatal("state 결박이 깨졌다(가짜 미실행 차단 실패)")
	}
	// nonce 변조(과거 응답 replay — 다른 조회의 nonce로 위장)면 불일치(조각 C R2).
	if Verify(key, ResponseCanonical("req-1", "sha256:aaa", ActionDeploy, "200", "COMPLETED", "nonce-2"), sig) {
		t.Fatal("nonce 결박이 깨졌다(과거 응답 replay 차단 실패 — R2)")
	}
}

// TestBodyDigestEmptyStable은 빈 body digest가 sha256(빈 바이트) 고정값임을 본다(GET·빈 body 서명).
func TestBodyDigestEmptyStable(t *testing.T) {
	if got := BodyDigest(nil); got != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("빈 body digest 고정값 불일치: %s", got)
	}
	if !strings.HasPrefix(BodyDigest([]byte("x")), "sha256:") {
		t.Fatal("digest는 sha256: 접두여야 한다")
	}
}

// TestValidateKey는 빈·공백 키를 거절함을 본다(fail-closed).
func TestValidateKey(t *testing.T) {
	for _, bad := range [][]byte{nil, {}, []byte("   "), []byte("\t\n")} {
		if err := ValidateKey(bad); err == nil {
			t.Fatalf("빈·공백 키(%q)인데 통과", bad)
		}
	}
	if err := ValidateKey([]byte("k")); err != nil {
		t.Fatalf("유효 키인데 거절: %v", err)
	}
}
