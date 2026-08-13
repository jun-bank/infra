// Package agentrpc는 main(.9)이 위성(.158·.164)의 ROLE=agent 실행자에게 배포 명령을
// 보내는 서명 RPC 전송이다(infra#34 조각 A). 두 반쪽으로 이뤄진다:
//
//   - RemoteDispatcher (main 측): coordinator가 부르는 deploy.Dispatcher 구현. 위성에
//     `POST /agent/deploy`(manifest+token, 서명)를 보내고 **응답도 HMAC 검증**한다.
//   - Handler (위성 측): 서명된 명령을 수신·검증하고 로컬 dispatch(internal/dispatch 재사용)로
//     자기 호스트를 배포한 뒤 응답에 서명한다. crash-safe 원장이 멱등·재기동 안전을 준다.
//
// 이 슬라이스의 경계(design rev.3 조각 A · 재슬라이스로 확정):
//   - execute 정확히 1회. UNKNOWN이면 그대로 반환 — **자동 status 조회·재개는 없다**(조각 C).
//   - 위성 fencing guard·역방향 RPC·원격 lease 하한식은 **없다**(조각 B). main coordinator의
//     실행 전 1회 fencing Confirm(기존 로컬 수준)까지가 이 슬라이스의 fencing이다.
//   - 위성은 main의 deputy다(F6): CI 게이트1 서명을 **재검증하지 않고** target·digest의 CI
//     결박을 main에서 상속한다. AGENT_TARGET 결박(R5)은 **오배선 방어**이지 서명 위조 방어가
//     아니다 — RPC 서명(위성 자기 키)이 "이 명령이 우리 main에서 왔다"를 증명하는 경계다.
//
// 계약 출처(정본 — 재해석하지 않는다):
//   - ADR-027 DO-16  (원격 실행 3상태: 미실행 / 완료 / UNKNOWN)
//   - ADR-027 DO-22  (SSH 아니라 HTTP+HMAC 전송)
//   - design rev.2 R1(응답도 HMAC)·R2(보수적 미실행/UNKNOWN 경계)·R3(crash-safe 원장)·
//     R5(AGENT_TARGET 결박)·R7(background context·LAN bind) · rev.3 조각 A(재개 없음)
package agentrpc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// 서명·라우팅에 쓰는 고정 상수. 헤더·경로·action은 main 송신자와 위성 검증자가 반드시
// 같은 값을 써야 한다 — 한쪽만 바꾸면 전건 서명 불일치한다.
const (
	// HeaderSignature는 canonical HMAC-SHA256 서명(소문자 hex)을 싣는 헤더다(요청·응답 공통).
	HeaderSignature = "X-Agent-Signature"
	// HeaderTimestamp는 서명에 든 발신 Unix 초(엄격 10진)를 싣는 헤더다.
	HeaderTimestamp = "X-Agent-Timestamp"
	// HeaderRequestID는 멱등 키(manifest.requestId)를 싣는 헤더다. Idempotency-Key가 아닌
	// 전용 헤더인 이유(R2): Go http 클라이언트가 Idempotency-Key를 자동 재전송에 쓸 수 있어
	// "execute 정확히 1회"를 깬다 — 재전송 판단은 우리 원장이 소유해야 한다.
	HeaderRequestID = "X-Agent-Request-ID"
	// HeaderNonce는 main이 매 요청마다 새로 만드는 per-query CSPRNG nonce(소문자 hex)를 싣는
	// 헤더다(조각 C R2). 요청 canonical에 결박되고 위성이 응답 canonical에 그대로 결박하므로,
	// 과거 status/응답을 현재 조회·재개에 끼워 넣어도 nonce 불일치로 거절된다(replay 방어).
	// version-monotonic(main durable 저장·재기동 유실)을 이 nonce로 대체한다 — main durable 상태 불요.
	HeaderNonce = "X-Agent-Nonce"
	// HeaderAttempt는 이 배포 시도의 attempt 번호(엄격 10진)를 싣는 헤더다(조각 C R1 · H2).
	// 최초 배포=1, UNKNOWN 해소 후 재개=2다. **command digest(요청 body digest)와 분리된 축**으로
	// 서명 canonical에 결박된다 — 같은 manifest의 재개가 "다른 digest(충돌)"로 오인되지 않으면서도
	// "네트워크 중복(같은 attempt)"과는 구별된다. status 조회에는 attempt가 없다(빈 문자열).
	HeaderAttempt = "X-Agent-Attempt"

	// PathDeploy는 배포 명령 수신 경로다(POST · 부작용 있음).
	PathDeploy = "/agent/deploy"
	// PathStatus는 requestId 상태 조회 경로다(GET · 부작용 0 · 조회만 · 재개는 조각 C).
	PathStatus = "/agent/status"

	// ActionDeploy·ActionStatus는 응답 결박에 드는 action 값이다(응답 canonical 필드).
	ActionDeploy = "deploy"
	ActionStatus = "status"

	// WireAbsent는 상태 조회에서 "이 위성이 그 requestId를 본 적이 없다"를 뜻하는 **별도 wire
	// 상태**다(C8). durable-UNEXECUTED(위성이 실행했고 부작용0을 내구 증명)와 서명 계약 수준에서
	// 구분한다 — 지금(조각 A)은 RemoteDispatcher가 status를 조회하지 않아 inert하지만, 조각 C의
	// 자동 재개가 이 계약을 상속할 때 "execute보다 먼저 도착한 status 조회의 ABSENT"를
	// durable-UNEXECUTED로 오인해 재개하는 것(중복 배포)을 막는다. 서명 계약은 나중보다 지금
	// 정하는 게 싸다. deploy.RemoteState가 아니라 agentrpc wire 전용 값이다.
	WireAbsent = "ABSENT"
)

// ErrNoKey는 RPC HMAC 키가 비었거나 공백뿐일 때 반환된다 — 키 없이 서명자·검증자를 만들지
// 않는다(무서명 폴백 제거 · fail-closed). 길이만 보면 "   " 공백 키가 유효로 새므로 TrimSpace로 본다.
var ErrNoKey = errors.New("agentrpc: RPC HMAC 키가 비어 있다(공백뿐도 불가 · fail-closed)")

// ValidateKey는 키가 비었거나 공백뿐이면 오류를 낸다(NewInternalSigner와 같은 축 · C4).
func ValidateKey(key []byte) error {
	if len(bytes.TrimSpace(key)) == 0 {
		return ErrNoKey
	}
	return nil
}

// BodyDigest는 raw 바이트의 서명용 digest를 만든다: "sha256:" + 소문자 hex(sha256(raw)).
// 빈 body(nil 포함)는 sha256(빈 바이트)의 고정 digest가 되어 "body 없음"도 서명 범위에
// 명시적으로 든다(빈 body 위조 차단 · GET 요청에도 쓰인다).
func BodyDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// RequestCanonical은 요청 서명 대상 바이트열을 만든다(7필드 · 필드 사이만 "\n" · 끝 개행 없음):
//
//	<METHOD>\n<path>\n<bodyDigest>\n<requestId>\n<timestamp>\n<nonce>\n<attempt>
//
// 조각 C에서 뒤 두 필드가 붙었다: **nonce**(per-query replay 방어 · R2)와 **attempt**(재개-vs-중복
// 축 · R1·H2). attempt는 bodyDigest와 **분리된** 필드다 — 같은 manifest의 재개(attempt+1)가 요청
// body를 바꾸지 않아 command digest는 그대로이고(충돌 오인 없음), 재개 의도만 이 필드로 결박된다.
// status 조회는 attempt가 없어 빈 문자열을 넣는다(main·위성이 같은 빈 값으로 서명·검증).
//
// auth.Sign(게이트1 · 6필드)·canonical-v1(gateway · 4필드)과 **다른 전용 형식**이다 —
// 그 함수들을 부르면 전건 불일치하므로 공유는 HMAC 프리미티브(crypto/hmac·sha256)까지다.
// method는 대문자로 정규화한다(HTTP method는 대소문자 무관). main 서명자와 위성 검증자가
// **같은 Go 코드**(한 바이너리·ROLE만 다름)라 gateway#6의 Go↔Kotlin interop 문제가 없다.
func RequestCanonical(method, path, bodyDigest, requestID, timestamp, nonce, attempt string) []byte {
	return []byte(strings.ToUpper(method) + "\n" + path + "\n" + bodyDigest + "\n" +
		requestID + "\n" + timestamp + "\n" + nonce + "\n" + attempt)
}

// ResponseCanonical은 응답 서명 대상 바이트열을 만든다(R1 — 응답도 HMAC · 6필드):
//
//	<requestId>\n<requestBodyDigest>\n<action>\n<httpStatus>\n<state>\n<nonce>
//
// **요청 bodyDigest**를 응답에 결박하는 것이 핵심이다(R1): 응답이 그 요청 하나에 묶여,
// 가짜 완료·가짜 미실행(중복 배포 유발)·가짜 인증거절·다른 요청의 응답 재사용이 전부 차단된다.
// httpStatus를 넣어 프록시·중간자가 상태코드를 바꿔치기하는 것도 막는다. requestId 결박으로
// 응답이 반드시 그 요청의 것이어야 한다.
//
// **nonce**(조각 C R2)는 F7 version-monotonic을 대체한 per-query replay 방어다: 위성이 요청의
// nonce를 응답 canonical에 그대로 결박하고, main은 **자기가 보낸 nonce**로 canonical을 재구성해
// 검증한다(응답 body의 nonce를 신뢰하지 않는다). 과거 응답은 옛 nonce에 서명돼 있으므로 현재
// 조회·재개(새 nonce)에 끼워 넣으면 검증이 실패한다 — 옛 COMPLETED 응답을 재개 창에 재생하는
// 공격이 차단된다. main durable 저장 없이(재기동 유실 없음) replay를 막는다.
func ResponseCanonical(requestID, requestBodyDigest, action, httpStatus, state, nonce string) []byte {
	return []byte(requestID + "\n" + requestBodyDigest + "\n" + action + "\n" +
		httpStatus + "\n" + state + "\n" + nonce)
}

// nonceBytes는 per-query nonce의 바이트 길이다(128비트 — 조각 B confirmId와 같은 강도).
const nonceBytes = 16

// newNonce는 main이 매 status/deploy 요청마다 새로 만드는 per-query CSPRNG nonce(소문자 hex)를
// 만든다(R2 — 조각 B newConfirmID 선례 재사용). crypto/rand가 실패하면 예측 가능한 폴백을 쓰지
// 않고 오류를 낸다 — 약한 nonce로 replay 방어를 여느니 그 요청을 fail-closed로 접는다(호출자가
// UNKNOWN/미실행으로 접는다). 조각 B의 newConfirmID와 계약이 같지만(같은 강도·형식) fencing
// 도메인과 분리하기 위해 별도 함수로 둔다(조각 B 무접촉).
func newNonce() (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("agentrpc: per-query nonce용 CSPRNG 실패(fail-closed): %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Sign은 canonical 바이트열에 대한 HMAC-SHA256을 소문자 hex로 계산한다. 키는 raw 바이트다.
// 서명자·검증자가 갈라지지 않게 하는 단일 출처 — main과 위성이 같은 함수를 부른다.
func Sign(key, canonical []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify는 hex 서명이 canonical·키에 대해 유효한지 상수 시간 비교한다(hmac.Equal). 서명 hex가
// 디코드되지 않으면(형식 오류) false다 — 위조·잘림 모두 거절이며 타이밍이 새지 않는다.
func Verify(key, canonical []byte, sigHex string) bool {
	got, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write(canonical)
	return hmac.Equal(m.Sum(nil), got)
}
