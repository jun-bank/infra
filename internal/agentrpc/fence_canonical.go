package agentrpc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
)

// 위성 fence-confirm의 서명 형식·wire 타입(infra#37 조각 B · G-1 replay 방어). 배포용
// RequestCanonical/ResponseCanonical과 **완전히 별도 함수·도메인**이다(조각 C가 그 두 함수에
// nonce·attempt를 더했어도 이 파일은 무관·불변) — 이 파일은 crypto/hmac·sha256 프리미티브와
// 위성별 키만 재사용한다(Sign/Verify/BodyDigest).
//
// 왜 별도 canonical인가(치명 G-1): 조각 A의 응답 canonical은 같은 requestId+digest면 매번
// 동일한 바이트열을 서명한다. 그래서 락 상실 **전**에 서명된 HELD 응답을 가로채 두었다가
// 락 상실 **후** 재사용하면(replay) 위성이 그것을 유효 HELD로 받아 stale mutation을 계속할 수
// 있다. 이를 막으려면 매 확인이 **일회용 nonce**에 결박돼야 한다:
//   - 매 mutation마다 CSPRNG confirmId를 새로 만든다(예측·재사용 불가).
//   - 요청은 confirmId를 결박하고, 응답은 그 요청의 digest+confirmId+판정을 결박한다.
//   - 과거 HELD 응답의 confirmId는 새 요청의 confirmId와 다르므로, 그 응답을 현재 확인에
//     끼워 넣어도 검증이 실패한다(응답이 그 한 번의 확인에만 묶인다).
//
// 도메인 리터럴(fenceReqDomain·fenceRespDomain)은 이 서명을 조각 A deploy 서명과 **교차
// 프로토콜로 뒤섞지 못하게** 하는 도메인 분리다 — 같은 위성 키로 서명하더라도 deploy 응답을
// fence 응답으로, 혹은 그 반대로 재해석할 수 없다(서명 대상 바이트의 첫 필드가 도메인이다).

const (
	// PathFenceConfirm은 main의 **별도** fence-confirm 수신 경로다(G-5 · CI /deploy와 분리).
	PathFenceConfirm = "/fence/confirm"

	// fenceReqDomain·fenceRespDomain은 서명 대상의 첫 필드에 박히는 도메인 리터럴이다(방향/domain
	// 결박 · G-1). 요청(위성→main)과 응답(main→위성)이 서로 다른 도메인이라, 한 방향의 서명을
	// 반대 방향으로 재사용할 수 없다.
	fenceReqDomain  = "jun-bank/fence-confirm/request/v1"
	fenceRespDomain = "jun-bank/fence-confirm/response/v1"

	// FenceVerdictHeld는 main이 "그 token·holder의 lease가 DB시각 기준 살아있다"를 서명한 판정이다
	// (mutation 허가). 이 값이 서명 검증까지 통과했을 때에만 위성이 mutation을 진행한다.
	FenceVerdictHeld = "HELD"
	// FenceVerdictStale은 "살아있지 않다(만료·인계·holder/token 불일치)" 또는 판정 불가(오류·부재)를
	// 뜻하는 판정이다 — 위성은 이것(또는 검증 실패·전송 실패)을 전부 deny로 접는다(fail-closed).
	FenceVerdictStale = "STALE"

	// confirmIDBytes는 CSPRNG confirmId의 바이트 길이다(128비트 — nonce로 충분히 유일).
	confirmIDBytes = 16
)

// newConfirmID는 매 mutation마다 새 일회용 nonce(소문자 hex)를 만든다(G-1). crypto/rand가
// 실패하면 예측 가능한 폴백을 쓰지 않고 오류를 낸다 — 약한 nonce로 replay 방어를 여느니
// 그 mutation을 fail-closed로 막는다(호출자가 fence deny로 접는다).
func newConfirmID() (string, error) {
	b := make([]byte, confirmIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("agentrpc: fence confirmId용 CSPRNG 실패(fail-closed): %w", err)
	}
	return hex.EncodeToString(b), nil
}

// FenceRequestCanonicalV1은 위성→main fence 요청의 서명 대상 바이트열이다(6필드 · 필드 사이만
// "\n" · 끝 개행 없음):
//
//	<도메인>\n<target>\n<requestId>\n<token(10진)>\n<confirmId>\n<issuedAt(10진)>
//
// target은 main이 위성별 키를 고르는 축이자 결박 대상이다. token은 이 확인이 묻는 fencing
// token이다. confirmId는 이 mutation 한 번의 일회용 nonce다(replay 방어의 핵). issuedAt은
// 신선도 창(main freshOK)의 입력이다. 조각 A RequestCanonical과 필드·순서·도메인이 모두
// 달라 서명이 절대 겹치지 않는다.
func FenceRequestCanonicalV1(target, requestID string, token uint64, confirmID string, issuedAt int64) []byte {
	return []byte(fenceReqDomain + "\n" + target + "\n" + requestID + "\n" +
		strconv.FormatUint(token, 10) + "\n" + confirmID + "\n" + strconv.FormatInt(issuedAt, 10))
}

// FenceResponseCanonicalV1은 main→위성 fence 응답의 서명 대상 바이트열이다(4필드):
//
//	<도메인>\n<요청bodyDigest>\n<confirmId>\n<verdict>
//
// **요청 bodyDigest**를 결박해 응답이 그 요청 하나에 묶이고, **confirmId**를 결박해 그
// 한 번의 확인에만 유효하며(과거 응답 replay 무효), **verdict**를 결박해 HELD/STALE 변조를
// 막는다. requestId·token은 요청 digest 안에 이미 들어 있으므로(요청 body가 그 필드를 담는다)
// 응답에는 digest로 한 번에 결박한다.
func FenceResponseCanonicalV1(requestBodyDigest, confirmID, verdict string) []byte {
	return []byte(fenceRespDomain + "\n" + requestBodyDigest + "\n" + confirmID + "\n" + verdict)
}

// fenceRequest는 `POST /fence/confirm`의 body다. 위성이 marshal·서명하고 main이 parse·검증한다.
// 서명(FenceRequestCanonicalV1)이 이 필드들을 결박하므로, body 필드는 서명 대상과 반드시 같은
// 값이어야 한다(다르면 검증 실패). issuedAt은 헤더 timestamp와 같은 값을 싣는다(신선도 창).
type fenceRequest struct {
	Target    string `json:"target"`
	RequestID string `json:"requestId"`
	Token     uint64 `json:"token"`
	ConfirmID string `json:"confirmId"`
	IssuedAt  int64  `json:"issuedAt"`
}

// fenceResponse는 fence-confirm 응답 body다. main이 서명하고(HeaderSignature) 위성이 검증한다.
// 신뢰의 뿌리는 서명(FenceResponseCanonicalV1)이며 body 필드는 사람이 읽는 사본이자 verdict
// 전달이다. detail에는 시크릿을 담지 않는다(로그·응답 노출 금지).
type fenceResponse struct {
	RequestID string `json:"requestId"`
	ConfirmID string `json:"confirmId"`
	Verdict   string `json:"verdict"`
	Detail    string `json:"detail"`
}
