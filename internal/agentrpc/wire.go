package agentrpc

import "encoding/json"

// deployRequest는 `POST /agent/deploy`의 RPC body다. main이 marshal하고 위성이 parse한다.
// RPC 서명은 이 body 전체의 digest를 결박하므로, manifest와 token이 함께 서명 범위에 든다.
//
// Manifest는 main이 이미 CI 검증·엄격 파싱한 뒤 **재marshal한** 깨끗한 JSON이다 — 위성은
// deputy(F6)로서 CI 게이트1 서명을 재검증하지 않고, RPC 서명(위성 자기 키)만으로 "우리
// main에서 왔다"를 신뢰한 뒤 target을 추출해 자기 호스트에 실행한다.
type deployRequest struct {
	Manifest json.RawMessage `json:"manifest"`
	// FencingToken은 main coordinator가 보유한 배포 창 락 토큰이다. 조각 A의 위성 로컬
	// 실행(settlement·ledger = 단일 경로 · Gateway 없음)은 이 토큰을 쓰지 않는다 — 단계별
	// fence guard는 조각 B다. main coordinator의 실행 전 1회 Confirm이 이 슬라이스의 fencing이며,
	// 토큰은 조각 B가 붙을 자리를 위해 서명 범위에 실려 운반될 뿐이다(JSON에 실은 토큰이 곧
	// fencing은 아니다 — R6은 조각 B).
	FencingToken uint64 `json:"fencingToken"`
}

// deployResponse는 배포·상태 응답 body다. 위성이 서명하고(HeaderSignature) main이 검증한다.
// 서명은 body가 아니라 ResponseCanonical(requestId·요청bodyDigest·action·httpStatus·state·nonce)을
// 결박하므로, body 필드는 사람이 읽는 사본이자 state 전달이고 신뢰의 뿌리는 서명이다. nonce는
// body에 싣지 않는다 — main이 **자기가 보낸 nonce**로 canonical을 재구성해 검증하므로(조각 C R2
// replay 방어), 응답 body의 nonce를 신뢰할 이유가 없다(오히려 신뢰하면 replay 표면이 된다).
type deployResponse struct {
	RequestID string `json:"requestId"`
	Action    string `json:"action"`
	State     string `json:"state"`  // deploy.RemoteState 문자열(UNEXECUTED·COMPLETED·UNKNOWN)
	Detail    string `json:"detail"` // 사람이 읽는 사유(UNKNOWN 개입의 단서 — 시크릿 없음)
}
