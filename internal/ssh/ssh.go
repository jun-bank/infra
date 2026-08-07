// Package ssh는 두 배포 게이트 중 게이트 2다: 게이트 1(auth)이 통과한 뒤 세 호스트에
// 도달하는 전송 계층이다(ADR-027 DO-2/DO-3). 여기서 SSH는 인증 축이 아니다 — 서명이
// 검증된 뒤에만 열리는 전송이다.
//
// 계약 출처(정본):
//   - ADR-027 DO-3   (위성 호스트는 agent가 SSH로 적용; 위성에는 agent가 없음;
//     허브 agent가 원격 컨테이너 연산을 실행)
//   - ADR-027 DO-13  (SSH는 셸이 아니라 root 소유 dispatcher에 도달)
//   - ADR-027 DO-14  (호스트별 키; restrict + 출처 제한 + forced command;
//     host-key 고정; 엄격 검증; TOFU 없음)
//   - ADR-027 DO-16  (세 가지 원격 실행 상태: 미실행 / 완료 / UNKNOWN)
//
// DO-14 ⑸는 키를 읽는 프로세스(이 실행자 측)가 인터넷 입력을 파싱하는 프로세스
// (internal/auth)와 분리될 것을 요구한다. 이 패키지가 실행자 측이며, 키 자료를
// 보유하는 유일한 곳이어야 한다.
package ssh

import "errors"

// ErrNotImplemented는 스캐폴드 표면을 표시한다.
var ErrNotImplemented = errors.New("ssh: not implemented (scaffold)")

// Host는 배포 대상을 식별한다. DO-14 ⑴에 따라 각 호스트는 자신의 키를 가지므로,
// 유출은 단일 호스트로 한정된다; 전송 계층은 절대 하나의 키를 세 호스트에 공유해서는
// 안 된다.
type Host struct {
	Name string // core(.9 자기 자신), settlement(.158), ledger(.164), 또는 self
	// TODO(.env): 주소, 호스트별 개인 키 경로, 고정된 host key. 이 중 어느 것도
	// 커밋하지 않는다 — .env.example 참조(DO-14 ⑹: 키는 절대 이미지에 넣지 않는다).
}

// Result는 DO-16의 세 가지 원격 실행 상태를 담는다. UNKNOWN을 실패로 접어 넣어서는
// 안 된다: 그렇게 하면 (재시도 시) 이중 적용되거나, 멈춘 위성을 살아 있다고 보고하게
// 된다.
type Result int

const (
	// Unexecuted는 부작용이 전혀 없었음을 증명한다(연결/인증/dispatcher 거부).
	Unexecuted Result = iota
	// Done은 dispatcher가 지속적 완료 표시를 남겼고 우리가 그것을 읽었음을 뜻한다.
	Done
	// Unknown은 명령은 전달되었으나 응답이 유실되었음을 뜻한다. 무턱대고 재시도하지
	// 말라 — 동일한 requestId로 부작용 없는 status query를 발행한다(DO-16 ⑵). 그
	// query마저 Unknown이면, 사람에게 에스컬레이션하고 락을 유지한다.
	Unknown
)

// Transport는 SSH로 호스트에서 단일 dispatcher 액션을 실행한다. 키 자료를 읽는
// 유일한 구성요소다(DO-14 ⑸).
type Transport interface {
	// Run은 하나의 고정된 dispatcher 명령(cmd/dispatcher 참조)을 호스트에 전달하고,
	// DO-16의 세 상태 중 어느 것이 되었는지 반환한다. host-key 고정을 강제한다
	// (DO-14 ⑶: 알 수 없는 host key => 연결 실패, 절대 TOFU 아님).
	Run(host Host, command []string) (Result, error)

	// Query는 Unknown 결과를 해소하기 위해 requestId에 대한 부작용 없는 status
	// 액션을 발행한다(DO-16 ⑵). 호스트의 상태를 절대 변경하지 않는다.
	Query(host Host, requestID string) (Result, error)
}

// stubTransport는 스캐폴드 구현이다.
type stubTransport struct{}

// NewTransport는 (미구현) SSH transport를 반환한다.
func NewTransport() Transport { return stubTransport{} }

func (stubTransport) Run(Host, []string) (Result, error) {
	// TODO(DO-3, DO-13, DO-14): 엄격한 host-key 고정, 호스트별 키, dispatcher로의
	// forced command(PTY 없음, 포워딩 없음), 구조화된 명령만.
	return Unexecuted, ErrNotImplemented
}

func (stubTransport) Query(Host, string) (Result, error) {
	// TODO(DO-16 ⑵): 부작용 없는 status query; Unknown 해소에 사용.
	return Unknown, ErrNotImplemented
}
