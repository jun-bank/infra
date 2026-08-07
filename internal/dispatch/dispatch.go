// Package dispatch는 특권 실행 모듈이다 — ROLE=agent 모드가 자기 호스트에서 특권
// 조작(컨테이너·systemctl 등)을 수행할 때 쓰는 내부 실행 층이다. 구 DO-13의 root
// 소유 SSH forced-command(별도 cmd/dispatcher)를 대체해, 같은 계약을 agent 모드의
// 내부 모듈로 흡수한다(ADR-027 DO-23 ⑴).
//
// 계약 출처(정본 — 이 코드는 이를 재해석하지 않는다):
//   - ADR-027 DO-23  (특권 = .env 서버 자격 + sudo · 수용된 잔여 위험 잔여-7;
//     완화 ⑴ 실행은 열거된 명령만, raw shell·임의 flag 금지 · ⑵ 인터넷 입력은
//     서명 검증 통과 후에만 특권 경로에 닿는다 — 코드 층 경계)
//   - ADR-027 DO-16  (원격/로컬 실행 3상태: 미실행 / 완료 / UNKNOWN)
//   - ADR-029 IA-5   (허용 import는 닫힌 목록으로 리뷰가 지킨다 — Go 관용구)
//
// 이것은 자리만 잡은 스캐폴드다(빈 파일이 아니라 계약 표면). Action은 닫힌 열거이며,
// 그 밖의 값은 어떤 것도 실행되지 않는다 — 자유도를 낮추는 것이 이 모듈의 핵심이다.
// 실제 실행(sudo 경유 특권 조작)은 다음 마일스톤에서 채운다.
package dispatch

import (
	"errors"
	"fmt"
)

// ErrNotImplemented는 스캐폴드 표면을 표시한다. 실행을 성급히 연결한 호출자가 조용히
// 통과하는 대신 요란하게 실패하도록 모든 스텁이 이를 반환한다(fail-closed).
var ErrNotImplemented = errors.New("dispatch: not implemented (scaffold)")

// Action은 이 모듈이 수행할 수 있는 닫힌 연산 집합이다(DO-23 ⑴: 열거된 명령만).
// 이 집합 밖의 값은 받아들이지 않으며, raw shell·임의 flag를 위한 자리는 의도적으로
// 두지 않는다.
type Action string

const (
	ActionPull   Action = "pull"   // digest로 이미지를 pull
	ActionUp     Action = "up"     // 고정된 manifest를 compose up
	ActionDown   Action = "down"   // compose down
	ActionStatus Action = "status" // 부작용 없는 query(DO-16)
)

// allowed는 허용 Action의 닫힌 목록이다.
var allowed = map[Action]bool{
	ActionPull: true, ActionUp: true, ActionDown: true, ActionStatus: true,
}

// Valid는 act가 열거에 속하는지 보고한다.
func (a Action) Valid() bool { return allowed[a] }

// Request는 실행 모듈이 받아들이는 고정 필드 집합이다(DO-23 ⑴). 임의의 flag·볼륨·
// 환경변수·경로를 위한 필드는 두지 않는다.
type Request struct {
	Target      string // core, settlement, ledger, self 중 하나
	Act         Action
	ImageDigest string // sha256:... (DO-18: 태그가 아니라 digest로 고정)
	RequestID   string // 멱등성 키(DO-10)
}

// Dispatch는 (형태가 검증된) 요청을 실행한다. 스캐폴드: 아직 특권 조작에 연결되지
// 않았다. 호출자는 이 모듈에 닿기 전에 서명 검증을 통과시켜야 한다(DO-23 ⑵ — 코드 층
// 경계). 이 전제는 다음 마일스톤에서 타입으로 강제한다.
func Dispatch(req Request) error {
	if !req.Act.Valid() {
		return fmt.Errorf("dispatch: action not in fixed enumeration: %q", req.Act)
	}
	// TODO(DO-23, 다음 마일스톤): 열거된 명령만 sudo로 실행하고(raw shell 금지),
	// 완료를 지속적으로 기록하며(DO-16 ⓑ), status는 부작용 없이 requestId 단위로
	// 멱등이게 한다(DO-16). UNKNOWN은 재시도하지 않고 status query로 해소한다.
	return ErrNotImplemented
}
