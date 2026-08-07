// Command dispatcher는 들어오는 SSH 세션과 Docker 사이에 위치하는, root 소유의 SSH
// forced-command다(ADR-027 DO-13). SSH는 셸이 아니라 dispatcher에 도달한다.
// dispatcher는 권한을 낮추지 않는다 — 고정된 열거형 인자 집합만 받아들여 입력의
// 자유도를 낮춘다.
//
// 계약 출처(정본):
//   - ADR-027 DO-13  (root 소유; 고정 열거형 인자; raw 셸 없음)
//   - ADR-027 DO-14  (호스트별 키; restrict; host-key 고정 — SSH 계층)
//   - ADR-027 DO-16  (세 가지 원격 실행 상태; UNKNOWN에 대한 query 액션)
//
// 이것은 스캐폴드다: SSH_ORIGINAL_COMMAND를 (셸 문자열이 아니라) 구조적으로 고정
// 필드로 파싱하고, 그 형태를 검증한 뒤, 해당 액션이 아직 구현되지 않았음을 보고한다.
// 모든 TODO는 계약 표면을 표시한다.
package main

import (
	"fmt"
	"os"
	"strings"
)

// action은 dispatcher가 수행할 수 있는 닫힌 연산 집합이다. 이 집합 밖의 값은 어떤
// 것도 받아들이지 않는다(DO-13 ⑵: 고정 열거).
type action string

const (
	actionPull   action = "pull"   // digest로 이미지를 pull
	actionUp     action = "up"     // 고정된 manifest를 compose up
	actionDown   action = "down"   // compose down
	actionStatus action = "status" // 부작용 없는 query(DO-16 ⑵)
)

var allowedActions = map[action]bool{
	actionPull: true, actionUp: true, actionDown: true, actionStatus: true,
}

// request는 dispatcher가 받아들이는 고정 열거형 인자 집합이다(DO-13 ⑵).
// 임의의 Docker 플래그, 볼륨, 환경변수, compose 파일 경로를 위한 필드는 의도적으로
// 두지 않는다(DO-13 ⑷).
type request struct {
	target         string // core, settlement, ledger, self 중 하나
	act            action
	imageDigest    string // sha256:... (DO-18: 태그가 아니라 digest로 고정)
	manifestDigest string
	requestID      string // 멱등성 키(DO-10); dispatcher는 requestId 단위로 멱등(DO-16 ⑵)
}

func main() {
	// DO-13 ⑶: SSH는 요청된 명령을 SSH_ORIGINAL_COMMAND로 전달한다. 우리는 이를
	// 구조적으로(공백으로 필드를 나누고 각각 검증) 파싱하며, 절대 셸 문자열로 평가하지
	// 않는다. 대화식(SSH 없음)으로 실행되면 os.Args로 대체한다.
	raw := os.Getenv("SSH_ORIGINAL_COMMAND")
	if raw == "" && len(os.Args) > 1 {
		raw = strings.Join(os.Args[1:], " ")
	}

	req, err := parse(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dispatcher: reject:", err)
		os.Exit(2)
	}

	if err := dispatch(req); err != nil {
		fmt.Fprintln(os.Stderr, "dispatcher:", err)
		os.Exit(1)
	}
}

// parse는 raw forced-command 문자열을 검증된 request로 바꾼다. DO-13 ⑶이 요구하는
// 구조적 파서다 — 어떤 셸 메타문자도 해석하지 않는다.
func parse(raw string) (request, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return request{}, fmt.Errorf("empty command")
	}
	// TODO(DO-13 ⑵): 부작용이 발생하기 전에 정확한 인자 개수와 각 필드의 형태
	// (target 열거, action 열거, digest 형식, requestId 형식)를 검증한다. 이 스캐폴드는
	// action 위치만 인식한다.
	act := action(fields[0])
	if !allowedActions[act] {
		return request{}, fmt.Errorf("action not in fixed enumeration: %q", fields[0])
	}
	return request{act: act}, nil
}

// dispatch는 (구조적으로 검증된) 액션을 수행한다. 스캐폴드: 아직 Docker/compose에
// 연결되지 않았다.
func dispatch(req request) error {
	// TODO(DO-4): pull(digest로) / compose up / compose down / status 만.
	//   - sudo가 필요한 연산 없음(DO-4)
	//   - status는 부작용이 없고 requestId 단위로 멱등(DO-16 ⑵⑶)
	//   - 완료는 agent가 읽을 수 있도록 지속적으로 기록(DO-16 ⓑ)
	return fmt.Errorf("action %q recognized but not implemented (scaffold)", req.act)
}
