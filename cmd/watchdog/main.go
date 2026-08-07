// Command watchdog는 허브(.9)에 상주하는 감시자로, agent 자기 교체의 마지막 실패
// 분기 — 교체 세션 자체가 죽는 경우 — 를 잡아낸다(ADR-027 DO-19).
//
// 계약 출처(정본):
//   - ADR-027 DO-19  (상주; 로컬 자기 교체 의도를 읽음; 이전 manifest를 단 한 번
//     복원; 어떤 요청도 받지 않음)
//   - ADR-022 §2.1   (watchdog에는 DB 계정이 주어지지 않는다 — 그래서 자기 교체
//     의도가 로컬에 남는다, DO-17 ⑷ / ADR-027 §2.2)
//
// 이것은 스캐폴드다: 아직 의도를 읽지도, 무엇을 복원하지도 않는다. 모든 TODO는 이후
// 단계가 채워야 할 계약 표면을 표시한다.
//
// 두 가지 속성이 반드시 성립하며, 여기서는 구조로써 보장된다:
//  1. watchdog에는 외부 입력 표면이 없다(수신하지 않으며, 배포 요청으로 도달할 수
//     없다) — DO-19 ⑷.
//  2. 수행할 수 있는 유일한 연산은 "이전 manifest를 재시작"이며, 한 번뿐이다 —
//     DO-19 ⑶. 배포하지 않으며 DB 자격증명을 보유하지 않는다.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "watchdog:", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Println("jun-bank watchdog (scaffold)")

	// TODO(DO-19 ⑵): 자기 교체 의도를 오직 로컬의 지속 저장소에서만 읽는다(이전
	// manifest, requestId, 데드라인). watchdog은 DB 계정을 보유하지 않으므로
	// (ADR-022 §2.1), 이 의도는 사실의 원천이 배포 스키마가 아니라 로컬인 유일한 항목이다.
	fmt.Println("  - read self-replacement intent (LOCAL only)   (no DB account)")

	// TODO(DO-19 ⑵⑶): 데드라인이 지나도록 완료 표시가 없으면, 이전 manifest를 정확히
	// 한 번만 재시작하고 그 결과를 별도의 이벤트로 기록한다.
	fmt.Println("  - on deadline miss: restore previous manifest (ONCE)")

	// 불변식(DO-19 ⑷): watchdog은 어떤 요청도 받지 않으며, 이전 manifest 재시작만
	// 수행할 수 있다. 절대 배포 경로로 확장되어서는 안 된다.
	return nil
}
