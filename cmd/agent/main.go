// Command agent는 Oracle 엣지 뒤에 위치해 이미 존재하는 SSH 채널을 통해 세 호스트에
// 배포를 적용하는 deploy-agent다.
//
// 계약 출처(정본 — 이 코드는 이를 재해석하지 않는다):
//   - ADR-027 DO-1..DO-20  (배포 오케스트레이션; 두 개의 게이트: 서명 이후 SSH)
//   - ADR-024 §2.1..§2.4    (릴리스 전략; 블루-그린, 모드, override)
//   - ADR-022 DT-9..DT-12   (배포 스키마가 지속적 사실의 원천)
//
// 이것은 스캐폴드다: main은 아직 아무것도 연결하지 않으며, 자신이 소유할 순서 있는
// 계약 지점을 출력한 뒤 정상 종료한다. 아래의 모든 TODO는 이후 단계에서 구현해야 할
// 계약 표면을 표시한다.
package main

import (
	"fmt"
	"os"
)

// listenAddr는 LAN 측에 바인딩되는 허브 수신 주소다(ADR-027 DO-1: 외부 진입점은
// 엣지이며, agent 자체는 엣지/LAN을 통해서만 도달된다).
// 구체적인 주소와 포트는 절대 커밋하지 않는다 — 환경변수에서 온다(.env.example 참조).
// 이것은 공개 저장소다.
//
// TODO(DO-15 ⑺): LAN/엣지 출처만 바인딩하고, 직접 우회는 거부한다.
func listenAddr() string {
	if a := os.Getenv("AGENT_LISTEN_ADDR"); a != "" {
		return a
	}
	return "(unset: set AGENT_LISTEN_ADDR in .env)"
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

func run() error {
	// agent가 소유하는 순서 있는 계약 지점. 각각은 이후 구현 단계가 채워야 할 게이트
	// 또는 스텝이며, 그 순서 자체가 안전 속성이다(서명 게이트를 통과하지 못한 요청은
	// 절대 SSH에 도달해서는 안 된다 — DO-2).
	fmt.Println("jun-bank deploy-agent (scaffold)")
	fmt.Println("listen:", listenAddr())
	fmt.Println("contract points (unimplemented):")

	// TODO(DO-2, DO-10): 게이트 1 — 정규화된 (method, path, body digest, requestId,
	// issuedAt/expiresAt)에 대한 HMAC 서명 검증. 실패 시 거부 후 기록(RL-8, 예외 없음).
	// internal/auth 참조.
	fmt.Println("  - gate 1: HMAC signature + freshness/idempotency  (internal/auth)")

	// TODO(DO-11): 게이트 1b — OIDC 클레임 매트릭스(HMAC과 AND). 하나라도 불일치하면
	// 거부 후 기록. internal/auth 참조.
	fmt.Println("  - gate 1b: OIDC claim matrix                       (internal/auth)")

	// TODO(DO-17 ⑷): 모드는 fail-closed다. 배포 스키마를 읽을 수 없거나 mode 행이
	// 없거나 손상되었으면 자동 배포하지 않는다(운영/승인 모드로 취급). internal/store 참조.
	fmt.Println("  - mode: fail-closed (default operational)          (internal/store)")

	// TODO(CD-3 / DT-9): 전이 프로시저를 통해 배포 윈도우 락을 원자적으로 획득하되,
	// requestId/jti 예약과 mode-version 확인을 한 트랜잭션 안에서 함께 수행한다.
	// internal/store 참조.
	fmt.Println("  - lock: acquire deployment-window lock             (internal/store)")

	// TODO(CD-4 / DO-4): 적용 시퀀스 — 이미지 pull(digest로) -> compose up ->
	// 헬스 판정 -> switch -> compose down -> 이력. internal/deploy 참조.
	fmt.Println("  - apply: CD-4 ordered sequence                     (internal/deploy)")

	// TODO(DO-3): 위성 호스트는 agent가 SSH로 적용한다. 게이트 2는 SSH 키이며,
	// 게이트 1을 통과한 뒤에야 도달한다. internal/ssh 참조.
	fmt.Println("  - gate 2: SSH transport to satellites              (internal/ssh)")

	// TODO(DO-8): agent는 자기 자신을 자기 교체를 위한 원격 대상으로 취급하므로,
	// agent 프로세스가 내려가더라도 sshd 세션은 완료된다.
	fmt.Println("  - self-replacement: agent as a remote target       (internal/ssh)")

	return nil
}
