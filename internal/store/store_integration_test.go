//go:build integration

// 배포 스키마 프로시저 계약(ADR-022 DT-9..DT-12, §6; ADR-024 §2.4)을 위한 통합 테스트
// 골격. 이 케이스들은 store를 인메모리 대체물이 아니라 실제 MySQL에 대해 검증한다 —
// 트랜잭션 경계, 원자성, grant 강제는 바로 인메모리 페이크가 확인할 수 없는 것들이다
// (test-strategy L1 하한). `integration` 태그로 기본 빌드에서 제외되며; 다음 단계에서
// Testcontainers MySQL에 연결하고 Skip을 제거한다.
//
// 아래 케이스들은 DDL을 작성하는 동안 이미 MySQL 8에 대해 손으로 스모크 검증했다;
// 이 파일은 그것들이 반복 가능해지는 표면이다.
package store

import (
	"context"
	"testing"
)

// TestLockContract는 일곱 개 전이와 그 불변식을 다룬다.
//
// 케이스(연결되면 각각 하나의 서브테스트):
//   - 비어 있는 락에 대한 acquire는 ok와 token=N을 반환한다; 동시에 두 번째 acquire는
//     ok=false를 반환한다(양방향 경합, 정확히 한 승자 — DT-12, R6).
//   - fencing token은 release/재획득에 걸쳐 단조 증가하며 절대 리셋되지 않는다.
//   - renew는 lease가 살아 있는 현재 holder(kind+id+token)에 대해서만 성공한다.
//   - release는 현재 holder에 대해서만 성공한다; 토큰은 리셋되지 않고; open-debt는
//     release로 지워지지 않는다.
//   - deploy_window_lock에 대한 raw UPDATE/DELETE는 두 계정 모두에 거부된다(DT-12);
//     store는 그것을 발행할 수 있는 메서드를 노출하지 않는다.
func TestLockContract(t *testing.T) {
	t.Skip("integration scaffold: wire to Testcontainers MySQL in the next step")
	_ = context.Background()
	_ = New()
}

// TestHandshake는 ADR-024 §2.4 "정지 후 인계" 긴급 롤백 인계를 다룬다.
//
// 케이스:
//   - record-preempt는 batch holder가 그대로 남은 채 행을 표시한다.
//   - ack 이전의 override-acquire는 실패한다(롤백은 시작되어서는 안 된다 — R9 ⑷).
//   - safety-boundary ack 이후, override-acquire는 새롭고 더 높은 fencing token으로
//     성공하며 open-debt는 0으로 유지된다(깨끗한 ack 경로).
//   - ack 없이 lease 만료를 통한 override는 open-debt를 설정한다; resolve-open-debt
//     (cutoff 전용)가 그것을 지운다; 그 전까지는 영업일을 마감할 수 없다.
//   - 호출자별 EXECUTE 분리: agent는 ack/resolve를 호출할 수 없고; cutoff는
//     preempt/override를 호출할 수 없다(DB grant에서 거부).
func TestHandshake(t *testing.T) {
	t.Skip("integration scaffold: wire to Testcontainers MySQL in the next step")
}

// TestReplayAndAppendOnly는 DO-10 재생 방어와 DT-12 append-only를 다룬다.
//
// 케이스:
//   - 동일 requestId를 두 번 reserve -> ErrReplay(INSERT 시점의 UNIQUE); 이를
//     우회하려 행을 삭제할 수 없다(append-only).
//   - 재사용된 jti를 reserve -> ErrReplay.
//   - history, ledger, mode에 대한 UPDATE/DELETE는 writer 계정에 거부된다.
//   - SQL SECURITY DEFINER는 EXECUTE 전용 계정이 직접 권한이 없는 락 테이블을
//     변경하는 전이를 실행할 수 있게 한다(CDV-19 / R8).
func TestReplayAndAppendOnly(t *testing.T) {
	t.Skip("integration scaffold: wire to Testcontainers MySQL in the next step")
}
