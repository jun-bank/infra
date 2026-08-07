// 모드 판정의 단위 테스트(DO-5·DO-17). 거절/안전 경로를 우선 밟는다 — 승인 게이트가
// 장애로 열리는 것(fail-open)이 이 판정의 치명적 실패이기 때문이다:
//   - dev = 자동, operational = 승인 필요 (ADR-024 §2.2).
//   - 저장 접근 실패·mode 부재·손상 = operational로 닫힘 (fail-closed, DO-17 ⑷).
//   - 수락 후 version이 바뀌면(진행 중 토글) 적용 직전 검증이 거절 (race, DO-17 ⑵).
//
// ModeReader는 인메모리 페이크로 대체한다 — 판정 자체는 순수 로직이며, 실 SQL 계약
// (Current의 최신 행 선택·ErrNoMode·append-only)은 store 통합 테스트가 진다.
package deploy

import (
	"context"
	"errors"
	"testing"

	"github.com/jun-bank/infra/internal/store"
)

// fakeModeReader는 대상별 (mode, version) 또는 오류를 돌려주는 인메모리 ModeReader다.
type fakeModeReader struct {
	mode    string
	version uint64
	err     error
}

func (f fakeModeReader) Current(context.Context, string) (string, uint64, error) {
	return f.mode, f.version, f.err
}

func TestDecideMode_Dev(t *testing.T) {
	d := DecideMode(context.Background(), fakeModeReader{mode: "dev", version: 7}, "core")
	if d.Mode != ModeDev || d.ApprovalRequired || d.FailClosed {
		t.Fatalf("dev: %+v — 자동 진행(승인 불필요·닫힘 아님) 기대", d)
	}
	if d.Version != 7 {
		t.Fatalf("dev: version = %d, 7 기대 (원자 검증 기준값)", d.Version)
	}
}

func TestDecideMode_Operational(t *testing.T) {
	d := DecideMode(context.Background(), fakeModeReader{mode: "operational", version: 3}, "ledger")
	if d.Mode != ModeOperational || !d.ApprovalRequired {
		t.Fatalf("operational: %+v — 승인 필요 기대", d)
	}
	if d.FailClosed {
		t.Fatalf("operational: 정상 판정인데 FailClosed로 표시됐다 — %+v", d)
	}
	if d.Version != 3 {
		t.Fatalf("operational: version = %d, 3 기대", d.Version)
	}
}

// 저장 접근 실패(연결·권한 오류 등)는 operational로 닫는다 — 자동으로 열지 않는다.
func TestDecideMode_FailClosedOnReadError(t *testing.T) {
	d := DecideMode(context.Background(), fakeModeReader{err: errors.New("db 접근 불가")}, "core")
	if d.Mode != ModeOperational || !d.ApprovalRequired || !d.FailClosed {
		t.Fatalf("읽기 실패: %+v — operational·승인 필요·FailClosed 기대(fail-closed)", d)
	}
}

// mode 행이 아예 없으면(ErrNoMode) operational로 닫는다 — "모르면 dev"가 아니다.
func TestDecideMode_FailClosedOnNoMode(t *testing.T) {
	d := DecideMode(context.Background(), fakeModeReader{err: store.ErrNoMode}, "settlement")
	if d.Mode != ModeOperational || !d.ApprovalRequired || !d.FailClosed {
		t.Fatalf("mode 부재: %+v — operational·FailClosed 기대", d)
	}
}

// 닫힌 집합 밖의 mode 문자열은 손상으로 보고 operational로 닫는다.
func TestDecideMode_FailClosedOnUnknownMode(t *testing.T) {
	d := DecideMode(context.Background(), fakeModeReader{mode: "staging", version: 1}, "core")
	if d.Mode != ModeOperational || !d.ApprovalRequired || !d.FailClosed {
		t.Fatalf("미지의 mode: %+v — operational·FailClosed 기대", d)
	}
}

func TestVerifyModeUnchanged_Same(t *testing.T) {
	v := VerifyModeUnchanged(context.Background(), fakeModeReader{mode: "operational", version: 5}, "core", 5)
	if !v.OK || v.FailClosed {
		t.Fatalf("동일 version: %+v — OK 기대(진행 허용)", v)
	}
}

// 요청 수락(version=5) 뒤 적용 직전 토글로 version이 6이 되면 거절 — 토글-요청 race.
func TestVerifyModeUnchanged_ChangedRejects(t *testing.T) {
	v := VerifyModeUnchanged(context.Background(), fakeModeReader{mode: "dev", version: 6}, "core", 5)
	if v.OK {
		t.Fatalf("version 변경(5→6): %+v — 거절(OK=false) 기대(race 차단)", v)
	}
	if v.CurrentVersion != 6 {
		t.Fatalf("거절 기록용 CurrentVersion = %d, 6 기대", v.CurrentVersion)
	}
}

// 적용 직전 검증에서 저장 접근이 실패하면 거절한다 — 검증 못 하는 채로 열지 않는다.
func TestVerifyModeUnchanged_FailClosedOnError(t *testing.T) {
	v := VerifyModeUnchanged(context.Background(), fakeModeReader{err: errors.New("db 접근 불가")}, "core", 5)
	if v.OK || !v.FailClosed {
		t.Fatalf("검증 중 읽기 실패: %+v — 거절·FailClosed 기대", v)
	}
}

// version은 그대로여도 mode 문자열이 손상(닫힌 집합 밖)되면 거절한다 — DecideMode의
// 손상=fail-closed 계약과 일관. version만 대조하고 mode를 버리면, version이 안 바뀐 채
// mode가 미지 값으로 손상됐을 때 OK=true로 새어 승인 게이트가 장애로 열린다.
func TestVerifyModeUnchanged_FailClosedOnCorruptMode(t *testing.T) {
	v := VerifyModeUnchanged(context.Background(), fakeModeReader{mode: "staging", version: 5}, "core", 5)
	if v.OK || !v.FailClosed {
		t.Fatalf("손상된 mode(version 동일): %+v — 거절·FailClosed 기대(fail-closed)", v)
	}
	if v.CurrentVersion != 5 {
		t.Fatalf("거절 기록용 CurrentVersion = %d, 5 기대", v.CurrentVersion)
	}
}
