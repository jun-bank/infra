package agentrpc

import (
	"path/filepath"
	"testing"
)

func openTempLedger(t *testing.T) (*Ledger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.journal")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

// TestLedgerAcceptFinalizeHappy는 정상 흐름을 본다: 첫 Accept=Proceed, 같은 command 재수신=
// terminal 상태 멱등 보고(재실행 없음).
func TestLedgerAcceptFinalizeHappy(t *testing.T) {
	l, _ := openTempLedger(t)
	dec := l.Accept("req-1", "sha256:aaa")
	if !dec.Proceed {
		t.Fatalf("첫 Accept는 Proceed여야 한다: %+v", dec)
	}
	if err := l.Finalize("req-1", "sha256:aaa", StateCompleted); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	// 같은 command 재수신 = 멱등 보고(재실행 없음).
	dec2 := l.Accept("req-1", "sha256:aaa")
	if dec2.Proceed || dec2.Report != StateCompleted {
		t.Fatalf("완료된 requestId 재수신은 COMPLETED 보고여야 한다(재실행 없음): %+v", dec2)
	}
}

// TestLedgerConflict는 같은 requestId 다른 digest를 충돌로 거절함을 본다(부작용 0).
func TestLedgerConflict(t *testing.T) {
	l, _ := openTempLedger(t)
	if dec := l.Accept("req-1", "sha256:aaa"); !dec.Proceed {
		t.Fatalf("첫 Accept Proceed 기대: %+v", dec)
	}
	dec := l.Accept("req-1", "sha256:bbb")
	if !dec.Conflict {
		t.Fatalf("같은 requestId 다른 digest는 Conflict여야 한다: %+v", dec)
	}
}

// TestLedgerQuarantineOnePerTarget는 비terminal 레코드가 있는 동안 다른 requestId를 Busy로
// 거절함을 본다(target당 하나 · quarantine).
func TestLedgerQuarantineOnePerTarget(t *testing.T) {
	l, _ := openTempLedger(t)
	if dec := l.Accept("req-1", "sha256:aaa"); !dec.Proceed {
		t.Fatalf("첫 Accept Proceed 기대: %+v", dec)
	}
	// req-1이 아직 비terminal(ACCEPTED)인 동안 req-2 = Busy.
	if dec := l.Accept("req-2", "sha256:ccc"); !dec.Busy {
		t.Fatalf("선행 배포 미해소 중 새 requestId는 Busy여야 한다: %+v", dec)
	}
	// req-1이 terminal이 되면 req-2를 받는다.
	if err := l.Finalize("req-1", "sha256:aaa", StateCompleted); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if dec := l.Accept("req-2", "sha256:ccc"); !dec.Proceed {
		t.Fatalf("선행 해소 후 새 requestId는 Proceed여야 한다: %+v", dec)
	}
}

// TestLedgerRestartAcceptedIsUnknown은 R3 핵심 불변식이다: ACCEPTED 뒤 재기동(원장 재열기)하면
// 그 requestId는 **UNEXECUTED가 아니라 UNKNOWN**으로 회복된다(미실행 오인 → 중복 배포 차단).
func TestLedgerRestartAcceptedIsUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.journal")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if dec := l.Accept("req-1", "sha256:aaa"); !dec.Proceed {
		t.Fatalf("Accept Proceed 기대: %+v", dec)
	}
	// crash 시뮬레이션: terminal 없이 원장을 닫고 다시 연다(fsync된 ACCEPTED만 남는다).
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("재열기: %v", err)
	}
	t.Cleanup(func() { _ = l2.Close() })

	// Status·Accept 양쪽이 UNKNOWN을 봐야 한다.
	if st, ok := l2.Status("req-1"); !ok || st != StateUnknown {
		t.Fatalf("재기동 후 ACCEPTED는 UNKNOWN이어야 한다(미실행 아님): st=%q ok=%v", st, ok)
	}
	dec := l2.Accept("req-1", "sha256:aaa")
	if dec.Proceed || dec.Report != StateUnknown {
		t.Fatalf("재기동 후 같은 requestId 재수신은 UNKNOWN 보고여야 한다(재실행 없음): %+v", dec)
	}
}

// TestLedgerRestartResolvedReplays는 terminal까지 간 뒤 재기동하면 그 상태가 복원됨을 본다
// (journal replay — 마지막 줄이 이긴다).
func TestLedgerRestartResolvedReplays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.journal")
	l, _ := OpenLedger(path)
	l.Accept("req-1", "sha256:aaa")
	_ = l.Finalize("req-1", "sha256:aaa", StateCompleted)
	_ = l.Close()

	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("재열기: %v", err)
	}
	t.Cleanup(func() { _ = l2.Close() })
	if st, ok := l2.Status("req-1"); !ok || st != StateCompleted {
		t.Fatalf("재기동 후 COMPLETED가 복원돼야 한다: st=%q ok=%v", st, ok)
	}
}

// TestLedgerFlockExcludesSecondOpener는 파일락이 두 번째 실행자의 열기를 막음을 본다(한 실행자 선점).
func TestLedgerFlockExcludesSecondOpener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.journal")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if _, err := OpenLedger(path); err == nil {
		t.Fatal("이미 열린 원장을 두 번째 실행자가 열었다(flock 배제 실패 · target당 하나 위반)")
	}
}

// TestLedgerStatusAbsent는 본 적 없는 requestId가 (_, false)임을 본다(부작용 0 조회).
func TestLedgerStatusAbsent(t *testing.T) {
	l, _ := openTempLedger(t)
	if _, ok := l.Status("never"); ok {
		t.Fatal("본 적 없는 requestId인데 ok=true")
	}
}

// TestFinalizeRejectsNonTerminal은 Finalize에 비terminal 상태가 오면 거절함을 본다(방어).
func TestFinalizeRejectsNonTerminal(t *testing.T) {
	l, _ := openTempLedger(t)
	if err := l.Finalize("req-1", "sha256:aaa", StateAccepted); err == nil {
		t.Fatal("Finalize(ACCEPTED)인데 통과")
	}
}
