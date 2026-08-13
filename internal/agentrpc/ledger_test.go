package agentrpc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// errTestDirSync는 dir fsync 실패 주입용 센티넬이다.
var errTestDirSync = errors.New("test: dir sync fail")

// openTempLedger는 journal·lock을 같은 temp 디렉터리에 두고 원장을 연다(단위 테스트용).
func openTempLedger(t *testing.T) (*Ledger, string) {
	t.Helper()
	dir := t.TempDir()
	journal := filepath.Join(dir, "ledger.journal")
	lock := filepath.Join(dir, "ledger.lock")
	l, err := OpenLedger(journal, lock)
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, journal
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
	dir := t.TempDir()
	journal, lock := filepath.Join(dir, "j"), filepath.Join(dir, "l")
	l, err := OpenLedger(journal, lock)
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
	l2, err := OpenLedger(journal, lock)
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
	dir := t.TempDir()
	journal, lock := filepath.Join(dir, "j"), filepath.Join(dir, "l")
	l, _ := OpenLedger(journal, lock)
	l.Accept("req-1", "sha256:aaa")
	_ = l.Finalize("req-1", "sha256:aaa", StateCompleted)
	_ = l.Close()

	l2, err := OpenLedger(journal, lock)
	if err != nil {
		t.Fatalf("재열기: %v", err)
	}
	t.Cleanup(func() { _ = l2.Close() })
	if st, ok := l2.Status("req-1"); !ok || st != StateCompleted {
		t.Fatalf("재기동 후 COMPLETED가 복원돼야 한다: st=%q ok=%v", st, ok)
	}
}

// TestLedgerLockExcludesSameTargetDifferentJournal은 C3 핵심이다: 같은 target 파생 lock 경로면
// **journal 경로가 달라도** 두 번째 실행자가 배제된다(경로 우회로 target당 1을 깨지 못한다).
func TestLedgerLockExcludesSameTargetDifferentJournal(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "settlement.lock") // target 파생 고정 lock
	l1, err := OpenLedger(filepath.Join(dir, "journalA"), lock)
	if err != nil {
		t.Fatalf("첫 OpenLedger: %v", err)
	}
	t.Cleanup(func() { _ = l1.Close() })
	// 다른 journal 경로지만 같은 lock — 두 번째는 배제돼야 한다.
	if l2, err := OpenLedger(filepath.Join(dir, "journalB"), lock); err == nil {
		_ = l2.Close()
		t.Fatal("같은 target lock인데 다른 journal 경로로 두 번째 실행자가 열렸다(C3 · target당 하나 붕괴)")
	}
	// 첫 실행자가 닫으면 다시 열린다(락 해제).
	_ = l1.Close()
	l3, err := OpenLedger(filepath.Join(dir, "journalB"), lock)
	if err != nil {
		t.Fatalf("락 해제 후 재열기 실패: %v", err)
	}
	_ = l3.Close()
}

// TestLedgerSyncsParentDirEveryOpen은 C5다: 부모 디렉터리 fsync를 **매 OpenLedger마다** 함을
// 본다(최초 생성에만 하면 생성 시 fsync 실패가 한 번의 재시작으로 우회되기 때문 · 멱등).
func TestLedgerSyncsParentDirEveryOpen(t *testing.T) {
	dir := t.TempDir()
	journal, lock := filepath.Join(dir, "j"), filepath.Join(dir, "l")

	orig := syncDir
	t.Cleanup(func() { syncDir = orig })
	var calls int
	syncDir = func(d string) error { calls++; return orig(d) }

	l, err := OpenLedger(journal, lock)
	if err != nil {
		t.Fatalf("최초 OpenLedger: %v", err)
	}
	if calls != 1 {
		t.Fatalf("최초 open 시 부모 디렉터리 fsync 1회여야 한다: calls=%d", calls)
	}
	_ = l.Close()

	l2, err := OpenLedger(journal, lock) // 이미 존재해도 다시 fsync
	if err != nil {
		t.Fatalf("재열기: %v", err)
	}
	t.Cleanup(func() { _ = l2.Close() })
	if calls != 2 {
		t.Fatalf("재열기 시에도 부모 디렉터리 fsync를 해야 한다(매 open · 우회 방지): calls=%d", calls)
	}
}

// TestLedgerDirSyncFailFailsClosed는 dir fsync 실패 시 기동을 거부함을 본다(fail-closed).
func TestLedgerDirSyncFailFailsClosed(t *testing.T) {
	dir := t.TempDir()
	journal, lock := filepath.Join(dir, "j"), filepath.Join(dir, "l")
	orig := syncDir
	t.Cleanup(func() { syncDir = orig })
	syncDir = func(string) error { return errTestDirSync }
	if l, err := OpenLedger(journal, lock); err == nil {
		_ = l.Close()
		t.Fatal("dir fsync 실패인데 기동됐다(fail-closed 위반)")
	}
}

// TestLedgerTornTailTolerated는 C6다: 마지막 줄이 개행 없이 잘린 원장(정상 crash 결과)을 열면
// 그 줄만 버리고 진행하며, 이전 ACCEPTED는 UNKNOWN으로 회복됨을 본다(기동 거부 아님).
func TestLedgerTornTailTolerated(t *testing.T) {
	dir := t.TempDir()
	journal, lock := filepath.Join(dir, "j"), filepath.Join(dir, "l")
	// 완전한 ACCEPTED 한 줄 + 개행 없이 잘린 부분 줄(torn tail).
	content := `{"requestId":"req-1","digest":"sha256:aaa","state":"ACCEPTED","ts":"t"}` + "\n" + `{"requestId":"req-2","dig`
	if err := os.WriteFile(journal, []byte(content), 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	firstLine := `{"requestId":"req-1","digest":"sha256:aaa","state":"ACCEPTED","ts":"t"}` + "\n"
	l, err := OpenLedger(journal, lock)
	if err != nil {
		t.Fatalf("torn tail은 관용돼야 한다(기동 거부 아님): %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if st, ok := l.Status("req-1"); !ok || st != StateUnknown {
		t.Fatalf("완전한 ACCEPTED는 UNKNOWN으로 회복돼야 한다: st=%q ok=%v", st, ok)
	}
	if _, ok := l.Status("req-2"); ok {
		t.Fatal("torn tail(req-2)은 버려져야 한다 — 존재하면 안 된다")
	}
	// C6 — torn tail이 **디스크에서도** 잘렸는지(파일 크기 = 마지막 정상 줄까지).
	fi, ferr := os.Stat(journal)
	if ferr != nil {
		t.Fatalf("stat: %v", ferr)
	}
	if fi.Size() != int64(len(firstLine)) {
		t.Fatalf("torn tail이 디스크에서 truncate되지 않았다: size=%d want=%d", fi.Size(), len(firstLine))
	}
}

// TestLedgerTornTailTruncateSurvivesReopen은 C6 핵심이다: torn tail을 truncate한 뒤 이어 쓴
// 레코드가 재기동에서 치명 손상으로 뒤집히지 않음을 본다(찢어진 조각 뒤 append 방지).
func TestLedgerTornTailTruncateSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	journal, lock := filepath.Join(dir, "j"), filepath.Join(dir, "l")
	content := `{"requestId":"req-1","digest":"sha256:aaa","state":"ACCEPTED","ts":"t"}` + "\n" + `{"requestId":"req-2","dig`
	if err := os.WriteFile(journal, []byte(content), 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	l, err := OpenLedger(journal, lock) // torn tail truncate
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	// truncate 이후 이어 쓰기(req-1 terminal). truncate가 없으면 이 줄이 찢어진 조각 뒤에 붙는다.
	if err := l.Finalize("req-1", "sha256:aaa", StateCompleted); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	_ = l.Close()

	// 재기동 — truncate 덕에 중간 손상 없이 열려야 하고 COMPLETED가 복원돼야 한다.
	l2, err := OpenLedger(journal, lock)
	if err != nil {
		t.Fatalf("재기동이 치명 손상으로 실패했다(truncate 누락 시 발생): %v", err)
	}
	t.Cleanup(func() { _ = l2.Close() })
	if st, ok := l2.Status("req-1"); !ok || st != StateCompleted {
		t.Fatalf("재기동 후 COMPLETED가 복원돼야 한다: st=%q ok=%v", st, ok)
	}
}

// TestLedgerMidCorruptionFatal은 C6다: 개행으로 끝난 완전한 줄이 손상됐거나 중간 줄이 손상되면
// 치명(기동 거부)임을 본다 — append-only 단일 writer에서 그런 손상은 torn이 아니라 진짜 오염이다.
func TestLedgerMidCorruptionFatal(t *testing.T) {
	dir := t.TempDir()
	journal, lock := filepath.Join(dir, "j"), filepath.Join(dir, "l")
	// 손상된 줄(개행 종료) + 그 뒤 완전한 줄 → 손상이 마지막이 아니다 = 치명.
	content := "garbage-not-json\n" + `{"requestId":"req-2","digest":"d","state":"COMPLETED","ts":"t"}` + "\n"
	if err := os.WriteFile(journal, []byte(content), 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	if l, err := OpenLedger(journal, lock); err == nil {
		_ = l.Close()
		t.Fatal("중간 줄 손상인데 기동됐다(치명이어야 한다 · fail-closed)")
	}
}

// TestLedgerPoisonAfterWriteError는 C6다: 내구 기록에 실패하면 원장이 오염돼 이후 Accept를 전부
// 거절함을 본다(부분 기록 위에 새 실행을 얹지 않는다 · 실행자 중단). journal fd를 닫아 write
// 실패를 유도한다.
func TestLedgerPoisonAfterWriteError(t *testing.T) {
	l, _ := openTempLedger(t)
	// journal fd를 닫아 다음 Accept의 append(write)가 실패하게 한다.
	_ = l.journal.Close()
	dec := l.Accept("req-1", "sha256:aaa")
	if dec.Err == nil {
		t.Fatal("write 실패인데 Accept가 오류를 내지 않았다(poison 실패)")
	}
	// 이후 Accept는 poison으로 전부 거절.
	if dec2 := l.Accept("req-2", "sha256:bbb"); dec2.Err == nil {
		t.Fatalf("poison 뒤 Accept가 거절되지 않았다: %+v", dec2)
	}
}

// TestLedgerPermanentQuarantine은 재기동 후 남은 ACCEPTED가 사후조건 해소 전 새 배포를 영구히
// 막음을 본다(quarantine — 반복 Accept가 계속 Busy). 사람이 해소해야 풀린다(조각 A는 자동 해소 없음).
func TestLedgerPermanentQuarantine(t *testing.T) {
	dir := t.TempDir()
	journal, lock := filepath.Join(dir, "j"), filepath.Join(dir, "l")
	l, _ := OpenLedger(journal, lock)
	l.Accept("stuck", "sha256:aaa") // ACCEPTED 남긴 채 crash
	_ = l.Close()

	l2, err := OpenLedger(journal, lock)
	if err != nil {
		t.Fatalf("재열기: %v", err)
	}
	t.Cleanup(func() { _ = l2.Close() })
	for i := 0; i < 3; i++ {
		if dec := l2.Accept("new", "sha256:ccc"); !dec.Busy {
			t.Fatalf("미해소 ACCEPTED가 있는 동안 새 requestId는 매번 Busy여야 한다(영구 격리): try=%d %+v", i, dec)
		}
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
