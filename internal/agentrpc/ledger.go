package agentrpc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

// crash-safe 위성 원장(R3 · OQ2) — 위성엔 DB가 없으므로 fsync 가능한 append-only journal로
// requestId 단위 멱등·재기동 안전을 준다. "원자 JSON 하나"로 불충분한 이유는 상태 전이 중
// 재기동을 견뎌야 하기 때문이다(쓰다 만 파일 = 손상). 각 전이는 한 줄 append + fsync다.
//
// 상태기계(R3):
//
//	ABSENT → ACCEPTED(requestId+command digest fsync) → COMPLETED|UNEXECUTED|UNKNOWN(fsync)
//
// 불변식:
//   - ACCEPTED를 fsync한 **뒤에만** docker(dispatch)를 시작한다. terminal을 fsync한 **뒤에만**
//     응답한다 — 그 사이(crash window)에 죽으면 재기동 후 ACCEPTED로 남아 UNKNOWN이 된다.
//   - 재기동 시 ACCEPTED(비terminal) → **절대 UNEXECUTED가 아니라 UNKNOWN**이다(부작용이
//     있었을 수 있다 — 미실행으로 접으면 중복 배포). Status·Accept 양쪽이 이를 지킨다.
//   - 같은 requestId + **다른** command digest = 충돌(거절 · 부작용 0). 같은 digest 재수신은
//     멱등: terminal이면 그 상태를 보고하고 비terminal이면 UNKNOWN을 보고한다(재실행 없음 —
//     자동 재개는 조각 C).
//   - **target당 하나만 실행**(quarantine): 비terminal 레코드가 있으면 다른 requestId의 새
//     배포를 거절한다 — 재기동 후 남은 ACCEPTED가 사후조건 해소 전 새 배포를 막는 것과 같은
//     불변식이다(R3 "실행 중 레코드 남은 채 재기동 = 새 배포 금지").
//   - 파일락(flock LOCK_EX)으로 **한 실행자만** 이 원장을 연다 — 두 프로세스가 같은 위성에서
//     동시에 배포하는 것을 프로세스 경계에서 막는다. 원장 부재/손상/권한/열기 실패는 빈 원장이
//     아니라 **열기 거부**로 드러난다(fail-closed — 위성 기동이 거부된다).
//
// ⚠️ 조각 A 단순화(판단): R3의 ACCEPTED→RUNNING 중간 전이는 별도로 materialize하지 않는다 —
// 조각 A는 재기동 시 ACCEPTED·RUNNING을 **동일하게 UNKNOWN**으로 회복하므로(둘 다 비terminal)
// 회복 판정이 갈리지 않는다. docker 시작 전/후를 구분해야 하는 fencing 단계 로직은 조각 B다.

// LedgerState는 원장 레코드의 상태다.
type LedgerState string

const (
	// StateAccepted는 요청을 내구 수락했고 실행이 진행 중이거나(정상) 그 사이 죽었음(crash)을
	// 뜻하는 **비terminal** 상태다. 재기동 후 이 상태는 UNKNOWN으로 회복된다(미실행 아님).
	StateAccepted LedgerState = "ACCEPTED"
	// StateCompleted·StateUnexecuted·StateUnknown은 terminal이다 — dispatch가 낸 3상태를
	// 그대로 내구 기록한 것이다(deploy.RemoteState와 1:1).
	StateCompleted  LedgerState = "COMPLETED"
	StateUnexecuted LedgerState = "UNEXECUTED"
	StateUnknown    LedgerState = "UNKNOWN"
)

// terminal은 상태가 종단(재실행 근거가 없는 확정 상태)인지 본다. ACCEPTED만 비terminal이다.
func (s LedgerState) terminal() bool {
	switch s {
	case StateCompleted, StateUnexecuted, StateUnknown:
		return true
	default:
		return false
	}
}

// record는 journal 한 줄이다(JSON). 마지막 줄이 그 requestId의 현재 상태다.
type record struct {
	RequestID string      `json:"requestId"`
	Digest    string      `json:"digest"` // command digest(요청 body digest) — 같은 id 다른 digest=충돌
	State     LedgerState `json:"state"`
	TS        string      `json:"ts"` // RFC3339 — 진단용(판정엔 쓰지 않는다)
}

// Ledger는 append-only journal 위의 crash-safe 상태 저장소다. 파일락으로 한 실행자만 연다.
type Ledger struct {
	mu      sync.Mutex
	f       *os.File
	records map[string]record // requestId → 최신 레코드(재기동 시 journal replay로 복원)
	now     func() time.Time
}

// OpenLedger는 원장 파일을 열고 배타 flock을 걸고 기존 journal을 replay한다. 이미 다른
// 실행자가 락을 쥐고 있거나 파일을 열 수 없으면 오류다(fail-closed — 위성이 기동을 거부한다).
func OpenLedger(path string) (*Ledger, error) {
	// O_APPEND: 모든 쓰기가 원자적으로 파일 끝에 붙는다(부분 쓰기 중 재기동에도 이전 줄은 온전).
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("agentrpc: 원장 열기 실패(fail-closed): %w", err)
	}
	// 비블로킹 배타 락 — 같은 위성의 두 번째 실행자를 프로세스 경계에서 막는다(target당 하나).
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("agentrpc: 원장 파일락 획득 실패 — 다른 실행자가 이미 열었다(target당 하나 · fail-closed): %w", err)
	}
	records, err := replay(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("agentrpc: 원장 replay 실패(손상 — fail-closed): %w", err)
	}
	return &Ledger{f: f, records: records, now: time.Now}, nil
}

// replay는 journal을 처음부터 읽어 requestId별 최신 레코드를 복원한다(마지막 줄이 이긴다).
func replay(f *os.File) (map[string]record, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	out := map[string]record{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r record
		if err := json.Unmarshal(line, &r); err != nil {
			// 손상된 줄 = 원장 신뢰 불가. 빈 원장으로 삼키지 않고 오류를 낸다(fail-closed).
			return nil, fmt.Errorf("journal 줄 파싱 불가: %w", err)
		}
		if r.RequestID == "" {
			return nil, fmt.Errorf("journal 줄에 requestId가 없다")
		}
		out[r.RequestID] = r
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Close는 원장 파일을 닫는다(flock도 해제된다).
func (l *Ledger) Close() error { return l.f.Close() }

// Decision은 Accept의 판정이다. 정확히 한 필드만 참이거나 Proceed다.
type Decision struct {
	// Proceed면 호출자가 실행해야 한다(ACCEPTED가 내구 기록됐다 — 이 뒤에만 docker 시작).
	Proceed bool
	// Report가 비어있지 않으면 실행 없이 이 상태를 보고한다(멱등 — 같은 digest 재수신).
	Report LedgerState
	// Conflict면 같은 requestId에 다른 command digest가 왔다(거절 · 부작용 0).
	Conflict bool
	// Busy면 다른 requestId가 비terminal이라 target이 점유·격리됐다(거절 · 부작용 0).
	Busy bool
	// Err는 내구 기록 실패다(ACCEPTED fsync 실패 — 실행하면 안 된다 · fail-closed).
	Err error
}

// Accept는 requestId·digest로 실행 진입을 판정하고, 진입 시 ACCEPTED를 내구 기록한다(fsync).
// **docker를 건드리기 전에** 부른다 — Proceed가 참일 때만, 그 뒤에만 dispatch를 시작한다.
func (l *Ledger) Accept(requestID, digest string) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	if r, ok := l.records[requestID]; ok {
		if r.Digest != digest {
			return Decision{Conflict: true}
		}
		if r.State.terminal() {
			return Decision{Report: r.State} // 멱등 보고(재실행 없음)
		}
		// 비terminal 재수신(동시 중복 또는 재기동 후 crash window) → UNKNOWN(미실행 아님 ·
		// 자동 재개 없음 — 조각 C). 부작용이 있었을 수 있으므로 재실행하지 않는다.
		return Decision{Report: StateUnknown}
	}
	// 새 requestId — quarantine 검사(target당 하나): 다른 requestId가 비terminal이면 거절.
	if l.hasNonTerminalLocked() {
		return Decision{Busy: true}
	}
	// ACCEPTED를 내구 기록(fsync)한 뒤에만 Proceed다 — 기록 실패면 실행하지 않는다(fail-closed).
	if err := l.appendLocked(record{RequestID: requestID, Digest: digest, State: StateAccepted, TS: l.nowStr()}); err != nil {
		return Decision{Err: err}
	}
	return Decision{Proceed: true}
}

// Finalize는 terminal 상태를 내구 기록한다(fsync). **응답을 서명·전송하기 전에** 부른다 —
// 기록에 성공해야만 그 상태를 응답으로 주장할 수 있다(기록 실패 = 상태 주장 불가).
func (l *Ledger) Finalize(requestID, digest string, state LedgerState) error {
	if !state.terminal() {
		return fmt.Errorf("agentrpc: Finalize에 비terminal 상태(%s)는 올 수 없다", state)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(record{RequestID: requestID, Digest: digest, State: state, TS: l.nowStr()})
}

// Status는 requestId의 현재 상태를 조회한다(부작용 0). 없으면 (_, false). 비terminal(ACCEPTED)은
// **UNKNOWN으로 회복**해 보고한다 — 재기동 후 미실행으로 오인해 중복 배포를 유발하지 않는다(R3).
func (l *Ledger) Status(requestID string) (LedgerState, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.records[requestID]
	if !ok {
		return "", false
	}
	if !r.State.terminal() {
		return StateUnknown, true
	}
	return r.State, true
}

// hasNonTerminalLocked는 비terminal 레코드가 하나라도 있는지 본다(mu 보유 전제 · quarantine).
func (l *Ledger) hasNonTerminalLocked() bool {
	for _, r := range l.records {
		if !r.State.terminal() {
			return true
		}
	}
	return false
}

// appendLocked는 레코드 한 줄을 append + fsync하고 in-memory 맵을 갱신한다(mu 보유 전제).
// fsync가 crash-safety의 핵심이다 — 페이지 캐시에만 있으면 재기동 시 사라져 상태가 되감긴다.
func (l *Ledger) appendLocked(r record) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := l.f.Write(line); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("agentrpc: 원장 fsync 실패(내구 기록 불가 · fail-closed): %w", err)
	}
	l.records[r.RequestID] = r
	return nil
}

func (l *Ledger) nowStr() string { return l.now().UTC().Format(time.RFC3339Nano) }
