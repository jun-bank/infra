package agentrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
//     불변식이다(R3 "실행 중 레코드 남은 채 재기동 = 새 배포 금지"). 해소 전까지 영구 격리다.
//   - **파일락은 target에 결박된다**(C3). journal 경로가 아니라 target 파생 고정 lock 경로에
//     flock을 건다 — 같은 AGENT_TARGET을 다른 journal 경로로 두 번 띄워도 같은 lock을 놓고
//     경합해 한 실행자만 연다. 원장 부재/손상/권한/열기 실패는 빈 원장이 아니라 **열기 거부**로
//     드러난다(fail-closed — 위성 기동이 거부된다).
//   - **write/fsync 오류 = poison**(C6): 한 번 내구 기록에 실패하면 원장을 오염 표시하고 이후
//     모든 Accept를 거절한다(부분 기록 위에 새 실행을 얹지 않는다 — 실행자 중단).
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

// errLedgerPoisoned는 원장이 내구 기록 실패로 오염됐을 때 Accept가 싣는 오류다(실행자 중단).
var errLedgerPoisoned = errors.New("agentrpc: 원장 오염(이전 내구 기록 실패) — 새 실행을 받지 않는다(fail-closed)")

// syncDir는 디렉터리 엔트리를 fsync한다(C5 · 부모 디렉터리 내구성). **매 OpenLedger마다** 부른다
// (멱등) — 최초 생성에만 하면 생성 시 fsync 실패가 한 번의 재시작으로 우회되기 때문이다. 패키지
// 변수로 둔 것은 테스트가 호출을 관측하기 위해서다.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// record는 journal 한 줄이다(JSON). 마지막 줄이 그 requestId의 현재 상태다.
type record struct {
	RequestID string      `json:"requestId"`
	Digest    string      `json:"digest"` // command digest(요청 body digest) — 같은 id 다른 digest=충돌
	State     LedgerState `json:"state"`
	TS        string      `json:"ts"` // RFC3339 — 진단용(판정엔 쓰지 않는다)
}

// Ledger는 append-only journal 위의 crash-safe 상태 저장소다. target 파생 lock 파일로 한
// 실행자만 연다(journal과 lock은 별개 파일 — C3).
type Ledger struct {
	mu       sync.Mutex
	journal  *os.File
	lock     *os.File
	records  map[string]record // requestId → 최신 레코드(재기동 시 journal replay로 복원)
	now      func() time.Time
	poisoned bool // 내구 기록 실패 후 true — 이후 Accept를 전부 거절(C6)
}

// OpenLedger는 target 파생 lock 파일에 배타 flock을 걸고(C3), journal을 열어 replay한다.
// journalPath와 lockPath는 별개다: lockPath는 target에서 파생된 **고정** 경로여야 하며(경로가
// 바뀌면 같은 target의 두 실행자가 서로 다른 lock을 잡아 배제가 무너진다), journalPath는 그
// target의 상태가 쌓이는 곳이다. 최초 journal 생성 시 부모 디렉터리를 fsync한다(C5).
func OpenLedger(journalPath, lockPath string) (*Ledger, error) {
	// 1. target 파생 lock에 배타 락 — 같은 target의 두 번째 실행자를 프로세스 경계에서 막는다.
	lf, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("agentrpc: 원장 lock 파일 열기 실패(fail-closed): %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lf.Close()
		return nil, fmt.Errorf("agentrpc: 원장 락 획득 실패 — 같은 target의 다른 실행자가 이미 쥐고 있다(target당 하나 · fail-closed): %w", err)
	}

	// 2. journal 열기 + **매 open 시** 부모 디렉터리 fsync(C5). 최초 생성에만 fsync하면, 생성 시
	//    fsync가 실패한 채 journal 파일만 남을 경우 다음 재기동에서 newlyCreated=false로 건너뛰어
	//    한 번의 재시작으로 실패가 우회된다 — dir fsync는 멱등하므로 존재 여부와 무관하게 매번 한다.
	// O_APPEND: 모든 쓰기가 파일 끝에 붙는다(부분 쓰기 중 재기동에도 이전 줄은 온전).
	jf, err := os.OpenFile(journalPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		_ = lf.Close()
		return nil, fmt.Errorf("agentrpc: 원장 journal 열기 실패(fail-closed): %w", err)
	}
	if err := syncDir(filepath.Dir(journalPath)); err != nil {
		_ = jf.Close()
		_ = lf.Close()
		return nil, fmt.Errorf("agentrpc: 원장 부모 디렉터리 fsync 실패(디렉터리 엔트리 내구성 미보장 — 전원 장애 시 빈 원장 재생성·중복 실행 위험 · fail-closed): %w", err)
	}

	records, truncateTo, err := replay(jf)
	if err != nil {
		_ = jf.Close()
		_ = lf.Close()
		return nil, fmt.Errorf("agentrpc: 원장 replay 실패(중간 손상 — fail-closed): %w", err)
	}
	// C6 — torn tail을 발견했으면 파일을 **마지막 정상 개행 오프셋까지 truncate + fsync**한 뒤 serve.
	// 이렇게 하지 않으면 이후 O_APPEND write가 찢어진 조각 뒤에 붙어, 다음 재기동에서 그 조각이
	// "개행종료 완전 줄"이 되어 치명적 중간 손상으로 뒤집힌다.
	if truncateTo >= 0 {
		if err := jf.Truncate(truncateTo); err != nil {
			_ = jf.Close()
			_ = lf.Close()
			return nil, fmt.Errorf("agentrpc: torn tail truncate 실패(fail-closed): %w", err)
		}
		if err := jf.Sync(); err != nil {
			_ = jf.Close()
			_ = lf.Close()
			return nil, fmt.Errorf("agentrpc: torn tail truncate 후 fsync 실패(fail-closed): %w", err)
		}
	}
	return &Ledger{journal: jf, lock: lf, records: records, now: time.Now}, nil
}

// replay는 journal을 처음부터 읽어 requestId별 최신 레코드를 복원한다(마지막 줄이 이긴다).
//
// torn tail 판정 근본화(C6): 정상 원장은 **항상 개행으로 끝난다**(매 레코드가 line+"\n" append).
// 따라서 파일이 개행으로 끝나지 않으면(!endsNL) 마지막 write가 미완이라는 신호이며, 그 마지막
// 조각은 **파싱 성공 여부와 무관하게** 버린다 — 완전한 JSON까지 다 써지고 trailing "\n"만 유실된
// 경우(fsync 반환 직전 crash의 흔한 형태)도 여기 포함된다. 파싱 성공만으로 남기면 이후 O_APPEND가
// 그 뒤에 붙어 "}{"가 되어 다음 재기동에서 중간 손상 치명이 된다.
//
// 마지막 조각을 버려도 안전한 근거: 개행 없이 끝난 조각은 **fsync 완료 전**이라 그 requestId는
// 애초에 durable하지 않다(클라이언트도 응답을 받지 못했다). 위성 관점에서 그 배포는 ABSENT이고
// main은 UNKNOWN으로 받아 사람에게 올린다 — 버림이 상태를 되감지 않는다(부작용 오인 없음).
//
// 개행으로 끝난 **완전한** 줄이 파싱 실패하거나(디스크 비트 손상) **중간** 줄이 손상되면 치명
// (기동 거부) — append-only 단일 writer에서 미완은 언제나 맨 끝에만 생기므로 그 밖은 진짜 오염이다.
//
// 두 번째 반환값 truncateTo는 마지막 미완 조각을 버렸을 때 **파일을 잘라야 할 오프셋**이다(마지막
// 정상 개행 직후 = 완전한 줄들의 총 바이트). 파일이 개행으로 끝나면 -1이다(truncate 불필요).
func replay(f *os.File) (map[string]record, int64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, -1, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, -1, err
	}
	out := map[string]record{}
	if len(data) == 0 {
		return out, -1, nil
	}
	endsNL := data[len(data)-1] == '\n'
	parts := bytes.Split(data, []byte{'\n'})
	truncateTo := int64(-1)
	if endsNL {
		parts = parts[:len(parts)-1] // 마지막 개행 뒤 빈 조각 제거(깔끔한 끝 · truncate 불필요)
	} else {
		// 파일이 개행으로 끝나지 않음 = 마지막 write 미완(fsync 전) = torn tail. 마지막 조각을
		// **파싱 여부와 무관하게** 버리고 last-good 개행 오프셋(= 전체 - 마지막 조각 길이)까지 truncate.
		last := parts[len(parts)-1]
		truncateTo = int64(len(data) - len(last))
		parts = parts[:len(parts)-1]
	}
	// 여기 남은 parts는 전부 개행으로 종료된 완전한 줄이다 — 그중 파싱 실패는 진짜 오염(치명)이다.
	for i, line := range parts {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r record
		if err := json.Unmarshal(line, &r); err != nil || r.RequestID == "" {
			return nil, -1, fmt.Errorf("journal 손상(치명): 개행 종료된 완전한 줄 %d 파싱 불가(중간·완전줄 손상은 torn tail이 아니다)", i)
		}
		out[r.RequestID] = r
	}
	return out, truncateTo, nil
}

// Close는 journal·lock 파일을 닫는다(flock도 해제된다).
func (l *Ledger) Close() error {
	err1 := l.journal.Close()
	err2 := l.lock.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

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
	// Err는 내구 기록 실패·원장 오염이다(실행하면 안 된다 · fail-closed).
	Err error
}

// Accept는 requestId·digest로 실행 진입을 판정하고, 진입 시 ACCEPTED를 내구 기록한다(fsync).
// **docker를 건드리기 전에** 부른다 — Proceed가 참일 때만, 그 뒤에만 dispatch를 시작한다.
func (l *Ledger) Accept(requestID, digest string) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.poisoned {
		return Decision{Err: errLedgerPoisoned}
	}
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
// write·fsync 오류는 원장을 poison해 이후 Accept를 전부 거절하게 한다(부분 기록 위에 실행 금지 · C6).
func (l *Ledger) appendLocked(r record) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := l.journal.Write(line); err != nil {
		l.poisoned = true
		return fmt.Errorf("agentrpc: 원장 write 실패(poison · fail-closed): %w", err)
	}
	if err := l.journal.Sync(); err != nil {
		l.poisoned = true
		return fmt.Errorf("agentrpc: 원장 fsync 실패(내구 기록 불가 · poison · fail-closed): %w", err)
	}
	l.records[r.RequestID] = r
	return nil
}

func (l *Ledger) nowStr() string { return l.now().UTC().Format(time.RFC3339Nano) }
