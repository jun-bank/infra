// 오케스트레이션 시퀀스의 단위 테스트(DO-16·17·18 · CD-3·4). 거절/안전 경로를 우선
// 밟는다 — 승인 게이트가 장애로 열리거나(fail-open), 경합을 획득으로 오인하거나, 미완
// 배포가 조용히 방치되는 것이 이 층의 치명적 실패이기 때문이다. 협력자(mode·lock·history·
// dispatch)는 인메모리 페이크로 대체한다 — 실 SQL 계약은 store 통합 테스트가 진다.
package deploy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/store"
)

// validDigest는 DO-18 ⑵ 형식(sha256: + 64자 hex)을 만족하는 테스트용 고정 digest다.
var validDigest = "sha256:" + strings.Repeat("a", 64)

// --- 페이크 -------------------------------------------------------------------

// seqModeReader는 호출마다 다음 응답을 돌려주는 ModeReader다(수락 시 vs 적용 직전의
// version 변화를 흉내낸다). 응답이 소진되면 마지막 응답을 반복한다.
type seqModeReader struct {
	resp []modeResp
	i    int
}
type modeResp struct {
	mode    string
	version uint64
	err     error
}

func (r *seqModeReader) Current(context.Context, string) (string, uint64, error) {
	resp := r.resp[len(r.resp)-1]
	if r.i < len(r.resp) {
		resp = r.resp[r.i]
	}
	r.i++
	return resp.mode, resp.version, resp.err
}

// orchLock은 고정 결과를 돌려주며 획득·재확인·해제 호출을 센다.
type orchLock struct {
	acquireTok    store.FencingToken
	acquireOK     bool
	acquireErr    error
	renewOK       bool  // Confirm(재확인)이 볼 결과. baseDeps는 true(정상 보유).
	renewErr      error // 설정 시 Renew(재확인)가 이 오류를 낸다(판정 불가).
	releaseOK     bool
	acquired      int
	released      int
	releaseCtxErr error // 마지막 Release에 넘어온 context의 Err()(취소된 ctx 재사용 감시).
}

func (l *orchLock) Acquire(context.Context, store.HolderKind, string, time.Duration) (store.FencingToken, bool, error) {
	l.acquired++
	return l.acquireTok, l.acquireOK, l.acquireErr
}
func (l *orchLock) Renew(context.Context, store.HolderKind, string, store.FencingToken, time.Duration) (bool, error) {
	if l.renewErr != nil {
		return false, l.renewErr
	}
	return l.renewOK, nil
}
func (l *orchLock) Release(ctx context.Context, _ store.HolderKind, _ string, _ store.FencingToken) (bool, error) {
	l.released++
	l.releaseCtxErr = ctx.Err()
	return l.releaseOK, nil
}

// recHistory는 append를 순서대로 담고 최신 조회를 지원하는 인메모리 이력이다.
type recHistory struct {
	events    []store.HistoryEvent
	appendErr error // 설정 시 AppendEvent가 이 오류를 반환한다(이력 쓰기 실패 흉내).
}

func (h *recHistory) AppendEvent(_ context.Context, ev store.HistoryEvent) error {
	if h.appendErr != nil {
		return h.appendErr
	}
	h.events = append(h.events, ev)
	return nil
}
func (h *recHistory) ReadLatest(_ context.Context, requestID string) (store.HistoryEvent, error) {
	for i := len(h.events) - 1; i >= 0; i-- {
		if h.events[i].RequestID == requestID {
			return h.events[i], nil
		}
	}
	return store.HistoryEvent{}, nil
}
func (h *recHistory) last() store.HistoryEvent {
	if len(h.events) == 0 {
		return store.HistoryEvent{}
	}
	return h.events[len(h.events)-1]
}

// fakeDispatcher는 고정 상태·오류를 낸다(실행 지점 대체).
type fakeDispatcher struct {
	state RemoteState
	err   error
}

func (d fakeDispatcher) Dispatch(context.Context, Manifest, store.FencingToken) (RemoteState, error) {
	return d.state, d.err
}

// recDispatcher는 고정 상태를 내며 호출 횟수를 센다(dispatch 미시작 검증용).
type recDispatcher struct {
	state RemoteState
	calls int
}

func (d *recDispatcher) Dispatch(context.Context, Manifest, store.FencingToken) (RemoteState, error) {
	d.calls++
	return d.state, nil
}

// --- 하네스 -------------------------------------------------------------------

func validManifest(requestID string) []byte {
	return []byte(`{"target":"core","commitSha":"c1","imageDigest":"` + validDigest + `","composeRevision":"rev1","configVersion":"v1","requestId":"` + requestID + `"}`)
}

// baseDeps는 정상 경로(dev·락 획득·UNEXECUTED dispatch)를 조립한다. 개별 테스트가 필요한
// 조각만 덮어쓴다.
func baseDeps() (Deps, *orchLock, *recHistory) {
	l := &orchLock{acquireTok: 7, acquireOK: true, renewOK: true, releaseOK: true}
	h := &recHistory{}
	return Deps{
		Mode:       &seqModeReader{resp: []modeResp{{mode: "dev", version: 3}}},
		Lock:       l,
		History:    h,
		Dispatcher: fakeDispatcher{state: StateUnexecuted},
		HolderID:   "deploy-1",
		Lease:      60 * time.Second,
	}, l, h
}

// --- manifest 검증 순수 함수 --------------------------------------------------

func TestParseManifest_TargetGate(t *testing.T) {
	if _, err := ParseManifest([]byte(`{"target":"staging"}`)); !errors.Is(err, ErrManifestTarget) {
		t.Fatalf("닫힌 집합 밖 대상: err=%v, ErrManifestTarget 기대", err)
	}
	if _, err := ParseManifest([]byte(`not-json`)); !errors.Is(err, ErrManifestMalformed) {
		t.Fatalf("깨진 JSON: err=%v, ErrManifestMalformed 기대", err)
	}
	if m, err := ParseManifest([]byte(`{"target":"core"}`)); err != nil || m.Target != TargetCore {
		t.Fatalf("유효 대상 파싱 실패: m=%+v err=%v", m, err)
	}
}

func TestVerifyManifest(t *testing.T) {
	full := Manifest{Target: TargetCore, CommitSHA: "c1", ImageDigest: validDigest, ComposeRevision: "r1", ConfigVersion: "v1", RequestID: "req-1"}
	if err := VerifyManifest(full, "req-1"); err != nil {
		t.Fatalf("완전·일치 manifest가 거절됐다: %v", err)
	}
	// 필드 누락.
	miss := full
	miss.ComposeRevision = ""
	if err := VerifyManifest(miss, "req-1"); !errors.Is(err, ErrManifestIncomplete) {
		t.Fatalf("필드 누락: err=%v, ErrManifestIncomplete 기대", err)
	}
	// 태그(digest 형식 아님).
	tag := full
	tag.ImageDigest = "latest"
	if err := VerifyManifest(tag, "req-1"); !errors.Is(err, ErrManifestDigest) {
		t.Fatalf("가변 태그: err=%v, ErrManifestDigest 기대", err)
	}
	// sha256: 접두는 있으나 64자 hex가 아님(길이 미달) — 거절.
	short := full
	short.ImageDigest = "sha256:abc"
	if err := VerifyManifest(short, "req-1"); !errors.Is(err, ErrManifestDigest) {
		t.Fatalf("짧은 digest(sha256:abc): err=%v, ErrManifestDigest 기대", err)
	}
	// 길이는 64지만 hex가 아님 — 거절.
	nothex := full
	nothex.ImageDigest = "sha256:" + strings.Repeat("g", 64)
	if err := VerifyManifest(nothex, "req-1"); !errors.Is(err, ErrManifestDigest) {
		t.Fatalf("비-hex digest: err=%v, ErrManifestDigest 기대", err)
	}
	// requestId 불일치(서명된 것과 다름).
	if err := VerifyManifest(full, "req-OTHER"); !errors.Is(err, ErrManifestRequestID) {
		t.Fatalf("requestId 불일치: err=%v, ErrManifestRequestID 기대", err)
	}
}

// --- 오케스트레이션 거절/안전 경로 -------------------------------------------

// manifest가 깨졌으면 락을 잡지 않고 거절한다.
func TestOrchestrate_ManifestMalformed_NoLock(t *testing.T) {
	d, l, h := baseDeps()
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "r", Body: []byte("nope")})
	if res.Outcome != OutcomeManifestInvalid {
		t.Fatalf("깨진 manifest: outcome=%v, MANIFEST_INVALID 기대", res.Outcome)
	}
	if l.acquired != 0 {
		t.Fatalf("깨진 manifest인데 락을 잡았다(acquired=%d) — 검증 전 락 금지", l.acquired)
	}
	if h.last().EventType != "REJECTED" {
		t.Fatalf("거절이 이력에 기록되지 않았다: %+v", h.last())
	}
}

// 모드 저장 접근 실패 = operational fail-closed → 락을 잡지 않고 FAIL_CLOSED.
func TestOrchestrate_ModeFailClosed_NoLock(t *testing.T) {
	d, l, _ := baseDeps()
	d.Mode = &seqModeReader{resp: []modeResp{{err: errors.New("db 접근 불가")}}}
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeFailClosed {
		t.Fatalf("모드 읽기 실패: outcome=%v, FAIL_CLOSED 기대(fail-closed)", res.Outcome)
	}
	if l.acquired != 0 {
		t.Fatalf("모드 fail-closed인데 락을 잡았다 — 자동 배포 미시작이어야 한다")
	}
}

// 락 경합 = 기록할 거절(오류 아님) → LOCK_CONTENDED, 흐름 중단.
func TestOrchestrate_LockContended(t *testing.T) {
	d, l, h := baseDeps()
	l.acquireOK = false
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeLockContended {
		t.Fatalf("락 경합: outcome=%v, LOCK_CONTENDED 기대", res.Outcome)
	}
	if h.last().EventType != "REJECTED" {
		t.Fatalf("경합 거절이 이력에 남지 않았다: %+v", h.last())
	}
}

// 락 획득 연결·권한 오류 = fail-closed(조용히 삼키지 않는다).
func TestOrchestrate_LockError_FailClosed(t *testing.T) {
	d, _, _ := baseDeps()
	d.Lock = &orchLock{acquireErr: errors.New("db 접근 불가")}
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeFailClosed {
		t.Fatalf("락 오류: outcome=%v, FAIL_CLOSED 기대", res.Outcome)
	}
}

// 수락 시(version=5) 뒤 적용 직전 토글(version=6)이면 락 획득 후 검증에서 거절하고 락을
// 해제한다(#9 원자 검증 — VerifyModeUnchanged가 락 획득과 같은 자리).
func TestOrchestrate_ModeChangedUnderLock_Rejects_ReleasesLock(t *testing.T) {
	d, l, h := baseDeps()
	d.Mode = &seqModeReader{resp: []modeResp{
		{mode: "operational", version: 5}, // DecideMode
		{mode: "operational", version: 6}, // VerifyModeUnchanged — 토글됨
	}}
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeModeChanged {
		t.Fatalf("적용 직전 토글: outcome=%v, MODE_CHANGED 기대(race 차단)", res.Outcome)
	}
	if l.acquired != 1 || l.released != 1 {
		t.Fatalf("모드 변경 거절 시 락 획득·해제 각 1회 기대: acquired=%d released=%d", l.acquired, l.released)
	}
	if h.last().EventType != "REJECTED" {
		t.Fatalf("모드 변경 거절이 이력에 남지 않았다: %+v", h.last())
	}
}

// 락은 잡았지만 manifest가 불완전(락 보유 중 DO-18 검증 실패)하면 거절하고 락을 해제한다.
func TestOrchestrate_ManifestIncompleteUnderLock_ReleasesLock(t *testing.T) {
	d, l, _ := baseDeps()
	// 대상은 유효(모드 판정 통과)하지만 나머지 필드가 비어 VerifyManifest에서 걸린다.
	body := []byte(`{"target":"core"}`)
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: body})
	if res.Outcome != OutcomeManifestInvalid {
		t.Fatalf("불완전 manifest: outcome=%v, MANIFEST_INVALID 기대", res.Outcome)
	}
	if l.acquired != 1 || l.released != 1 {
		t.Fatalf("락 보유 중 거절 시 획득·해제 각 1회 기대: acquired=%d released=%d", l.acquired, l.released)
	}
}

// requestId가 서명된 것과 다르면(manifest 위조된 id) 거절한다.
func TestOrchestrate_RequestIDMismatch(t *testing.T) {
	d, _, _ := baseDeps()
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-SIGNED", Body: validManifest("req-OTHER")})
	if res.Outcome != OutcomeManifestInvalid {
		t.Fatalf("requestId 불일치: outcome=%v, MANIFEST_INVALID 기대", res.Outcome)
	}
}

// --- 정상 경로 + dispatch 상태 사상 ------------------------------------------

// 완전 manifest → 실행 지점 도달. dispatch 스텁은 UNEXECUTED → REACHED_DISPATCH, 락 해제,
// STEP_RESULT(UNEXECUTED) 이력.
func TestOrchestrate_ReachesDispatch(t *testing.T) {
	d, l, h := baseDeps()
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeReachedDispatch || res.State != StateUnexecuted {
		t.Fatalf("정상 경로: outcome=%v state=%v, REACHED_DISPATCH·UNEXECUTED 기대", res.Outcome, res.State)
	}
	if l.released != 1 {
		t.Fatalf("실행 지점 도달 후 락 해제 기대: released=%d", l.released)
	}
	if h.last().EventType != "STEP_RESULT" || h.last().Result != string(StateUnexecuted) {
		t.Fatalf("dispatch 상태가 이력에 남지 않았다: %+v", h.last())
	}
	if h.last().FencingToken != 7 {
		t.Fatalf("이력에 fencing 토큰이 실리지 않았다: %+v", h.last())
	}
}

// dispatch가 COMPLETED면 완료로 사상하고 락을 해제한다.
func TestOrchestrate_CompletedReleasesLock(t *testing.T) {
	d, l, h := baseDeps()
	d.Dispatcher = fakeDispatcher{state: StateCompleted}
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("dispatch 완료: outcome=%v, COMPLETED 기대", res.Outcome)
	}
	if l.released != 1 {
		t.Fatalf("완료 후 락 해제 기대: released=%d", l.released)
	}
	if h.last().EventType != string(OutcomeCompleted) {
		t.Fatalf("완료 이력 event_type=%q, COMPLETED 기대", h.last().EventType)
	}
}

// dispatch가 UNKNOWN이면 락을 유지한 채 사람에게 올린다(DO-16 ⑵ — 재시도·실패 접기 금지).
func TestOrchestrate_UnknownKeepsLock(t *testing.T) {
	d, l, h := baseDeps()
	d.Dispatcher = fakeDispatcher{state: StateUnknown}
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeUnknown {
		t.Fatalf("dispatch UNKNOWN: outcome=%v, UNKNOWN 기대", res.Outcome)
	}
	if l.released != 0 {
		t.Fatalf("UNKNOWN은 락을 유지해야 한다: released=%d", l.released)
	}
	if h.last().EventType != string(OutcomeUnknown) {
		t.Fatalf("UNKNOWN 이력 event_type=%q, UNKNOWN 기대", h.last().EventType)
	}
}

// dispatch 직전 fencing 재확인(Confirm)이 held=false(lease 만료·탈취)면 그 단계를 시작하지
// 않는다 — 만료·탈취된 락으로 특권 실행을 시작하는 것을 막는다(CD-3 보유 재확인). dispatch가
// 호출돼서는 안 되고 fail-closed로 닫는다.
func TestOrchestrate_FencingLostBeforeDispatch_NoDispatch(t *testing.T) {
	d, l, h := baseDeps()
	l.renewOK = false // 재확인 시 이미 보유하지 않음(만료·탈취)
	disp := &recDispatcher{state: StateUnexecuted}
	d.Dispatcher = disp
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeFailClosed {
		t.Fatalf("fencing 상실: outcome=%v, FAIL_CLOSED 기대(dispatch 미시작)", res.Outcome)
	}
	if disp.calls != 0 {
		t.Fatalf("fencing 상실인데 dispatch가 호출됐다(calls=%d) — 만료·탈취 락으로 실행 금지", disp.calls)
	}
	if h.last().EventType != "REJECTED" {
		t.Fatalf("fencing 상실 거절이 이력에 남지 않았다: %+v", h.last())
	}
}

// dispatch 직전 재확인이 오류(판정 불가)면 시작하지 않는다(fail-closed).
func TestOrchestrate_FencingConfirmError_NoDispatch(t *testing.T) {
	d, l, _ := baseDeps()
	l.renewErr = errors.New("db 접근 불가")
	disp := &recDispatcher{state: StateUnexecuted}
	d.Dispatcher = disp
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeFailClosed {
		t.Fatalf("재확인 오류: outcome=%v, FAIL_CLOSED 기대", res.Outcome)
	}
	if disp.calls != 0 {
		t.Fatalf("재확인 오류인데 dispatch가 호출됐다(calls=%d)", disp.calls)
	}
}

// dispatch가 (UNKNOWN, err)를 내면 err 유무와 무관하게 UNKNOWN으로 사상하고 락을 유지한다.
// UNKNOWN(전환 이후 상태 불명)은 오류로 접어서는 안 된다 — 오류로 접으면 락이 풀려 멈춘
// 대상을 살아 있다고 오인하거나 재시도로 이중 부작용을 낸다(DO-16 ⑵ · CD-4).
func TestOrchestrate_UnknownWithError_KeepsLock(t *testing.T) {
	d, l, h := baseDeps()
	d.Dispatcher = fakeDispatcher{state: StateUnknown, err: errors.New("응답 유실")}
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeUnknown {
		t.Fatalf("(UNKNOWN,err): outcome=%v, UNKNOWN 기대(err보다 UNKNOWN 우선·락 유지)", res.Outcome)
	}
	if l.released != 0 {
		t.Fatalf("(UNKNOWN,err)은 err가 있어도 락을 유지해야 한다: released=%d", l.released)
	}
	if h.last().EventType != string(OutcomeUnknown) {
		t.Fatalf("UNKNOWN 이력 event_type=%q, UNKNOWN 기대", h.last().EventType)
	}
}

// dispatch 이력 쓰기가 실패하면 COMPLETED를 반환하지 않는다 — 이력은 재개 분류의 유일한
// durable 근거이므로, durable하게 남기지 못한 완료는 UNKNOWN(락 유지·사람에게)으로 접는다
// (fail-closed). 근거가 없으니 재전송은 재실행하지 않는다(ClassifyReplay: 이력 없음→REPORT).
func TestOrchestrate_HistoryWriteFailure_FoldsToUnknown(t *testing.T) {
	d, l, h := baseDeps()
	d.Dispatcher = fakeDispatcher{state: StateCompleted} // dispatch는 완료를 보고하나
	h.appendErr = errors.New("이력 쓰기 실패")                 // 그 완료를 durable하게 남기지 못한다
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome == OutcomeCompleted {
		t.Fatalf("이력 쓰기 실패인데 COMPLETED 반환 — durable 아님(재전송이 재실행할 수 있다)")
	}
	if res.Outcome != OutcomeUnknown {
		t.Fatalf("이력 쓰기 실패: outcome=%v, UNKNOWN 기대(fail-closed·락 유지)", res.Outcome)
	}
	if l.released != 0 {
		t.Fatalf("이력 쓰기 실패 시 락을 유지해야 한다: released=%d", l.released)
	}
	// 근거가 남지 않았으니 재전송은 재실행하지 않는다(이력 없음 → REPORT).
	if a := ClassifyReplay(h.last()); a == ResumeReexecute {
		t.Fatalf("이력 없음인데 재전송이 재실행(REEXECUTE)으로 분류됐다: %v", a)
	}
}

// dispatch가 정의된 세 상태(UNEXECUTED·COMPLETED·UNKNOWN) 밖의 값(빈 문자열·미지)을 내면
// UNEXECUTED로 오인해 락을 풀어서는 안 된다 — 실행 결과를 신뢰할 수 없으므로 UNKNOWN으로
// 접어 락을 유지하고 사람에게 올린다(DO-16 fail-closed). COMPLETED로도 사상하지 않는다.
func TestOrchestrate_OutOfDefinitionState_FoldsToUnknown(t *testing.T) {
	for _, st := range []RemoteState{"", "WEIRD"} {
		d, l, h := baseDeps()
		d.Dispatcher = fakeDispatcher{state: st}
		res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: validManifest("req-1")})
		if res.Outcome == OutcomeCompleted {
			t.Fatalf("정의 밖 상태(%q)를 COMPLETED로 사상 — fail-open", st)
		}
		if res.Outcome != OutcomeUnknown {
			t.Fatalf("정의 밖 상태(%q): outcome=%v, UNKNOWN 기대(fail-closed·락 유지)", st, res.Outcome)
		}
		if l.released != 0 {
			t.Fatalf("정의 밖 상태(%q)는 락을 유지해야 한다: released=%d", st, l.released)
		}
		if h.last().EventType != string(OutcomeUnknown) {
			t.Fatalf("정의 밖 상태(%q) 이력 event_type=%q, UNKNOWN 기대(에스컬레이션 근거)", st, h.last().EventType)
		}
	}
}

// History가 nil이면 실행 상태를 durable하게 남길 수 없어 재개 판정의 근거가 사라진다 —
// 그런 오케스트레이터는 애초에 조립되지 못하게 막는다(fail-closed 기동). 필수 의존이
// 비어 있는 것은 배선 오류(프로그래머 오류)이므로 구성 시점에 panic한다.
func TestNewCoordinator_NilHistory_Panics(t *testing.T) {
	d, _, _ := baseDeps()
	d.History = nil
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("nil History인데 panic하지 않았다 — 기록 불가면 durable 근거 없음(fail-closed 기동)")
		}
	}()
	NewCoordinator(d)
}

// 전환 전 락 해제는 요청 ctx와 분리한다 — 요청 ctx가 취소됐어도 락은 반드시 놓아야 한다.
// 취소된 ctx를 재사용하면 해제가 즉시 실패해 락이 lease 만료까지 누수된다.
func TestOrchestrate_ReleaseUsesFreshContext(t *testing.T) {
	d, l, _ := baseDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 요청 ctx가 이미 취소된 상황
	res := NewCoordinator(d).Orchestrate(ctx, Request{RequestID: "req-1", Body: validManifest("req-1")})
	if res.Outcome != OutcomeReachedDispatch {
		t.Fatalf("outcome=%v, REACHED_DISPATCH 기대", res.Outcome)
	}
	if l.released != 1 {
		t.Fatalf("취소된 요청이라도 락은 해제돼야 한다: released=%d", l.released)
	}
	if l.releaseCtxErr != nil {
		t.Fatalf("락 해제에 취소된 요청 ctx가 재사용됐다: %v — 별도 context(background+timeout) 기대", l.releaseCtxErr)
	}
}

// --- 재전송 분류(#9) ---------------------------------------------------------

func TestClassifyReplay(t *testing.T) {
	// 미완(예약·미실행) → 재개.
	if a := ClassifyReplay(store.HistoryEvent{EventType: "RESERVED"}); a != ResumeReexecute {
		t.Fatalf("예약만: %v, REEXECUTE 기대(재개)", a)
	}
	if a := ClassifyReplay(store.HistoryEvent{EventType: "STEP_RESULT", Result: "UNEXECUTED"}); a != ResumeReexecute {
		t.Fatalf("미실행: %v, REEXECUTE 기대(재개)", a)
	}
	// 완료 → 재실행 없이 상태 반환.
	if a := ClassifyReplay(store.HistoryEvent{EventType: "COMPLETED"}); a != ResumeReport {
		t.Fatalf("완료: %v, REPORT 기대(재실행 없음)", a)
	}
	// UNKNOWN → 재시도 금지.
	if a := ClassifyReplay(store.HistoryEvent{EventType: "UNKNOWN"}); a != ResumeEscalate {
		t.Fatalf("UNKNOWN: %v, ESCALATE 기대(재시도 금지)", a)
	}
	// 이력 없음 → 재개하지 않는다(이 requestId 미예약 — jti 재사용 등). 예약-우선 불변식.
	if a := ClassifyReplay(store.HistoryEvent{}); a != ResumeReport {
		t.Fatalf("이력 없음: %v, REPORT 기대(미예약이면 부작용 금지)", a)
	}
}
