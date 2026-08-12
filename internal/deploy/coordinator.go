package deploy

import (
	"context"
	"log"
	"time"

	"github.com/jun-bank/infra/internal/store"
)

// releaseTimeout은 전환 전 락 해제에 쓰는 별도 context의 상한이다(요청 ctx와 분리 — 요청이
// 취소돼도 해제는 완주해야 한다). 짧게 둔다 — 해제 실패는 lease 만료가 어차피 회수한다.
const releaseTimeout = 5 * time.Second

// 오케스트레이션 시퀀스 — 게이트·멱등을 통과한 검증된 배포 요청을 받아 실행 직전까지
// 엮는다(IA-4 ⑵: 오케스트레이터는 상태를 가진 층). HTTP 진입 층(httpentry)이 이 층을
// 호출하며, 미들웨어의 선형성이 이 상태 경계를 가리지 않도록 두 층을 분리한다.
//
// 순서(CD-4 앞단): 모드 판정(DecideMode) → 배포 창 락 획득(AcquireWindow) + 같은 자리에서
// mode version 원자 검증(VerifyModeUnchanged — DO-17 ⑵) → manifest 검증(DO-18) →
// 실행 지점(dispatch — #15 스텁) → 락 해제. 각 단계 실패는 fail-closed다.
//
// 계약 출처(정본 — 재해석하지 않는다):
//   - ADR-027 DO-16  (원격/로컬 실행 3상태: 미실행 / 완료 / UNKNOWN)
//   - ADR-027 DO-17  (모드 정본=배포 스키마 · 적용 직전 mode version 원자 검증 · fail-closed)
//   - ADR-027 DO-18  (CI가 서명하는 manifest 검증 · digest 고정)
//   - operations/cicd.md CD-3·CD-4 (배포 창 락 · 순서 있는 적용 · 전환 전 실패는 락 해제)

// RemoteState는 실행의 세 상태다(DO-16). dispatch가 실행 결과로 낸다. UNKNOWN을 실패로
// 접어서는 안 된다 — 재시도 시 이중 부작용이거나, 멈춘 대상을 살아 있다고 보고하게 된다.
type RemoteState string

const (
	// StateUnexecuted는 부작용이 전혀 없었음을 증명한다(연결·인증·dispatcher 거부 — DO-16 ⓐ).
	StateUnexecuted RemoteState = "UNEXECUTED"
	// StateCompleted는 dispatcher가 내구 완료 표시를 남겼고 그것을 읽었음을 뜻한다(DO-16 ⓑ).
	StateCompleted RemoteState = "COMPLETED"
	// StateUnknown은 명령 전달 후 응답이 유실됐음을 뜻한다(DO-16 ⓒ). 무턱대고 재시도하지
	// 않고 부작용 없는 조회로 해소하며, 그 조회마저 UNKNOWN이면 사람에게 올리고 락을 유지한다.
	StateUnknown RemoteState = "UNKNOWN"
)

// Dispatcher는 실행 지점이다(#15). 락을 보유한 검증된 manifest를 대상 호스트에서
// 실행하고 세 상태 중 하나를 낸다. 이번 범위(#14)에서는 스텁이 UNEXECUTED(부작용 0)를
// 낸다 — 실제 특권 실행(이미지 pull·compose up·헬스체크)은 #15다.
type Dispatcher interface {
	Dispatch(ctx context.Context, m Manifest, token store.FencingToken) (RemoteState, error)
}

// StubDispatcher는 실행 지점의 스캐폴드다. 아직 특권 조작에 연결되지 않았으므로 부작용
// 없이 UNEXECUTED를 낸다(부작용 0 증명 — DO-16 ⓐ). 조용한 성공 위장이 아니다: 호출자는
// 이 상태를 실행 미구현으로 사상해 요란하게 드러낸다(REACHED_DISPATCH → 501).
type StubDispatcher struct{}

func (StubDispatcher) Dispatch(context.Context, Manifest, store.FencingToken) (RemoteState, error) {
	return StateUnexecuted, nil
}

// Outcome은 오케스트레이션 시퀀스의 종단 결과다(전송 무관 — httpentry가 상태코드로 사상).
type Outcome string

const (
	// OutcomeReachedDispatch는 모드·락·검증을 통과해 실행 지점에 도달했으나 dispatch가
	// 아직 미구현임을 뜻한다(#15). 조용한 성공이 아니다 — 실행이 일어나지 않았다.
	OutcomeReachedDispatch Outcome = "REACHED_DISPATCH"
	// OutcomeManifestInvalid는 manifest 파싱·대상·완전성·digest·requestId 검증 실패다(DO-18).
	OutcomeManifestInvalid Outcome = "MANIFEST_INVALID"
	// OutcomeLockContended는 배포 창 락 경합이다(다른 배포·배치 점유) — 기록할 거절(RL-4).
	OutcomeLockContended Outcome = "LOCK_CONTENDED"
	// OutcomeModeChanged는 적용 직전 mode version이 바뀐 것이다(토글-요청 race — DO-17 ⑵).
	OutcomeModeChanged Outcome = "MODE_CHANGED"
	// OutcomeFailClosed는 저장 접근·검증 불가로 자동 배포를 시작하지 않은 것이다(DO-17 ⑷).
	OutcomeFailClosed Outcome = "FAIL_CLOSED"
	// OutcomeCompleted는 실행이 완료됐음을(또는 재전송 시 이미 완료됐음을) 뜻한다(DO-16 ⓑ).
	OutcomeCompleted Outcome = "COMPLETED"
	// OutcomeUnknown은 실행 상태가 UNKNOWN이라 사람 개입이 필요함을 뜻한다(DO-16 ⓒ · 락 유지).
	OutcomeUnknown Outcome = "UNKNOWN"
)

// Result는 종단 결과와 사람이 읽는 사유다.
type Result struct {
	Outcome Outcome
	State   RemoteState // dispatch가 낸 상태(실행 지점에 도달했을 때)
	Detail  string      // 응답 본문·이력에 남길 사유
}

// Request는 게이트(HMAC·OIDC)와 멱등 선점을 통과한 검증된 배포 요청이다. httpentry가
// 채워 넘긴다 — 이 층은 재파싱·재검증하지 않고 서명된 body와 requestId를 신뢰한다.
type Request struct {
	// RequestID는 서명된 envelope의 requestId다(멱등·이력 키). manifest의 requestId가
	// 이것과 일치해야 한다(DO-10 ⑴).
	RequestID string
	// Body는 서명·인증된 manifest JSON이다(gate 1이 digest로 이미 인증).
	Body []byte
}

// Deps는 오케스트레이션이 소비하는 협력자다. 전부 소비 지점 인터페이스이며 store
// 구체 타입에 묶이지 않는다(IA-5) — main이 실제 배포 스키마 store를 조립해 주입한다.
type Deps struct {
	Mode       ModeReader         // 대상별 mode·version 조회(DO-5·DO-17)
	Lock       WindowLock         // 배포 창 락(CD-3)
	History    store.HistoryStore // 배포 이력 append·조회(DO-16 상태 기록) — 필수(nil이면 NewCoordinator 거부)
	Dispatcher Dispatcher         // 실행 지점(#15)
	HolderID   string             // 이 agent의 락 holder 식별자(CD-3)
	Lease      time.Duration      // 배포 창 락 lease(≥ store.MinLease)
}

// Coordinator는 하나의 검증된 요청에 대해 오케스트레이션 시퀀스를 실행한다.
type Coordinator interface {
	Orchestrate(ctx context.Context, req Request) Result
}

type coordinator struct{ d Deps }

// NewCoordinator는 오케스트레이터를 만든다. History는 실행 상태를 durable하게 남기는 필수
// 의존이다 — 이력이 없으면 재개 판정(ClassifyReplay)의 근거가 사라지고 완료를 durable하게
// 증명할 수 없다. nil이면 그런 오케스트레이터가 조립되지 못하게 구성 시점에 panic한다
// (fail-closed 기동 — 배선 오류를 런타임 fail-open으로 흘리지 않는다).
func NewCoordinator(d Deps) Coordinator {
	if d.History == nil {
		panic("deploy: NewCoordinator에 History가 필요하다(nil 금지) — 실행 상태를 durable하게 남길 수 없으면 재개 판정 근거가 없다(fail-closed 기동)")
	}
	return coordinator{d: d}
}

// Orchestrate는 시퀀스를 실행한다. 각 거절·상태 전이는 이력에 남고(RL-8·DO-16), 어느
// 단계든 실패는 fail-closed로 막는다. 전환 전 실패(모드·락·검증)는 락을 해제하고 끝나며,
// UNKNOWN(전환 이후 상태 불명)만 락을 유지한 채 사람에게 올린다(CD-4 부분 실패 전이).
func (c coordinator) Orchestrate(ctx context.Context, req Request) Result {
	// 1. manifest 파싱(대상 추출 — 모드 판정에 필요). 파싱·대상 실패 = 거절·기록.
	m, err := ParseManifest(req.Body)
	if err != nil {
		c.reject(ctx, req.RequestID, "", "", 0, "manifest 파싱: "+err.Error())
		return Result{Outcome: OutcomeManifestInvalid, Detail: err.Error()}
	}
	target := string(m.Target)

	// 2. 모드 판정(DO-5). 저장 접근 실패·부재·손상 = operational fail-closed(DO-17 ⑷).
	//    dev/operational의 자동 진행 여부(사람 승인 게이트)는 게이트 2 자기 신고·S3 소유이며,
	//    이 배선은 여기서 막지 않는다 — 여기서 닫는 것은 "모드를 못 읽으면 시작하지 않는다"다.
	dec := DecideMode(ctx, c.d.Mode, target)
	if dec.FailClosed {
		c.reject(ctx, req.RequestID, target, m.CommitSHA, 0, "모드 판정 fail-closed(저장 접근·부재·손상)")
		return Result{Outcome: OutcomeFailClosed, Detail: "모드 판정 fail-closed"}
	}

	// 3. 배포 창 락 획득(CD-4 ①). 경합 = 기록할 거절(오류 아님) · 연결·권한 오류 = fail-closed.
	hold, held, err := AcquireWindow(ctx, c.d.Lock, c.d.HolderID, c.d.Lease)
	if err != nil {
		c.reject(ctx, req.RequestID, target, m.CommitSHA, 0, "락 획득 오류(fail-closed): "+err.Error())
		return Result{Outcome: OutcomeFailClosed, Detail: "락 획득 오류"}
	}
	if !held {
		c.reject(ctx, req.RequestID, target, m.CommitSHA, 0, "배포 창 락 경합(다른 배포·배치 점유)")
		return Result{Outcome: OutcomeLockContended, Detail: "배포 창 락 경합"}
	}
	// 락을 잡은 뒤의 종료 경로는 원칙적으로 락을 해제한다(전환 전 실패 = 락 해제 — CD-4).
	// 단 UNKNOWN(전환 이후 상태 불명)만 락을 유지한다 — 아래에서 releaseLock을 끈다.
	releaseLock := true
	defer func() {
		if !releaseLock {
			return
		}
		// 해제는 요청 ctx와 분리한다 — 요청이 취소됐어도 락은 반드시 놓아야 한다. 취소된
		// 요청 ctx를 재사용하면 해제가 즉시 실패해 락이 lease 만료까지 누수된다. 결과를
		// 확인해 실패는 남긴다(치명적이진 않다 — lease 만료가 그 행을 회수한다. CD-3 stale 회수).
		rctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		defer cancel()
		if released, rerr := hold.Release(rctx); rerr != nil || !released {
			log.Printf("deploy: 배포 창 락 해제 실패(target=%s released=%v err=%v) — lease 만료가 회수한다(CD-3)", target, released, rerr)
		}
	}()

	// 4. 락 획득과 같은 자리에서 mode version 원자 검증(DO-17 ⑵ — 토글-요청 race 차단).
	//    수락 시(DecideMode) 읽은 version이 그대로인지 재확인해, 진행 전 토글을 거절한다.
	mv := VerifyModeUnchanged(ctx, c.d.Mode, target, dec.Version)
	if !mv.OK {
		if mv.FailClosed {
			c.reject(ctx, req.RequestID, target, m.CommitSHA, hold.Token(), "mode version 검증 fail-closed(저장 접근·손상)")
			return Result{Outcome: OutcomeFailClosed, Detail: "mode version 검증 fail-closed"}
		}
		c.reject(ctx, req.RequestID, target, m.CommitSHA, hold.Token(), "적용 직전 mode version 변경(토글-요청 race)")
		return Result{Outcome: OutcomeModeChanged, Detail: "적용 직전 모드 토글"}
	}

	// 5. manifest 검증(DO-18) — 실행 직전 완전성·digest 고정·서명 requestId 일치.
	if err := VerifyManifest(m, req.RequestID); err != nil {
		c.reject(ctx, req.RequestID, target, m.CommitSHA, hold.Token(), "manifest 검증: "+err.Error())
		return Result{Outcome: OutcomeManifestInvalid, Detail: err.Error()}
	}

	// 6. 실행 지점 직전 fencing 재확인(CD-3 「불가역 단계 직전 보유 재확인」). lease가 만료돼
	//    다른 점유자가 진입했거나(held=false) 판정 불가(err)면 dispatch를 시작하지 않는다 —
	//    만료·탈취된 락으로 특권 실행을 여는 것을 막는다(좀비 차단). 시작 전이므로 부작용 0.
	if held2, cerr := hold.Confirm(ctx); cerr != nil {
		c.reject(ctx, req.RequestID, target, m.CommitSHA, hold.Token(), "dispatch 직전 fencing 재확인 오류(fail-closed): "+cerr.Error())
		return Result{Outcome: OutcomeFailClosed, State: StateUnexecuted, Detail: "fencing 재확인 오류 — dispatch 미시작"}
	} else if !held2 {
		c.reject(ctx, req.RequestID, target, m.CommitSHA, hold.Token(), "dispatch 직전 fencing 상실(lease 만료·탈취) — dispatch 미시작")
		return Result{Outcome: OutcomeFailClosed, State: StateUnexecuted, Detail: "fencing 상실(lease 만료·탈취) — dispatch 미시작"}
	}

	// 7. 실행 지점(dispatch — #15). 스텁은 UNEXECUTED(부작용 0)를 낸다. 실행 상태를
	//    이력에 남긴다(DO-16 3상태 기록·조회 골격).
	state, derr := c.d.Dispatcher.Dispatch(ctx, m, hold.Token())

	// dispatch가 정의된 세 상태(UNEXECUTED·COMPLETED·UNKNOWN) 밖의 값(빈 문자열·미지)을 내면
	// 실행 결과를 신뢰할 수 없다 — UNEXECUTED로 오인해 락을 풀면 fail-open이다. UNKNOWN으로
	// 접어(락 유지·사람에게) 이력·재개 분류까지 일관되게 만든다(DO-16 fail-closed).
	switch state {
	case StateUnexecuted, StateCompleted, StateUnknown:
		// 정의된 상태 — 그대로 둔다.
	default:
		state = StateUnknown
	}

	// dispatch 오류 메시지는 UNKNOWN의 유일한 단서다 — "사람 개입 필요"인데 근거가 없으면
	// 개입할 사람이 처음부터 다시 파야 한다(통합에서 실측 — troubleshooting-false-unknown.md).
	// 이력 detail과 반환 Detail 양쪽에 싣는다(무음 금지).
	dispatchDetail := ""
	if derr != nil {
		dispatchDetail = derr.Error()
	}

	// 실행 상태를 이력에 남긴다(DO-16). 이 이력은 재전송 재개 분류(ClassifyReplay)의 유일한
	// durable 근거다 — 쓰기가 실패하면 COMPLETED/미실행을 durable하게 증명할 수 없으므로,
	// 완료로 보고해서는 안 된다. UNKNOWN으로 접어 락을 유지하고 사람에게 올린다(fail-closed).
	// 근거가 남지 않았으니 재전송은 재실행하지 않는다(이력 없음 → REPORT).
	if herr := c.recordDispatch(ctx, req, m, hold.Token(), state, dispatchDetail); herr != nil {
		state = StateUnknown
		// 이력 쓰기 실패로 UNKNOWN이 된 경로 — durable persist는 불가하지만(그 쓰기가 실패했다),
		// 반환 Detail·로그에는 herr을 실어 "왜 UNKNOWN인가"의 단서를 남긴다(리뷰 P2 — 무음 금지).
		// derr이 이미 있으면 이어 붙인다(둘 다 원인일 수 있다).
		if dispatchDetail != "" {
			dispatchDetail += " · 이력 기록 실패: " + herr.Error()
		} else {
			dispatchDetail = "이력 기록 실패: " + herr.Error()
		}
	}

	// state==UNKNOWN을 err 유무보다 먼저 판정한다 — dispatch가 (UNKNOWN, err)를 낼 수 있고,
	// 그때 err 분기가 앞서면 UNKNOWN이 FAIL_CLOSED로 접혀 락이 풀린다. UNKNOWN(전환 이후 상태
	// 불명)은 err가 있어도 오류로 접지 않고 락을 유지한 채 사람에게 올린다(DO-16 ⑵ · CD-4).
	if state == StateUnknown {
		releaseLock = false
		detail := "원격 실행 UNKNOWN — 사람 개입·락 유지"
		if dispatchDetail != "" {
			detail += ": " + dispatchDetail
		}
		return Result{Outcome: OutcomeUnknown, State: state, Detail: detail}
	}
	if derr != nil {
		return Result{Outcome: OutcomeFailClosed, State: state, Detail: "dispatch 오류: " + derr.Error()}
	}
	switch state {
	case StateCompleted:
		return Result{Outcome: OutcomeCompleted, State: state}
	case StateUnexecuted:
		// UNEXECUTED — 실행 지점 도달·실행 미구현(#15). 부작용 0이므로 락은 해제한다.
		return Result{Outcome: OutcomeReachedDispatch, State: state, Detail: "실행 지점 도달·dispatch 미구현(#15)"}
	default:
		// 위에서 정의 밖 상태를 UNKNOWN으로 접었고 UNKNOWN은 이미 반환했으므로 여기에 닿지
		// 않는다 — 도달 불가 경로도 UNEXECUTED로 오인해 락을 풀지 않는다(방어적 fail-closed).
		releaseLock = false
		return Result{Outcome: OutcomeUnknown, State: StateUnknown, Detail: "원격 실행 상태 정의 밖 — 사람 개입·락 유지"}
	}
}

// ResumeAction은 이미 예약된(재전송) 요청을 어떻게 처리할지다(#9 · DO-16 ⑵).
type ResumeAction string

const (
	// ResumeReexecute는 미실행(부작용 0 증명)이라 같은 requestId로 재개함이다 — 중복
	// 부작용이 없으므로 "재실행 금지"(DO-10 ⑷)에 반하지 않는다: 첫 실행을 완주시킨다.
	ResumeReexecute ResumeAction = "REEXECUTE"
	// ResumeReport는 이미 완료돼 재실행 없이 상태만 반환함이다(DO-10 ⑷ 문자 그대로).
	ResumeReport ResumeAction = "REPORT"
	// ResumeEscalate는 UNKNOWN이라 무턱대고 재시도하지 않고 사람에게 올림이다(DO-16 ⑵).
	ResumeEscalate ResumeAction = "ESCALATE"
)

// ClassifyReplay는 재전송된 요청의 현재 이력 상태로 처리 방식을 정한다(#9 갭 차단).
// 예약(RESERVED) 뒤 수신 실패로 미완이 된 배포는 REEXECUTE로 완주시키고, 완료·UNKNOWN·
// 이력 없음은 재개하지 않는다:
//   - RESERVED / STEP_RESULT(UNEXECUTED) → REEXECUTE — 예약됐으나 미실행(부작용 0 증명)이라
//     같은 requestId로 재개해 완주시킨다(중복 부작용 없음 — dispatcher는 requestId 단위 멱등).
//   - COMPLETED                          → REPORT — 이미 완료, 재실행 없이 상태 반환(DO-10 ⑷).
//   - UNKNOWN                            → ESCALATE — 무턱대고 재시도하지 않는다(DO-16 ⑵).
//   - 그 외(이력 없음 포함)              → REPORT — 이 requestId가 예약된 적 없다는 뜻이다.
//     특히 jti 재사용(새 requestId·재사용 토큰)은 새 requestId가 미예약이므로, 재개하면
//     예약 없이 부작용을 여는 셈이 된다 — 재개하지 않고 상태만 반환한다(예약-우선 불변식).
//
// [#9 한계 — 이 PR이 닫지 않는다] default 분기의 "이력 없음=미예약"(→REPORT)은 호출 문맥인
// handleReplay의 "ErrReplay=예약 확정"과 어긋난다. 예약(reserve)과 RESERVED 이력 append가
// 별개 쓰기라, 예약은 됐는데 RESERVED 이력이 유실되면 재전송이 REEXECUTE 대신 REPORT로 빠져
// 미완 배포가 stranded되고, post-reserve 거절은 그 requestId를 오염시킨다(liveness trap).
// 이 갭은 reserve+락+mode version+이력을 하나의 트랜잭션으로 묶고 실행 상태를 durable하게
// 원자 기록해야 닫히며(DO-17 §2.2 — [구현 검증] 이연), 그 원자 기록은 실제 dispatch를
// 소유하는 S2-3의 몫이다. #14/이 PR은 그 원자성을 성립시키지 못하므로 #9를 닫지 않는다.
func ClassifyReplay(latest store.HistoryEvent) ResumeAction {
	switch {
	case latest.EventType == string(OutcomeUnknown) || latest.Result == string(StateUnknown):
		return ResumeEscalate
	case latest.EventType == "RESERVED":
		return ResumeReexecute
	case latest.EventType == "STEP_RESULT" && latest.Result == string(StateUnexecuted):
		return ResumeReexecute
	default:
		return ResumeReport
	}
}

// reject는 거절을 이력에 남긴다(RL-8). append 실패는 삼키되 — 거절 자체는 확정이므로
// 통과로 뒤집지 않는다(fail-closed).
func (c coordinator) reject(ctx context.Context, requestID, target, commit string, token store.FencingToken, reason string) {
	ev := store.HistoryEvent{
		RequestID:    requestID,
		EventType:    "REJECTED",
		CommitSHA:    commit,
		RejectReason: reason,
		FencingToken: token,
	}
	if target != "" {
		ev.Target = target
	}
	_ = c.d.History.AppendEvent(ctx, ev)
}

// recordDispatch는 실행 지점의 상태를 이력에 남긴다(DO-16 3상태 기록). event_type은 상태에
// 따라 갈라 재전송 분류(ClassifyReplay)가 최신 이력만으로 판정 가능하게 한다. 쓰기 오류를
// 반환하며(무음 삼킴 금지), 호출자는 그 실패를 COMPLETED로 보고하지 않고 UNKNOWN으로 접는다.
func (c coordinator) recordDispatch(ctx context.Context, req Request, m Manifest, token store.FencingToken, state RemoteState, detail string) error {
	ev := store.HistoryEvent{
		RequestID:      req.RequestID,
		Target:         string(m.Target),
		CommitSHA:      m.CommitSHA,
		ManifestDigest: m.ImageDigest,
		Step:           "dispatch",
		Result:         string(state),
		Detail:         detail,
		FencingToken:   token,
	}
	switch state {
	case StateCompleted:
		ev.EventType = string(OutcomeCompleted)
	case StateUnknown:
		ev.EventType = string(OutcomeUnknown)
	default:
		ev.EventType = "STEP_RESULT"
	}
	return c.d.History.AppendEvent(ctx, ev)
}
