// LocalDispatcher(실 실행 지점)의 단위 테스트 — DO-16 3상태 매핑을 페이크 실행기/헬스로
// 검증한다. 실제 docker·HTTP를 돌리지 않는다. 치명 실패는 UNEXECUTED로 오인해 락을
// 푸는 것과 UNKNOWN에서 스스로 재시도하는 것이다.
package deploy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/store"
)

// fakeExec는 HostExecutor 페이크다 — 호출 인자·횟수를 포착하고 설정된 오류를 낸다.
// name·log가 설정되면 호출을 공유 로그에 순서대로 남긴다(전환 시퀀스 순서 검증용).
type fakeExec struct {
	name        string    // 슬롯 이름(순서 로그에 "blue:down" 식으로 남는다)
	log         *[]string // nil이 아니면 각 호출을 순서대로 append
	pullRef     string
	upRef       string
	verifyRef   string
	pullErr     error
	upErr       error
	verifyErr   error
	downErr     error
	pulls       int
	ups         int
	verifies    int
	downs       int
	downAt      time.Time // 마지막 Down 시각(드레인이 down 앞에 있는지 검증 — CD-4 ⑥→⑨).
	downCtxErr  error     // 마지막 Down에 넘어온 context의 Err()(취소된 ctx 재사용 감시 — O1).
	blockUp     bool      // true면 Up이 ctx.Done까지 블록하고 ctx.Err()를 낸다(phase budget 초과 재현).
	blockVerify bool      // true면 VerifyImageDigest가 ctx.Done까지 블록한다(phase budget이 verify를 상한하는지 — H1).
}

// record는 호출을 공유 순서 로그에 남긴다(log가 nil이면 아무것도 하지 않는다).
func (f *fakeExec) record(step string) {
	if f.log == nil {
		return
	}
	if f.name != "" {
		step = f.name + ":" + step
	}
	*f.log = append(*f.log, step)
}

func (f *fakeExec) Pull(_ context.Context, ref string) error {
	f.pulls++
	f.pullRef = ref
	f.record("pull")
	return f.pullErr
}
func (f *fakeExec) Up(ctx context.Context, ref string) error {
	f.ups++
	f.upRef = ref
	f.record("up")
	if f.blockUp {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.upErr
}
func (f *fakeExec) VerifyImageDigest(ctx context.Context, ref string) error {
	f.verifies++
	f.verifyRef = ref
	f.record("verify")
	if f.blockVerify {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.verifyErr
}
func (f *fakeExec) Down(ctx context.Context) error {
	f.downs++
	f.downAt = time.Now()
	f.downCtxErr = ctx.Err()
	f.record("down")
	return f.downErr
}

type fakeHealth struct {
	err  error
	name string
	log  *[]string
}

func (f fakeHealth) Check(context.Context) error {
	if f.log != nil {
		step := "health"
		if f.name != "" {
			step = f.name + ":" + step
		}
		*f.log = append(*f.log, step)
	}
	return f.err
}

func manifest(digest string) Manifest {
	return Manifest{
		Target:          TargetCore,
		CommitSHA:       "abc123",
		ImageDigest:     digest,
		ComposeRevision: "rev1",
		ConfigVersion:   "v1",
		RequestID:       "req-1",
	}
}

func repos() map[Target]string {
	return map[Target]string{TargetCore: "registry.example/core"}
}

func dispatch(t *testing.T, x *fakeExec, h fakeHealth, m Manifest) (RemoteState, error) {
	t.Helper()
	d := LocalDispatcher{Exec: x, Health: h, Repos: repos(), PhaseBudget: time.Minute}
	return d.Dispatch(context.Background(), m, store.FencingToken(1))
}

// 정상 경로: pull → up → 헬스 통과 = COMPLETED. 이미지 참조 = repo@digest.
func TestDispatchCompleted(t *testing.T) {
	x := &fakeExec{}
	st, err := dispatch(t, x, fakeHealth{}, manifest(validDigest))
	if st != StateCompleted || err != nil {
		t.Fatalf("정상 경로: state=%v err=%v, COMPLETED·nil 기대", st, err)
	}
	wantRef := "registry.example/core@" + validDigest
	if x.pullRef != wantRef || x.upRef != wantRef {
		t.Fatalf("이미지 참조 pull=%q up=%q, 기대 %q(DO-18 digest 고정)", x.pullRef, x.upRef, wantRef)
	}
	if x.downs != 0 {
		t.Fatalf("성공 경로인데 down 호출됨(%d)", x.downs)
	}
}

// repo 미설정 = 부작용 0 = UNEXECUTED. pull도 부르지 않는다.
func TestDispatchRepoMissing(t *testing.T) {
	x := &fakeExec{}
	d := LocalDispatcher{Exec: x, Health: fakeHealth{}, Repos: map[Target]string{}, PhaseBudget: time.Minute}
	st, err := d.Dispatch(context.Background(), manifest(validDigest), store.FencingToken(1))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("repo 미설정: state=%v err=%v, UNEXECUTED·err 기대", st, err)
	}
	if x.pulls != 0 {
		t.Fatal("repo 미설정인데 pull 호출됨(부작용 0 위반)")
	}
}

// digest 형식 위반(태그·짧은·비hex·latest·빈값) = UNEXECUTED, pull 미호출(방어적 고정).
func TestDispatchRejectsNonDigest(t *testing.T) {
	bad := []string{
		"sha256:latest",
		"sha256:abc",
		"sha256:" + strings.Repeat("g", 64), // 비hex
		"v1.2.3",
		"latest",
		"",
	}
	for _, dg := range bad {
		x := &fakeExec{}
		st, err := dispatch(t, x, fakeHealth{}, manifest(dg))
		if st != StateUnexecuted || err == nil {
			t.Fatalf("digest %q: state=%v err=%v, UNEXECUTED·err 기대(태그·오타 실행 금지)", dg, st, err)
		}
		if x.pulls != 0 {
			t.Fatalf("digest %q인데 pull 호출됨(%d)", dg, x.pulls)
		}
	}
}

// pull 실패 = 부작용 0(compose 미접촉) = UNEXECUTED. up 미호출.
func TestDispatchPullFailUnexecuted(t *testing.T) {
	x := &fakeExec{pullErr: errors.New("digest not found")}
	st, err := dispatch(t, x, fakeHealth{}, manifest(validDigest))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("pull 실패: state=%v, UNEXECUTED 기대", st)
	}
	if x.ups != 0 {
		t.Fatal("pull 실패인데 up 호출됨")
	}
}

// up 실패 + down 성공 = 미전환·net0 = UNEXECUTED.
func TestDispatchUpFailDownOK(t *testing.T) {
	x := &fakeExec{upErr: errors.New("up 실패")}
	st, err := dispatch(t, x, fakeHealth{}, manifest(validDigest))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("up 실패·down 성공: state=%v, UNEXECUTED 기대", st)
	}
	if x.downs != 1 {
		t.Fatalf("정리 down 호출 = %d, 기대 1", x.downs)
	}
}

// up 실패 + down 실패 = green 잔존 가능 = UNKNOWN. 변이 명령은 각 1회만(Q4 — 재시도 금지).
func TestDispatchUpFailDownFailUnknown(t *testing.T) {
	x := &fakeExec{upErr: errors.New("up 실패"), downErr: errors.New("down 실패")}
	st, err := dispatch(t, x, fakeHealth{}, manifest(validDigest))
	if st != StateUnknown || err == nil {
		t.Fatalf("up 실패·down 실패: state=%v, UNKNOWN 기대", st)
	}
	if x.pulls != 1 || x.ups != 1 || x.downs != 1 {
		t.Fatalf("UNKNOWN에서 변이 명령 재실행됨 pull=%d up=%d down=%d, 각 1회 기대(Q4)", x.pulls, x.ups, x.downs)
	}
}

// 헬스 실패 + down 성공 = 미전환(롤백 아님) = UNEXECUTED.
func TestDispatchHealthFailDownOK(t *testing.T) {
	x := &fakeExec{}
	st, err := dispatch(t, x, fakeHealth{err: errors.New("헬스 실패")}, manifest(validDigest))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("헬스 실패·down 성공: state=%v, UNEXECUTED 기대", st)
	}
	if x.downs != 1 {
		t.Fatalf("green 종료 down = %d, 기대 1(CD-4 ④)", x.downs)
	}
}

// 헬스 실패 + down 실패 = green 잔존 가능 = UNKNOWN.
func TestDispatchHealthFailDownFailUnknown(t *testing.T) {
	x := &fakeExec{downErr: errors.New("down 실패")}
	st, err := dispatch(t, x, fakeHealth{err: errors.New("헬스 실패")}, manifest(validDigest))
	if st != StateUnknown || err == nil {
		t.Fatalf("헬스 실패·down 실패: state=%v, UNKNOWN 기대", st)
	}
}

// C2: up 후 이미지 대조 실패 + down 성공 = 미전환·net0 = UNEXECUTED(silent COMPLETED 차단).
// 헬스는 통과하도록 두어, 대조가 없으면 엉뚱한 이미지가 COMPLETED로 위장함을 재현한다.
func TestDispatchImageMismatchDownOK(t *testing.T) {
	x := &fakeExec{verifyErr: errors.New("실행 이미지가 pinned digest와 불일치")}
	st, err := dispatch(t, x, fakeHealth{}, manifest(validDigest))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("이미지 불일치·down 성공: state=%v err=%v, UNEXECUTED·err 기대(silent COMPLETED 차단)", st, err)
	}
	if x.verifies != 1 {
		t.Fatalf("이미지 대조 호출 = %d, 기대 1(up 후 헬스 전)", x.verifies)
	}
	if x.downs != 1 {
		t.Fatalf("정리 down = %d, 기대 1", x.downs)
	}
	// 대조가 up 뒤·헬스 전이므로, 대조 실패 시 헬스는 부르지 않는다(down으로 미전환).
}

// C2: 이미지 대조 실패 + down 실패 = green 잔존 가능 = UNKNOWN.
func TestDispatchImageMismatchDownFailUnknown(t *testing.T) {
	x := &fakeExec{verifyErr: errors.New("불일치"), downErr: errors.New("down 실패")}
	st, err := dispatch(t, x, fakeHealth{}, manifest(validDigest))
	if st != StateUnknown || err == nil {
		t.Fatalf("이미지 불일치·down 실패: state=%v, UNKNOWN 기대", st)
	}
}

// C2: 정상 경로에서도 이미지 대조가 pinned 참조로 정확히 1회 호출된다.
func TestDispatchVerifiesImageOnSuccess(t *testing.T) {
	x := &fakeExec{}
	st, err := dispatch(t, x, fakeHealth{}, manifest(validDigest))
	if st != StateCompleted || err != nil {
		t.Fatalf("정상 경로: state=%v err=%v, COMPLETED 기대", st, err)
	}
	wantRef := "registry.example/core@" + validDigest
	if x.verifies != 1 || x.verifyRef != wantRef {
		t.Fatalf("이미지 대조 verifies=%d ref=%q, 기대 1·%q", x.verifies, x.verifyRef, wantRef)
	}
}

// O1: 요청 ctx가 취소돼도 정리 down은 detached ctx로 완주해야 한다(net-0 복원 성립).
// 취소된 ctx로 up 실패 → 정리 down이 받은 ctx가 취소돼 있지 않음을 확인한다.
func TestDispatchCleanupDownUsesDetachedCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 요청 ctx를 미리 취소한다.
	x := &fakeExec{upErr: errors.New("up 실패")}
	d := LocalDispatcher{Exec: x, Health: fakeHealth{}, Repos: repos(), PhaseBudget: time.Minute}
	st, err := d.Dispatch(ctx, manifest(validDigest), store.FencingToken(1))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("취소 ctx·up 실패·down 성공: state=%v, UNEXECUTED 기대(정리 완주)", st)
	}
	if x.downs != 1 {
		t.Fatalf("정리 down = %d, 기대 1", x.downs)
	}
	if x.downCtxErr != nil {
		t.Fatalf("정리 down이 취소된 ctx를 재사용함(Err=%v) — detached ctx여야 한다(O1)", x.downCtxErr)
	}
}

// P3: pull+up이 phase budget을 초과하면(느린 up) phaseCtx가 취소돼 up이 실패로 접히고,
// 정리 down이 (요청 ctx가 아니라 detached로) 완주해 미전환·net0 = UNEXECUTED가 된다.
// 이로써 상한 없는 up이 lease 마진을 무한정 넘겨 락이 만료되는 일이 구조적으로 막힌다.
func TestDispatchPhaseBudgetTimeoutUpCleanup(t *testing.T) {
	x := &fakeExec{blockUp: true}
	d := LocalDispatcher{Exec: x, Health: fakeHealth{}, Repos: repos(), PhaseBudget: 10 * time.Millisecond}
	st, err := d.Dispatch(context.Background(), manifest(validDigest), store.FencingToken(1))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("phase budget 초과 up: state=%v err=%v, UNEXECUTED 기대(정리 완주)", st, err)
	}
	if x.ups != 1 {
		t.Fatalf("up 호출 = %d, 기대 1", x.ups)
	}
	if x.downs != 1 {
		t.Fatalf("phase budget 초과 후 정리 down = %d, 기대 1", x.downs)
	}
	if x.downCtxErr != nil {
		t.Fatalf("정리 down이 취소된 ctx를 재사용함(Err=%v) — detached ctx여야 한다", x.downCtxErr)
	}
}

// H1: VerifyImageDigest도 phase budget으로 상한돼야 한다 — 느린 inspect가 lease를 넘기면
// cleanup이 락 만료 뒤 실행될 여지가 생긴다. verify가 블록하면 phaseBudget이 취소해 실패로
// 접히고, 정리 down은 detached ctx로 완주해야 한다.
func TestDispatchPhaseBudgetTimeoutVerifyCleanup(t *testing.T) {
	x := &fakeExec{blockVerify: true}
	d := LocalDispatcher{Exec: x, Health: fakeHealth{}, Repos: repos(), PhaseBudget: 10 * time.Millisecond}
	st, err := d.Dispatch(context.Background(), manifest(validDigest), store.FencingToken(1))
	if err == nil || (st != StateUnexecuted && st != StateUnknown) {
		t.Fatalf("phase budget 초과 verify: state=%v err=%v, UNEXECUTED/UNKNOWN 기대", st, err)
	}
	if x.verifies != 1 {
		t.Fatalf("verify 호출 = %d, 기대 1", x.verifies)
	}
	if x.downs != 1 {
		t.Fatalf("verify 상한 후 정리 down = %d, 기대 1", x.downs)
	}
	if x.downCtxErr != nil {
		t.Fatalf("정리 down이 취소된 ctx 재사용(Err=%v) — detached여야 한다", x.downCtxErr)
	}
}

// LocalDispatcher는 Dispatcher 계약을 만족하고 coordinator에 그대로 꽂힌다.
func TestLocalDispatcherSatisfiesInterface(t *testing.T) {
	var _ Dispatcher = LocalDispatcher{}
}

// ─── 블루-그린 전환(CD-4 ⑤⑥⑨ · ADR-031) ────────────────────────────────────────
//
// 여기서 막는 치명 실패는 넷이다: ⑴ 전환이 CD-1 통과 전에 일어나는 것(BG-2) ⑵ 전환 실패를
// 전환된 것처럼 접는 것(⑤ 실패 = 미전환) ⑶ 전환 성공 후 실패를 UNEXECUTED로 오인해 락을
// 푸는 것(⑤ 이후 = UNKNOWN) ⑷ 구 slot을 끄는 down이 방금 올린 slot을 끄는 것(BG-3 ⑶).

// fakeGateway는 SlotGateway 페이크다 — 조회 결과·전환 오류를 설정하고 호출을 포착한다.
type fakeGateway struct {
	active     string
	activeErr  error
	switchErr  error
	queries    int
	switches   int
	gotSlot    string
	gotToken   uint64
	switchedAt time.Time
	log        *[]string
}

func (g *fakeGateway) ActiveSlot(context.Context) (string, error) {
	g.queries++
	if g.log != nil {
		*g.log = append(*g.log, "gw:active")
	}
	return g.active, g.activeErr
}

func (g *fakeGateway) Switch(_ context.Context, targetSlot string, token uint64) error {
	g.switches++
	g.gotSlot, g.gotToken = targetSlot, token
	g.switchedAt = time.Now()
	if g.log != nil {
		*g.log = append(*g.log, "gw:switch")
	}
	return g.switchErr
}

// bgRig는 블루-그린 배선 한 벌이다(슬롯별 실행기·헬스 + 게이트웨이 + 공유 순서 로그).
type bgRig struct {
	blue, green   *fakeExec
	blueH, greenH fakeHealth
	gw            *fakeGateway
	order         []string
}

const testDrainWait = 30 * time.Millisecond

// newBGRig는 active 슬롯을 지정해 배선을 만든다.
func newBGRig(active Slot) *bgRig {
	r := &bgRig{}
	r.blue = &fakeExec{name: "blue", log: &r.order}
	r.green = &fakeExec{name: "green", log: &r.order}
	r.blueH = fakeHealth{name: "blue", log: &r.order}
	r.greenH = fakeHealth{name: "green", log: &r.order}
	r.gw = &fakeGateway{active: string(active), log: &r.order}
	return r
}

func (r *bgRig) dispatcher() LocalDispatcher {
	return LocalDispatcher{
		Repos:       repos(),
		PhaseBudget: time.Minute,
		Gateway:     r.gw,
		SlotExec:    map[Slot]HostExecutor{SlotBlue: r.blue, SlotGreen: r.green},
		SlotHealth:  map[Slot]HealthChecker{SlotBlue: r.blueH, SlotGreen: r.greenH},
		DrainWait:   testDrainWait,
	}
}

func (r *bgRig) run(t *testing.T) (RemoteState, error) {
	t.Helper()
	return r.dispatcher().Dispatch(context.Background(), manifest(validDigest), store.FencingToken(7))
}

func orderEq(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ⑴ 정상 완주 — active=blue면 green(idle)에 올리고, pull→up→verify→health→switch→드레인→
// 구 slot(blue) down 순으로 끝난다. 전환 요청에는 이 배포의 fencing token이 실린다(BG-4 ⓐ).
func TestDispatchBlueGreenCompletesInOrder(t *testing.T) {
	r := newBGRig(SlotBlue)
	st, err := r.run(t)
	if st != StateCompleted || err != nil {
		t.Fatalf("정상 전환: state=%v err=%v, COMPLETED·nil 기대", st, err)
	}
	want := []string{"gw:active", "green:pull", "green:up", "green:verify", "green:health", "gw:switch", "blue:down"}
	if !orderEq(r.order, want) {
		t.Fatalf("실행 순서=%v\n기대=%v (CD-4 ②③④⑤⑨)", r.order, want)
	}
	if r.gw.gotSlot != string(SlotGreen) {
		t.Fatalf("전환 대상 slot=%q, green 기대(idle에 올린 쪽으로 옮긴다)", r.gw.gotSlot)
	}
	if r.gw.gotToken != 7 {
		t.Fatalf("전환 요청의 fencing token=%d, 7 기대(BG-4 ⓐ — sink-side 검증 근거)", r.gw.gotToken)
	}
	if r.green.downs != 0 {
		t.Fatalf("새 slot(green)이 down됨(%d) — 구 slot만 내려야 한다(BG-3 ⑶)", r.green.downs)
	}
	// ⑥ 드레인이 ⑤와 ⑨ 사이에 실제로 있었나 — 전환 시각과 down 시각의 간격으로 본다.
	if gap := r.blue.downAt.Sub(r.gw.switchedAt); gap < testDrainWait {
		t.Fatalf("전환~구 slot down 간격=%s, 드레인 대기(%s) 이상 기대(CD-4 ⑥이 건너뛰어졌다)", gap, testDrainWait)
	}
}

// active=green이면 반대쪽(blue)에 올리고 green을 내린다 — 슬롯 고정 가정이 없다.
func TestDispatchBlueGreenUsesIdleSlot(t *testing.T) {
	r := newBGRig(SlotGreen)
	st, err := r.run(t)
	if st != StateCompleted || err != nil {
		t.Fatalf("정상 전환: state=%v err=%v, COMPLETED 기대", st, err)
	}
	if r.blue.ups != 1 || r.green.ups != 0 {
		t.Fatalf("active=green인데 up: blue=%d green=%d — idle(blue)에 올려야 한다", r.blue.ups, r.green.ups)
	}
	if r.green.downs != 1 || r.blue.downs != 0 {
		t.Fatalf("구 slot 종료: green=%d blue=%d, green만 1 기대", r.green.downs, r.blue.downs)
	}
}

// ⑵ 전환 실패(409 stale 포함) = 미전환 — 올린 slot을 정리하고 UNEXECUTED. 구 slot은
// 손대지 않는다(살아 있는 blue를 끄면 서비스가 죽는다).
func TestDispatchBlueGreenSwitchFailCleansGreen(t *testing.T) {
	r := newBGRig(SlotBlue)
	r.gw.switchErr = errors.New("409 stale fencing token")
	st, err := r.run(t)
	if st != StateUnexecuted || err == nil {
		t.Fatalf("전환 실패: state=%v err=%v, UNEXECUTED·err 기대(미전환)", st, err)
	}
	if r.green.downs != 1 {
		t.Fatalf("green 정리 down=%d, 1 기대(CD-4 ⑤ 실패 = green 종료·미전환)", r.green.downs)
	}
	if r.blue.downs != 0 {
		t.Fatalf("구 active(blue)를 내렸다(%d) — 전환되지 않았으므로 blue가 서비스 중이다", r.blue.downs)
	}
	if !strings.Contains(err.Error(), "⑤") {
		t.Fatalf("오류에 실패 단계가 없다: %v", err)
	}
}

// 전환 실패 + green 정리 실패 = green 잔존 가능 = UNKNOWN.
func TestDispatchBlueGreenSwitchFailCleanupFailUnknown(t *testing.T) {
	r := newBGRig(SlotBlue)
	r.gw.switchErr = errors.New("500")
	r.green.downErr = errors.New("down 실패")
	st, err := r.run(t)
	if st != StateUnknown || err == nil {
		t.Fatalf("전환 실패·정리 실패: state=%v, UNKNOWN 기대", st)
	}
}

// ⑶ 전환 성공 후 구 slot down 실패 = 신·구 두 프로세스 생존 가능 = UNKNOWN + 단계 명시.
// 여기서 UNEXECUTED로 접으면 coordinator가 락을 풀어 라우트가 옮겨진 채로 다음 배포가 들어온다.
func TestDispatchBlueGreenDownFailAfterSwitchUnknown(t *testing.T) {
	r := newBGRig(SlotBlue)
	r.blue.downErr = errors.New("compose down 실패")
	st, err := r.run(t)
	if st != StateUnknown || err == nil {
		t.Fatalf("전환 성공·구 slot down 실패: state=%v err=%v, UNKNOWN·err 기대(락 유지·사람)", st, err)
	}
	if !strings.Contains(err.Error(), "⑨") || !strings.Contains(err.Error(), "전환") {
		t.Fatalf("UNKNOWN 오류에 단계(⑨ · 전환 성공 사실)가 없다 — 사람 개입의 유일한 단서다: %v", err)
	}
	if r.green.downs != 0 {
		t.Fatalf("전환 뒤인데 새 slot(green)을 내렸다(%d) — 트래픽이 가는 쪽이다", r.green.downs)
	}
}

// 헬스 실패는 전환 전이다 — 라우트를 건드리지 않고 올린 slot만 정리한다(BG-2).
func TestDispatchBlueGreenHealthFailNoSwitch(t *testing.T) {
	r := newBGRig(SlotBlue)
	r.greenH = fakeHealth{err: errors.New("헬스 실패"), name: "green", log: &r.order}
	st, err := r.run(t)
	if st != StateUnexecuted || err == nil {
		t.Fatalf("헬스 실패: state=%v, UNEXECUTED 기대(미전환)", st)
	}
	if r.gw.switches != 0 {
		t.Fatalf("CD-1 미통과인데 전환 호출됨(%d) — BG-2 위반", r.gw.switches)
	}
	if r.green.downs != 1 {
		t.Fatalf("green 정리 down=%d, 1 기대", r.green.downs)
	}
}

// 게이트웨이 조회 실패 = 배포 시작 전 = 부작용 0 = UNEXECUTED(fail-closed). pull도 안 한다 —
// 어느 쪽이 idle인지 모른 채 올리면 살아 있는 slot을 덮어쓸 수 있다.
func TestDispatchBlueGreenActiveSlotQueryFailUnexecuted(t *testing.T) {
	r := newBGRig(SlotBlue)
	r.gw.activeErr = errors.New("connection refused")
	st, err := r.run(t)
	if st != StateUnexecuted || err == nil {
		t.Fatalf("active slot 조회 실패: state=%v err=%v, UNEXECUTED·err 기대", st, err)
	}
	if r.blue.pulls+r.green.pulls != 0 || r.gw.switches != 0 {
		t.Fatalf("조회 실패인데 부작용 발생 pulls=%d switches=%d", r.blue.pulls+r.green.pulls, r.gw.switches)
	}
}

// 게이트웨이가 낯선 슬롯 이름을 주면 추측하지 않고 거절한다(fail-closed).
func TestDispatchBlueGreenRejectsUnknownSlot(t *testing.T) {
	r := newBGRig(SlotBlue)
	r.gw.active = "red"
	st, err := r.run(t)
	if st != StateUnexecuted || err == nil {
		t.Fatalf("낯선 slot: state=%v err=%v, UNEXECUTED·err 기대", st, err)
	}
	if r.blue.pulls+r.green.pulls != 0 {
		t.Fatal("낯선 slot인데 pull 호출됨(부작용 0 위반)")
	}
}

// 드레인 대기가 0 이하면 in-flight를 절단한다 — 조용히 0으로 돌지 않고 시작 전에 거절한다.
func TestDispatchBlueGreenRejectsZeroDrain(t *testing.T) {
	r := newBGRig(SlotBlue)
	d := r.dispatcher()
	d.DrainWait = 0
	st, err := d.Dispatch(context.Background(), manifest(validDigest), store.FencingToken(1))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("드레인 0: state=%v err=%v, UNEXECUTED·err 기대", st, err)
	}
	if r.gw.queries != 0 || r.green.pulls != 0 {
		t.Fatal("드레인 0인데 조회·pull이 일어났다(부작용 0 위반)")
	}
}

// 슬롯 배선이 빠지면 시작 전에 거절한다(부작용 0).
func TestDispatchBlueGreenRejectsMissingSlotWiring(t *testing.T) {
	r := newBGRig(SlotBlue)
	d := r.dispatcher()
	d.SlotExec = map[Slot]HostExecutor{SlotBlue: r.blue} // green 실행기 누락
	st, err := d.Dispatch(context.Background(), manifest(validDigest), store.FencingToken(1))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("슬롯 배선 부재: state=%v err=%v, UNEXECUTED·err 기대", st, err)
	}
	if r.green.pulls != 0 || r.gw.switches != 0 {
		t.Fatal("배선 부재인데 부작용 발생")
	}
}

// ⑷ 게이트웨이 미설정 = 기존 단일 경로 그대로(하위호환) — 전환 단계가 없고 ④까지가 종단이다.
// (기존 단일 경로 테스트 전부가 이 모드를 덮는다 — 여기서는 슬롯 배선이 있어도 Gateway가
// nil이면 단일 실행기만 쓰인다는 것을 못 박는다.)
func TestDispatchWithoutGatewayKeepsSinglePath(t *testing.T) {
	r := newBGRig(SlotBlue)
	single := &fakeExec{}
	d := r.dispatcher()
	d.Gateway = nil
	d.Exec, d.Health = single, fakeHealth{}
	st, err := d.Dispatch(context.Background(), manifest(validDigest), store.FencingToken(1))
	if st != StateCompleted || err != nil {
		t.Fatalf("게이트웨이 미설정: state=%v err=%v, COMPLETED 기대(기존 동작)", st, err)
	}
	if single.pulls != 1 || single.ups != 1 || single.verifies != 1 {
		t.Fatalf("단일 실행기 호출 pull=%d up=%d verify=%d, 각 1 기대", single.pulls, single.ups, single.verifies)
	}
	if r.gw.queries != 0 || r.gw.switches != 0 || r.blue.downs != 0 || r.green.ups != 0 {
		t.Fatal("게이트웨이 미설정인데 전환 경로가 돌았다")
	}
}

// ⑸ target=gateway는 전환 단계 없이 단일 경로다 — 게이트웨이는 전환 수단의 소유자라
// 자기 자신을 전환할 수 없다(DO-20 ⓐ 재기동 교체).
func TestDispatchGatewayTargetSkipsCutover(t *testing.T) {
	r := newBGRig(SlotBlue)
	single := &fakeExec{}
	d := r.dispatcher()
	d.Exec, d.Health = single, fakeHealth{}
	d.Repos = map[Target]string{TargetGateway: "registry.example/gateway"}

	m := manifest(validDigest)
	m.Target = TargetGateway
	st, err := d.Dispatch(context.Background(), m, store.FencingToken(1))
	if st != StateCompleted || err != nil {
		t.Fatalf("target=gateway: state=%v err=%v, COMPLETED 기대(재기동 교체)", st, err)
	}
	if r.gw.queries != 0 || r.gw.switches != 0 {
		t.Fatalf("게이트웨이 배포인데 전환 API 호출됨(active=%d switch=%d) — 자기 전환 불가(DO-20 ⓐ)", r.gw.queries, r.gw.switches)
	}
	if single.upRef != "registry.example/gateway@"+validDigest {
		t.Fatalf("게이트웨이 이미지 참조=%q", single.upRef)
	}
	if r.blue.downs != 0 || r.green.downs != 0 {
		t.Fatal("게이트웨이 배포가 슬롯을 내렸다")
	}
}

// 게이트웨이 모드인데 단일 경로 배선이 없으면 target=gateway 배포를 조용히 성공시키지 않고
// 요란하게 거절한다(부작용 0).
func TestDispatchGatewayTargetWithoutSingleWiringUnexecuted(t *testing.T) {
	r := newBGRig(SlotBlue)
	d := r.dispatcher()
	d.Repos = map[Target]string{TargetGateway: "registry.example/gateway"}

	m := manifest(validDigest)
	m.Target = TargetGateway
	st, err := d.Dispatch(context.Background(), m, store.FencingToken(1))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("배선 없는 게이트웨이 배포: state=%v err=%v, UNEXECUTED·err 기대", st, err)
	}
}
