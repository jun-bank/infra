// LocalDispatcher(실 실행 지점)의 단위 테스트 — DO-16 3상태 매핑을 페이크 실행기/헬스로
// 검증한다. 실제 docker·HTTP를 돌리지 않는다. 치명 실패는 UNEXECUTED로 오인해 락을
// 푸는 것과 UNKNOWN에서 스스로 재시도하는 것이다.
package deploy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jun-bank/infra/internal/store"
)

// fakeExec는 HostExecutor 페이크다 — 호출 인자·횟수를 포착하고 설정된 오류를 낸다.
type fakeExec struct {
	pullRef string
	upRef   string
	pullErr error
	upErr   error
	downErr error
	pulls   int
	ups     int
	downs   int
}

func (f *fakeExec) Pull(_ context.Context, ref string) error {
	f.pulls++
	f.pullRef = ref
	return f.pullErr
}
func (f *fakeExec) Up(_ context.Context, ref string) error {
	f.ups++
	f.upRef = ref
	return f.upErr
}
func (f *fakeExec) Down(context.Context) error {
	f.downs++
	return f.downErr
}

type fakeHealth struct{ err error }

func (f fakeHealth) Check(context.Context) error { return f.err }

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
	d := LocalDispatcher{Exec: x, Health: h, Repos: repos()}
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
	d := LocalDispatcher{Exec: x, Health: fakeHealth{}, Repos: map[Target]string{}}
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

// LocalDispatcher는 Dispatcher 계약을 만족하고 coordinator에 그대로 꽂힌다.
func TestLocalDispatcherSatisfiesInterface(t *testing.T) {
	var _ Dispatcher = LocalDispatcher{}
}
