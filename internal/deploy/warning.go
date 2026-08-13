package deploy

import (
	"context"
	"sync"
)

// 배포 결과를 **뒤집지 않는** 경고를 실행 지점에서 오케스트레이션 층까지 나르는 채널이다.
//
// 왜 별도 채널인가: dispatch의 반환은 (상태, 오류) 둘뿐이고, 그 조합은 이미 의미가 꽉 차
// 있다 — (COMPLETED, err≠nil)은 "완료했다"와 "실패했다"를 동시에 주장하는 모순 조합이라
// coordinator가 UNKNOWN으로 정규화한다(락 유지·사람 개입). 그래서 "배포는 성공했는데
// 부수 기록이 실패했다"를 오류로 실으면 정상 배포가 사람을 부르는 사고로 둔갑한다.
// 반대로 로그로만 남기면 이력에 아무것도 남지 않아, 나중에 "이 배포의 복원 재료가 왜
// 없는가"를 되짚을 근거가 사라진다.
//
// 그 사이를 여는 것이 이 채널이다: 결과 판정에는 관여하지 않고 이력 detail에만 실린다.
// context로 나르는 이유는 Dispatcher 인터페이스(#15부터의 계약)를 건드리지 않기 위해서다 —
// 경고를 낼 수 있는 구현과 그러지 않는 구현이 같은 서명을 유지한다.

// warningKey는 context 값 키다(외부에서 덮어쓸 수 없도록 unexported 타입).
type warningKey struct{}

// warningSink는 한 요청 동안 모인 경고 코드들이다.
type warningSink struct {
	mu    sync.Mutex
	codes []string
}

// withWarnings는 요청 ctx에 경고 수집기를 붙인다(coordinator가 dispatch 직전에 부른다).
func withWarnings(ctx context.Context) (context.Context, *warningSink) {
	s := &warningSink{}
	return context.WithValue(ctx, warningKey{}, s), s
}

// addWarning은 경고 코드를 남긴다. 수집기가 없으면(경고를 소비하지 않는 호출 경로) 조용히
// 버린다 — 경고 때문에 실행이 실패하는 일은 없어야 한다.
func addWarning(ctx context.Context, code string) {
	s, ok := ctx.Value(warningKey{}).(*warningSink)
	if !ok || s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes = append(s.codes, code)
}

// list는 모인 경고 코드를 순서대로 준다.
func (s *warningSink) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.codes...)
}
