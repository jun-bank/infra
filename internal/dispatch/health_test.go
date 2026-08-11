// CD-1 헬스 판정의 단위 테스트 — 순수 판정(healthEval.observe)과 프로브 루프(Check)를
// 실제 네트워크 없이 검증한다. 그린 위장 방어(재시작 증가 → FAIL)가 핵심이다.
package dispatch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// --- 순수 판정 -----------------------------------------------------------------

func TestObserveConsecutive(t *testing.T) {
	h := &healthEval{threshold: 3}
	for i, ok := range []bool{true, true} {
		if done, _ := h.observe(ok); done {
			t.Fatalf("표본 %d에서 조기 종료", i)
		}
	}
	done, healthy := h.observe(true)
	if !done || !healthy {
		t.Fatalf("연속 3회 후 done=%v healthy=%v, 통과 기대", done, healthy)
	}
}

func TestObserveResetOnFail(t *testing.T) {
	h := &healthEval{threshold: 3}
	seq := []bool{true, true, false, true, true} // 실패가 연속을 리셋
	for _, ok := range seq {
		if done, _ := h.observe(ok); done {
			t.Fatal("리셋 전 조기 통과")
		}
	}
	if done, healthy := h.observe(true); !done || !healthy {
		t.Fatal("리셋 후 연속 3회 재달성 시 통과해야 한다")
	}
}

// --- 프로브 루프(페이크 IO) ----------------------------------------------------

type fakeHTTP struct {
	codes []int // 순서대로; 소진되면 마지막 반복
	i     int
	err   error
}

func (f *fakeHTTP) Do(*http.Request) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	code := f.codes[len(f.codes)-1]
	if f.i < len(f.codes) {
		code = f.codes[f.i]
	}
	f.i++
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(""))}, nil
}

type fakeRestart struct {
	counts     []int // 단일 컨테이너의 호출별 재시작 횟수(소진되면 마지막 반복)
	i          int
	err        error    // RestartCount 오류
	containers []string // GreenContainers가 줄 컨테이너 목록(nil이면 기본 1개)
	greenErr   error    // GreenContainers 오류
}

func (f *fakeRestart) GreenContainers(context.Context) ([]string, error) {
	if f.greenErr != nil {
		return nil, f.greenErr
	}
	if f.containers != nil {
		return f.containers, nil
	}
	return []string{"core-green-app-1"}, nil
}

func (f *fakeRestart) RestartCount(context.Context, string) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	c := f.counts[len(f.counts)-1]
	if f.i < len(f.counts) {
		c = f.counts[f.i]
	}
	f.i++
	return c, nil
}

func fastHealthCfg() HealthConfig {
	return HealthConfig{
		URL:              "http://green.local/ready",
		SuccessThreshold: 2,
		Interval:         1 * time.Millisecond,
		Timeout:          50 * time.Millisecond,
		Deadline:         200 * time.Millisecond,
	}
}

func TestCheckHealthy(t *testing.T) {
	p := &Prober{cfg: fastHealthCfg(), http: &fakeHTTP{codes: []int{200}}, restarts: &fakeRestart{counts: []int{2}}}
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("정상 경로 헬스 실패: %v", err)
	}
}

func TestCheckTimeout(t *testing.T) {
	cfg := fastHealthCfg()
	cfg.Deadline = 30 * time.Millisecond
	cfg.Interval = 5 * time.Millisecond
	p := &Prober{cfg: cfg, http: &fakeHTTP{codes: []int{500}}, restarts: &fakeRestart{counts: []int{0}}}
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("비2xx 지속인데 상한 초과 실패가 나지 않음")
	}
}

func TestCheckRestartIncreaseFails(t *testing.T) {
	p := &Prober{cfg: fastHealthCfg(), http: &fakeHTTP{codes: []int{200}}, restarts: &fakeRestart{counts: []int{0, 1, 2}}}
	err := p.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "재시작") {
		t.Fatalf("재시작 증가인데 실패 사유 없음: %v", err)
	}
}

func TestCheckRestartReadErrorFails(t *testing.T) {
	p := &Prober{cfg: fastHealthCfg(), http: &fakeHTTP{codes: []int{200}}, restarts: &fakeRestart{err: errors.New("inspect 실패")}}
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("재시작 조회 실패인데 헬스가 통과로 넘어감(판정 불가 = 실패여야 한다)")
	}
}

// C3: green 컨테이너를 확정하지 못하면 재시작 방어선이 성립하지 않는다 → fail-closed
// (통과로 넘기지 않는다). 예전엔 ContainerName이 비면 검사를 통째로 생략했다.
func TestCheckGreenContainersErrorFailsClosed(t *testing.T) {
	p := &Prober{cfg: fastHealthCfg(), http: &fakeHTTP{codes: []int{200}}, restarts: &fakeRestart{greenErr: errors.New("ps -q 실패"), counts: []int{0}}}
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("green 컨테이너 확정 실패인데 헬스 통과(판정 불가 = 실패여야 한다)")
	}
}

// C3: green 컨테이너가 0개면 재시작 검사를 켤 수 없다 → fail-closed.
func TestCheckNoGreenContainersFailsClosed(t *testing.T) {
	p := &Prober{cfg: fastHealthCfg(), http: &fakeHTTP{codes: []int{200}}, restarts: &fakeRestart{containers: []string{}, counts: []int{0}}}
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("green 컨테이너 0개인데 헬스 통과(재시작 검사 불가 = 실패여야 한다)")
	}
}

// C3: 여러 컨테이너 중 하나라도 재시작하면(합 증가) 즉시 실패.
func TestCheckMultiContainerRestartFails(t *testing.T) {
	p := &Prober{
		cfg:      fastHealthCfg(),
		http:     &fakeHTTP{codes: []int{200}},
		restarts: &fakeRestart{containers: []string{"a", "b"}, counts: []int{0, 0, 1}},
	}
	if err := p.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "재시작") {
		t.Fatalf("다중 컨테이너 재시작 감지 실패: %v", err)
	}
}

// C4: baseline을 프로브 루프 전에 읽어, threshold 도달 전이라도 첫 프로브 중 일어난
// 재시작을 놓치지 않는다. threshold=1·counts=[0,1]: 예전엔 첫 표본(count0)으로 baseline을
// 잡으며 동시에 consec=1로 통과해 재시작(count1)을 아예 못 봤다. 이제는 baseline(0)을
// 먼저 고정하고 첫 프로브에서 1>0을 잡아 실패한다.
func TestCheckBaselineReadBeforeFirstProbe(t *testing.T) {
	cfg := fastHealthCfg()
	cfg.SuccessThreshold = 1
	p := &Prober{cfg: cfg, http: &fakeHTTP{codes: []int{200}}, restarts: &fakeRestart{counts: []int{0, 1}}}
	if err := p.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "재시작") {
		t.Fatalf("첫 프로브 중 재시작을 놓침(baseline이 대기 시작에 안 잡힘): %v", err)
	}
}

// O3: 0 이하 duration은 busy-loop·즉시 만료를 만든다 → 진입에서 거부한다.
func TestCheckRejectsNonPositiveDurations(t *testing.T) {
	for _, mut := range []func(*HealthConfig){
		func(c *HealthConfig) { c.Interval = 0 },
		func(c *HealthConfig) { c.Deadline = 0 },
		func(c *HealthConfig) { c.Timeout = 0 },
		func(c *HealthConfig) { c.Interval = -1 },
	} {
		cfg := fastHealthCfg()
		mut(&cfg)
		p := &Prober{cfg: cfg, http: &fakeHTTP{codes: []int{200}}, restarts: &fakeRestart{counts: []int{0}}}
		if err := p.Check(context.Background()); err == nil {
			t.Fatalf("0 이하 duration인데 통과: %+v", cfg)
		}
	}
}
