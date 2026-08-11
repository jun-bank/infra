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
		done, _, _ := h.observe(ok, 0, false)
		if done {
			t.Fatalf("표본 %d에서 조기 종료", i)
		}
	}
	done, healthy, _ := h.observe(true, 0, false)
	if !done || !healthy {
		t.Fatalf("연속 3회 후 done=%v healthy=%v, 통과 기대", done, healthy)
	}
}

func TestObserveResetOnFail(t *testing.T) {
	h := &healthEval{threshold: 3}
	seq := []bool{true, true, false, true, true} // 실패가 연속을 리셋
	for _, ok := range seq {
		if done, _, _ := h.observe(ok, 0, false); done {
			t.Fatal("리셋 전 조기 통과")
		}
	}
	if done, healthy, _ := h.observe(true, 0, false); !done || !healthy {
		t.Fatal("리셋 후 연속 3회 재달성 시 통과해야 한다")
	}
}

// Q1: 재시작 횟수가 증가하면 2xx여도 즉시 FAIL(그린 위장 방어).
func TestObserveRestartIncreaseFails(t *testing.T) {
	h := &healthEval{threshold: 2}
	if done, _, _ := h.observe(true, 0, true); done { // baseline=0, consec=1
		t.Fatal("baseline 표본에서 조기 종료")
	}
	done, healthy, reason := h.observe(true, 1, true) // 재시작 증가
	if !done || healthy {
		t.Fatalf("재시작 증가인데 done=%v healthy=%v, FAIL 기대", done, healthy)
	}
	if !strings.Contains(reason, "재시작") {
		t.Fatalf("사유에 재시작 언급 없음: %q", reason)
	}
}

// Q1: baseline이 0이 아니어도 대기 중 불변이면 통과(==0 강제 아님).
func TestObserveRestartStableNonZero(t *testing.T) {
	h := &healthEval{threshold: 2}
	if done, _, _ := h.observe(true, 3, true); done { // baseline=3
		t.Fatal("조기 종료")
	}
	if done, healthy, _ := h.observe(true, 3, true); !done || !healthy {
		t.Fatal("baseline 3 불변인데 통과 실패 — ==0 강제 오탐")
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
	counts []int
	i      int
	err    error
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
		ContainerName:    "core-green-app-1",
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

// ContainerName 미설정이면 재시작 검사를 생략하고 HTTP만으로 판정한다.
func TestCheckNoContainerSkipsRestart(t *testing.T) {
	cfg := fastHealthCfg()
	cfg.ContainerName = ""
	// restarts가 nil이어도 호출되지 않아야 한다.
	p := &Prober{cfg: cfg, http: &fakeHTTP{codes: []int{200}}, restarts: nil}
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("컨테이너 미설정 정상 경로 실패: %v", err)
	}
}
