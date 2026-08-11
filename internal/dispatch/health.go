package dispatch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CD-1 헬스 판정 — agent 자체의 준비성 프로브다(정본: operations/cicd.md §2.1 CD-1).
//
// 계약(재해석하지 않는다):
//   - 판정 주체 = deploy-agent(기계). green 프로세스가 노출하는 준비성 URL에 GET을 던져
//     2xx가 연속 N회일 때만 통과한다. 전체 대기 상한 D 안에 N회를 못 채우면 실패.
//   - compose 내장 healthcheck를 CD-1로 읽지 않는다 — CD-1은 agent 자체 판정이고 compose
//     healthcheck는 호스트 경보·재시작 정책의 입력이다(§2.1 말미).
//   - ★ 재시작 정책이 판정을 감추지 못하게 한다(그린 위장 방어): 대기 시작 시 컨테이너
//     재시작 횟수를 baseline으로 한 번 읽고, 대기 중 어느 프로브에서든 값이 증가하면
//     즉시 실패로 판정한다(Q1). baseline이 0이 아니어도 대기 중 불변이면 통과한다 —
//     "==0" 을 강제하지 않는다(이미 재시작 이력이 있는 정상 컨테이너 오탐 방지).
//   - ★ 이 방어선은 예외 없이 항상 켜진다: 대상 컨테이너는 compose 프로젝트에서 파생하며
//     (설정 컨테이너명에 의존하지 않는다), 컨테이너를 확정하거나 재시작 횟수를 읽지 못하면
//     통과로 넘기지 않고 fail-closed(헬스 판정 불가 = 실패)한다.
//
// N·T·D 값은 [구현 검증](CDV-1)이며 설정에서 온다.

// HealthConfig는 CD-1 준비성 프로브 설정이다.
type HealthConfig struct {
	// URL은 green 프로세스의 준비성 엔드포인트다(GET). 비면 헬스 판정을 시작할 수 없다.
	URL string
	// SuccessThreshold는 통과에 필요한 연속 2xx 횟수 N이다(≥1).
	SuccessThreshold int
	// Interval은 프로브 간격 T다(>0 — 0이면 busy-loop).
	Interval time.Duration
	// Timeout은 개별 GET의 상한이다(>0).
	Timeout time.Duration
	// Deadline은 전체 대기 상한 D다 — 이 안에 N회를 못 채우면 실패(>0).
	Deadline time.Duration
}

// restartReader는 그린 위장 방어 입력을 읽는 표면이다(Executor가 만족한다): green
// 프로젝트의 컨테이너 목록과 각 컨테이너의 재시작 횟수. 컨테이너명은 설정이 아니라
// compose 프로젝트에서 파생해, 재시작 검사가 항상 실제 뜬 컨테이너를 대상으로 한다.
type restartReader interface {
	GreenContainers(ctx context.Context) ([]string, error)
	RestartCount(ctx context.Context, name string) (int, error)
}

// httpDoer는 프로브 GET을 수행하는 표면이다(*http.Client가 만족한다 · 테스트는 페이크).
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Prober는 CD-1 준비성 판정을 수행한다. deploy.HealthChecker(Check)를 만족한다.
type Prober struct {
	cfg      HealthConfig
	http     httpDoer
	restarts restartReader
}

// NewProber는 기본 http.Client로 Prober를 만든다. restarts는 재시작 횟수를 읽을 실행기다
// (보통 같은 *Executor를 주입한다).
func NewProber(cfg HealthConfig, restarts restartReader) *Prober {
	return &Prober{
		cfg:      cfg,
		http:     &http.Client{Timeout: cfg.Timeout},
		restarts: restarts,
	}
}

// healthEval은 프로브 표본을 받아 연속 2xx 횟수를 세는 순수 상태다(시간·IO 없음 —
// 단위 테스트가 표본 시퀀스로 직접 검증한다). 재시작(그린 위장) 판정은 Check가 baseline
// 대비로 소유한다 — baseline을 대기 시작 전에 한 번 읽어야 하므로 관심사를 분리한다.
type healthEval struct {
	threshold int // N
	consec    int // 현재 연속 2xx 횟수
}

// observe는 한 표본을 반영하고 연속 성공 판정을 갱신한다. done=true·healthy=true면 통과.
func (h *healthEval) observe(ok bool) (done, healthy bool) {
	if ok {
		h.consec++
	} else {
		h.consec = 0
	}
	if h.consec >= h.threshold {
		return true, true
	}
	return false, false
}

// sumRestarts는 green 컨테이너 전체의 재시작 횟수 합을 읽는다. 어느 하나라도 읽지 못하면
// 오류(fail-closed) — 합의 증가는 어떤 컨테이너든 재시작했음을 뜻한다(그린 위장 방어).
func (p *Prober) sumRestarts(ctx context.Context, names []string) (int, error) {
	total := 0
	for _, n := range names {
		rc, err := p.restarts.RestartCount(ctx, n)
		if err != nil {
			return 0, fmt.Errorf("컨테이너 %s: %w", n, err)
		}
		total += rc
	}
	return total, nil
}

// Check는 CD-1 준비성 판정을 실행한다. 통과면 nil, 실패면 사유를 담은 error를 준다
// (재시작 증가·대기 상한 초과·재시작 조회 실패·컨테이너 확정 실패). 이 판정은 mutate
// 명령을 재시도하지 않는다(Q4) — 부작용 없는 GET·inspect만 반복한다.
func (p *Prober) Check(ctx context.Context) error {
	if p.cfg.URL == "" {
		return errors.New("dispatch: CD-1 준비성 URL 미설정 — 헬스 판정 불가")
	}
	if p.cfg.SuccessThreshold < 1 {
		return fmt.Errorf("dispatch: CD-1 연속 성공 임계 N이 1 미만이다: %d", p.cfg.SuccessThreshold)
	}
	// O3: 0 이하 duration은 busy-loop·즉시 만료를 만든다 — 진입에서 거부한다.
	if p.cfg.Interval <= 0 || p.cfg.Deadline <= 0 || p.cfg.Timeout <= 0 {
		return fmt.Errorf("dispatch: CD-1 간격·상한·타임아웃은 모두 >0 이어야 한다(Interval=%s Deadline=%s Timeout=%s)", p.cfg.Interval, p.cfg.Deadline, p.cfg.Timeout)
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Deadline)
	defer cancel()

	// C3: 재시작 검사 대상 컨테이너를 compose 프로젝트에서 파생한다(설정 컨테이너명에
	//     의존하지 않는다 — 방어선을 예외 없이 켠다). 확정 실패·0개면 fail-closed.
	names, err := p.restarts.GreenContainers(ctx)
	if err != nil {
		return fmt.Errorf("dispatch: CD-1 green 컨테이너 확정 실패(판정 불가): %w", err)
	}
	if len(names) == 0 {
		return errors.New("dispatch: CD-1 green 컨테이너가 없다 — 재시작 검사 불가(판정 불가)")
	}

	// C4: baseline을 프로브 루프 전에 한 번 읽는다 — 첫 프로브 중 일어난 재시작도 놓치지
	//     않도록 대기 시작 시점 기준을 고정한다. 읽기 실패면 fail-closed.
	baseline, err := p.sumRestarts(ctx, names)
	if err != nil {
		return fmt.Errorf("dispatch: CD-1 재시작 baseline 조회 실패(판정 불가): %w", err)
	}

	eval := &healthEval{threshold: p.cfg.SuccessThreshold}

	// O2: time.After는 ctx.Done 승리 시 정지되지 않아 누수가 된다 — 하나의 Timer를 재사용하고
	//     defer Stop으로 확실히 정지한다. 정지 상태로 만들어 두고 매 간격마다 Reset한다.
	timer := time.NewTimer(p.cfg.Interval)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}

	for {
		ok := p.probeOnce(ctx)

		// 그린 위장 방어(Q1): 현재 재시작 합이 baseline보다 크면 2xx 여부와 무관하게 즉시 실패.
		now, rerr := p.sumRestarts(ctx, names)
		if rerr != nil {
			return fmt.Errorf("dispatch: CD-1 재시작 횟수 조회 실패(판정 불가): %w", rerr)
		}
		if now > baseline {
			return fmt.Errorf("dispatch: CD-1 헬스 실패: 컨테이너 재시작 감지(baseline=%d now=%d) — 그린 위장 방어(CD-1)", baseline, now)
		}

		if done, healthy := eval.observe(ok); done && healthy {
			return nil
		}

		timer.Reset(p.cfg.Interval)
		select {
		case <-ctx.Done():
			return fmt.Errorf("dispatch: CD-1 대기 상한(D=%s) 초과 — 연속 %d회 미달", p.cfg.Deadline, p.cfg.SuccessThreshold)
		case <-timer.C:
		}
	}
}

// probeOnce는 준비성 URL에 GET 한 번을 던지고 2xx면 true를 준다. 오류·비2xx는 false.
func (p *Prober) probeOnce(ctx context.Context) bool {
	rctx := ctx
	if p.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, p.cfg.Timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, p.cfg.URL, nil)
	if err != nil {
		return false
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
