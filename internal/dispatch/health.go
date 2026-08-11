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
//
// N·T·D 값은 [구현 검증](CDV-1)이며 설정에서 온다.

// HealthConfig는 CD-1 준비성 프로브 설정이다.
type HealthConfig struct {
	// URL은 green 프로세스의 준비성 엔드포인트다(GET). 비면 헬스 판정을 시작할 수 없다.
	URL string
	// SuccessThreshold는 통과에 필요한 연속 2xx 횟수 N이다(≥1).
	SuccessThreshold int
	// Interval은 프로브 간격 T다.
	Interval time.Duration
	// Timeout은 개별 GET의 상한이다.
	Timeout time.Duration
	// Deadline은 전체 대기 상한 D다 — 이 안에 N회를 못 채우면 실패.
	Deadline time.Duration
	// ContainerName은 재시작 횟수를 읽을 컨테이너다(그린 위장 방어 입력). 비면 재시작
	// 검사를 생략한다 — 그때는 그 방어선이 없다는 뜻이므로 설정을 권장한다.
	ContainerName string
}

// restartReader는 컨테이너 재시작 횟수를 읽는 표면이다(Executor가 만족한다).
type restartReader interface {
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

// healthEval은 프로브 표본을 받아 CD-1 판정을 갱신하는 순수 상태다(시간·IO 없음 —
// 단위 테스트가 표본 시퀀스로 직접 검증한다).
type healthEval struct {
	threshold int  // N
	consec    int  // 현재 연속 2xx 횟수
	baseline  int  // 첫 표본에서 읽은 재시작 횟수
	haveBase  bool // baseline을 읽었는지
}

// observe는 한 표본을 반영하고 판정한다. done=true면 종료(healthy로 통과/실패 확정).
// checkRestart=false면 재시작 검사를 하지 않는다(ContainerName 미설정). restarts 증가는
// 2xx 여부와 무관하게 즉시 실패다(Q1 — 그린 위장 방어).
func (h *healthEval) observe(ok bool, restarts int, checkRestart bool) (done, healthy bool, reason string) {
	if checkRestart {
		if !h.haveBase {
			h.baseline = restarts
			h.haveBase = true
		} else if restarts > h.baseline {
			return true, false, fmt.Sprintf("컨테이너 재시작 감지(baseline=%d now=%d) — 그린 위장 방어(CD-1)", h.baseline, restarts)
		}
	}
	if ok {
		h.consec++
	} else {
		h.consec = 0
	}
	if h.consec >= h.threshold {
		return true, true, ""
	}
	return false, false, ""
}

// Check는 CD-1 준비성 판정을 실행한다. 통과면 nil, 실패면 사유를 담은 error를 준다
// (재시작 증가·대기 상한 초과·재시작 조회 실패). 이 판정은 mutate 명령을 재시도하지
// 않는다(Q4) — 부작용 없는 GET·inspect만 반복한다.
func (p *Prober) Check(ctx context.Context) error {
	if p.cfg.URL == "" {
		return errors.New("dispatch: CD-1 준비성 URL 미설정 — 헬스 판정 불가")
	}
	if p.cfg.SuccessThreshold < 1 {
		return fmt.Errorf("dispatch: CD-1 연속 성공 임계 N이 1 미만이다: %d", p.cfg.SuccessThreshold)
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Deadline)
	defer cancel()

	eval := &healthEval{threshold: p.cfg.SuccessThreshold}
	checkRestart := p.cfg.ContainerName != ""

	for {
		ok := p.probeOnce(ctx)

		restarts := 0
		if checkRestart {
			rc, err := p.restarts.RestartCount(ctx, p.cfg.ContainerName)
			if err != nil {
				// 재시작 횟수를 읽지 못하면 그린 위장 방어가 성립하지 않는다 — 통과로
				// 넘기지 않는다(CD-1 판정 불가 = 실패로 접어 미전환 경로로 보낸다).
				return fmt.Errorf("dispatch: CD-1 재시작 횟수 조회 실패(판정 불가): %w", err)
			}
			restarts = rc
		}

		done, healthy, reason := eval.observe(ok, restarts, checkRestart)
		if done {
			if healthy {
				return nil
			}
			return fmt.Errorf("dispatch: CD-1 헬스 실패: %s", reason)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("dispatch: CD-1 대기 상한(D=%s) 초과 — 연속 %d회 미달", p.cfg.Deadline, p.cfg.SuccessThreshold)
		case <-time.After(p.cfg.Interval):
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
