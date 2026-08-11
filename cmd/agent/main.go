// Command agent는 deploy-agent 단일 바이너리다. 하나를 크로스컴파일해 세 호스트에
// 배포하고, 역할은 .env의 ROLE로 가른다(ADR-027 DO-21 — 프로세스가 아니라 모드로
// 역할을 분리한다).
//
//   - ROLE=main  (.9): 외부 HTTP 수신·서명 검증·모드 판정·각 호스트 분배 + 자기
//     호스트의 로컬 배포. 이번 이슈는 그 중 HTTP 진입 골격만 세운다(internal/httpentry).
//   - ROLE=agent (.158·.164): 메인에서 서명 명령만 받아 자기 호스트를 배포한다.
//     아직 미구현 스텁이다(다음 마일스톤).
//
// 계약 출처(정본 — 이 코드는 이를 재해석하지 않는다):
//   - ADR-027 DO-21  (단일 Go 바이너리 · 역할은 .env의 ROLE=main|agent)
//   - ADR-027 DO-1   (ROLE=main의 외부 진입은 엔드포인트 하나 — CI 수신 전용)
//   - ADR-029 IA-4   (agent 두 층: HTTP 진입 미들웨어 / 오케스트레이션)
//
// ROLE이 없거나 알 수 없으면 기동을 거부한다(fail-closed) — 역할이 모호한 채로 특권
// 프로세스를 띄우지 않는다.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/jun-bank/infra/internal/auth"
	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/dispatch"
	"github.com/jun-bank/infra/internal/httpentry"
	"github.com/jun-bank/infra/internal/store"
)

// defaultDeployLease는 배포 창 락의 기본 lease다(AGENT_DEPLOY_LEASE로 덮어쓴다). ⚠️ 이
// 값은 [구현 검증]이다 — 한 배포 시퀀스를 넉넉히 덮으면서 죽은 주체를 오래 붙들지 않는
// 실측 값은 배포 시간과 함께 정해진다. store.MinLease(1초) 이상이어야 하고, 기본 설정끼리
// leaseCoversDispatch를 통과해야 한다(기본 phaseBudget 120s + D 60s + cleanup 30s + slack
// 10s = 220s 하한 — TestDefaultConfigLeaseCoversDispatch가 이 정합성을 지킨다).
const defaultDeployLease = 4 * time.Minute

// defaultDispatchPhaseBudget은 pull+up 단계 상한 phaseBudget의 기본값이다(P3). ⚠️ [구현 검증]:
// 실제 이미지 pull(회수)·compose up(기동) 소요와 함께 sizing한다 — 이미지 pull이 이 budget
// 보다 오래 걸리면 배포가 실패한다(운영자가 이미지 크기에 맞게 조정 · CD-3 무갱신 하한 입력).
const defaultDispatchPhaseBudget = 120 * time.Second

// dispatchLeaseSlack은 lease 하한식의 여유 상수다 — 단계 경계 오버헤드(context 전환·조회
// 왕복)를 흡수한다. ⚠️ [구현 검증]: 실측으로 조정한다(기본 10s는 합리 가정).
const dispatchLeaseSlack = 10 * time.Second

// leaseCoversDispatch는 배포 창 락 lease가 dispatch 전체 소요를 덮는지 본다(CD-3 하한식).
// dispatch가 실시간이 되면서 dispatch 중 lease 갱신이 없으므로(CD-3 무갱신 모델을 채택 —
// lease 갱신 goroutine을 두지 않는다), lease가 dispatch보다 짧으면 실행 도중 락이 만료돼
// 다른 주체가 stale 락을 회수하고(P3 동시 배포·버전 스큐), 그때 A의 detached cleanup down이
// fencing 없이 실행돼 B가 재획득·green up한 것을 철거한다(P4 O1 회귀). 그래서 하한을
//
//	lease ≥ phaseBudget(pull+up 상한) + healthDeadline D(헬스) + CleanupTimeout(실패 시 정리) + slack
//
// 으로 강화한다 — 이러면 전체 dispatch(pull+up ≤ phaseBudget, health ≤ D, 실패 시 cleanup ≤
// CleanupTimeout)가 lease 안에 보증돼, cleanup이 락 상실 후 실행되는 일이 구조적으로 불가능
// 하다(P4 닫힘). 미달이면 오류(fail-closed). ⚠️ UNKNOWN(전환 이후 상태 불명)이 lease 만료
// 까지만 유지되는 잔여는 남는다(CD-3 "만료 ≠ 상태 복구" — 사람이 만료 전 개입한다). lease는
// 그 개입 창을 벌 뿐, 만료 자체를 상태 복구로 삼지 않는다.
func leaseCoversDispatch(lease, phaseBudget, healthDeadline time.Duration) error {
	min := phaseBudget + healthDeadline + deploy.CleanupTimeout + dispatchLeaseSlack
	if lease < min {
		return fmt.Errorf("배포 창 락 lease가 dispatch 소요를 덮지 못한다(fail-closed): lease=%s < phaseBudget(%s) + 헬스 deadline D(%s) + cleanup(%s) + slack(%s) = %s — lease를 늘리거나 phaseBudget·D를 줄여라(CD-3 하한식)", lease, phaseBudget, healthDeadline, deploy.CleanupTimeout, dispatchLeaseSlack, min)
	}
	return nil
}

// role은 이 바이너리가 띄우는 역할의 닫힌 집합이다(DO-21).
type role string

const (
	roleMain  role = "main"  // .9 — 오케스트레이터 + 자기 호스트 배포
	roleAgent role = "agent" // .158·.164 — 메인 명령 수신 실행자
)

func main() {
	if err := run(os.Getenv("ROLE")); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

// run은 ROLE을 해석해 해당 역할을 띄운다. os.Getenv를 밖에서 주입받아 역할 분기가
// 테스트 가능하도록 한다.
func run(rawRole string) error {
	r, err := resolveRole(rawRole)
	if err != nil {
		return err
	}
	switch r {
	case roleMain:
		return runMain()
	case roleAgent:
		return runAgent()
	default:
		// resolveRole이 이미 걸러내므로 도달 불가 — 방어적으로 fail-closed.
		return fmt.Errorf("ROLE 처리되지 않음: %q", r)
	}
}

// resolveRole은 ROLE 원시 값을 검증한다. 빈 값·미지원 값은 오류다(fail-closed —
// 역할이 정해지지 않은 채로 기동하지 않는다, DO-21).
func resolveRole(raw string) (role, error) {
	switch role(raw) {
	case roleMain, roleAgent:
		return role(raw), nil
	case "":
		return "", errors.New("ROLE 미설정 (.env에 ROLE=main 또는 ROLE=agent 를 둔다)")
	default:
		return "", fmt.Errorf("ROLE 미지원: %q (main|agent 중 하나여야 한다)", raw)
	}
}

// runMain은 ROLE=main의 HTTP 진입 서버를 띄운다(DO-1 · IA-4 ⑴). 설정은 환경에서
// 오며, 주소가 없으면 리스너를 열지 않는다(fail-closed — httpentry.LoadConfig).
func runMain() error {
	cfg, err := httpentry.LoadConfig()
	if err != nil {
		return fmt.Errorf("설정 로딩 실패: %w", err)
	}

	deps, err := buildDeps()
	if err != nil {
		return fmt.Errorf("게이트 1·store 조립 실패: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpentry.NewHandler(cfg, deps),
		ReadHeaderTimeout: 10 * time.Second, // slowloris 완화 — timeout 값은 [구현 검증](DO-15 ⑷)
	}

	// SIGINT/SIGTERM에 우아하게 종료한다.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		fmt.Println("jun-bank deploy-agent · ROLE=main · listen:", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// buildDeps는 진입 층이 판정을 위임할 협력자들을 환경에서 조립한다: 게이트 1
// verifier(AGENT_HMAC_KEY)와 배포 스키마 store(DEPLOY_DB_DSN). 어느 하나라도 없으면
// 오류를 반환해 기동을 막는다(fail-closed — 검증 못 하거나 원장에 쓸 수 없는 채로
// 배포 수신을 열지 않는다, DO-17 ⑷). DB 핸들은 지연 연결이며(sql.Open은 접속하지
// 않는다) 실제 접속 실패는 요청 시점에 fail-closed로 드러난다.
func buildDeps() (httpentry.Deps, error) {
	authCfg, err := auth.LoadConfig()
	if err != nil {
		return httpentry.Deps{}, fmt.Errorf("게이트 1 설정: %w", err)
	}
	verifier, err := auth.NewVerifier(authCfg, nil) // 기본 벽시계
	if err != nil {
		return httpentry.Deps{}, fmt.Errorf("게이트 1 verifier: %w", err)
	}

	// 게이트 2(OIDC claim 행렬 — DO-11). 정책(기대 claim 값)은 환경에서 오고, 서명
	// 검증은 발급자 JWKS 공개키로 한다. 실제 JWKS 페치는 스캐폴드 뒤에 있다(아래).
	oidcPolicy, err := auth.LoadOIDCPolicy()
	if err != nil {
		return httpentry.Deps{}, fmt.Errorf("게이트 2 정책: %w", err)
	}
	oidcGate, err := auth.NewOIDCVerifier(auth.NewJWKSTokenVerifier(jwksScaffold{}), oidcPolicy, nil)
	if err != nil {
		return httpentry.Deps{}, fmt.Errorf("게이트 2 verifier: %w", err)
	}

	dsn := os.Getenv("DEPLOY_DB_DSN")
	if dsn == "" {
		return httpentry.Deps{}, errors.New("DEPLOY_DB_DSN 미설정 (배포 스키마 접속은 .env에서 온다)")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return httpentry.Deps{}, fmt.Errorf("배포 DB 열기: %w", err)
	}
	st := store.New(db)

	coord, err := buildCoordinator(st)
	if err != nil {
		return httpentry.Deps{}, fmt.Errorf("오케스트레이터 조립: %w", err)
	}

	return httpentry.Deps{Verifier: verifier, OIDC: oidcGate, Ledger: st, History: st, Deploy: coord}, nil
}

// buildCoordinator는 상태 있는 오케스트레이션 층을 조립한다(IA-4 ⑵). 모드·락·이력은
// 같은 배포 스키마 store가, 실행 지점은 아직 스텁(#15)이 소유한다. holderID는 이 agent
// 인스턴스를 락에서 식별하며(CD-3), lease는 환경에서 온다(기본값·[구현 검증]).
func buildCoordinator(st *store.SQLStore) (deploy.Coordinator, error) {
	holderID, err := os.Hostname()
	if err != nil || holderID == "" {
		return nil, errors.New("락 holder 식별자 확정 불가 (hostname)")
	}

	lease := defaultDeployLease
	if raw := os.Getenv("AGENT_DEPLOY_LEASE"); raw != "" {
		d, perr := time.ParseDuration(raw)
		if perr != nil || d < store.MinLease {
			return nil, fmt.Errorf("AGENT_DEPLOY_LEASE 값이 올바르지 않다 (>= %s Go duration): %q", store.MinLease, raw)
		}
		lease = d
	}

	disp, healthDeadline, phaseBudget, err := buildDispatcher()
	if err != nil {
		return nil, fmt.Errorf("실행 지점(dispatcher) 조립: %w", err)
	}

	// C5/C6: 배포 창 락 lease가 실시간 dispatch 전체 소요(pull+up 상한 phaseBudget + 헬스
	//        deadline D + 실패 시 cleanup)를 덮는지 시동 시 검증한다(CD-3 하한식 — 갱신을 두지
	//        않으므로 lease ≥ 전 단계 소요 합). 미달이면 기동 거부(fail-closed) — lease가
	//        dispatch보다 짧으면 실행 중 락이 만료돼 다른 배포/배치가 stale 락을 회수하고,
	//        A의 cleanup down이 락 상실 후 B의 green을 철거한다(P3·P4).
	if err := leaseCoversDispatch(lease, phaseBudget, healthDeadline); err != nil {
		return nil, err
	}

	return deploy.NewCoordinator(deploy.Deps{
		Mode:       st,
		Lock:       st,
		History:    st,
		Dispatcher: disp, // 실행 지점(#15) — pull → up → CD-1 헬스 → RemoteState
		HolderID:   holderID,
		Lease:      lease,
	}), nil
}

// defaultHealth*는 CD-1 준비성 프로브의 기본값이다(모두 [구현 검증] CDV-1 — 실측으로
// 정해진다). env로 덮어쓴다. N·T·Timeout·D는 배포 시간과 함께 튜닝된다.
const (
	defaultHealthThreshold = 3
	defaultHealthInterval  = 2 * time.Second
	defaultHealthTimeout   = 3 * time.Second
	defaultHealthDeadline  = 60 * time.Second
)

// buildDispatcher는 특권 실행 지점을 환경에서 조립한다(DO-23 · DO-18 · CD-1). 배포에
// 필수인 설정(compose 파일·프로젝트·준비성 URL·이미지 repo 최소 1개)이 없으면 오류를
// 반환해 기동을 막는다(fail-closed — 배포를 수행할 수 없는 채로 수신을 열지 않는다,
// DO-17 ⑷와 같은 축). sudo 프리픽스·비번은 선택이다(개발 머신은 비운다 — 직접 실행).
// 반환하는 healthDeadline·phaseBudget은 락 lease가 dispatch 소요를 덮는지 검증하는 입력이다(C5/C6).
func buildDispatcher() (deploy.Dispatcher, time.Duration, time.Duration, error) {
	composeFile := os.Getenv("DEPLOY_COMPOSE_FILE")
	project := os.Getenv("DEPLOY_COMPOSE_PROJECT")
	healthURL := os.Getenv("DEPLOY_HEALTH_URL")
	if composeFile == "" || project == "" || healthURL == "" {
		return nil, 0, 0, errors.New("DEPLOY_COMPOSE_FILE·DEPLOY_COMPOSE_PROJECT·DEPLOY_HEALTH_URL 미설정 (배포 실행에 필수 — fail-closed)")
	}

	repos := map[deploy.Target]string{}
	for target, env := range map[deploy.Target]string{
		deploy.TargetCore:       "IMAGE_CORE",
		deploy.TargetSettlement: "IMAGE_SETTLEMENT",
		deploy.TargetLedger:     "IMAGE_LEDGER",
	} {
		if v := os.Getenv(env); v != "" {
			repos[target] = v
		}
	}
	if len(repos) == 0 {
		return nil, 0, 0, errors.New("IMAGE_CORE·IMAGE_SETTLEMENT·IMAGE_LEDGER 중 최소 하나가 필요하다 (배포 대상 이미지 repo — fail-closed)")
	}

	execr, err := dispatch.NewExecutor(dispatch.Config{
		SudoPrefix:   strings.Fields(os.Getenv("DEPLOY_SUDO_PREFIX")), // 공백 split · 비면 직접 실행
		SudoPassword: os.Getenv("DEPLOY_SUDO_PASSWORD"),
		ComposeFile:  composeFile,
		Project:      project,
		ImageEnvVar:  os.Getenv("DEPLOY_IMAGE_ENV"), // 비면 dispatch 기본(DEPLOY_IMAGE_REF)
	})
	if err != nil {
		return nil, 0, 0, fmt.Errorf("특권 실행기 조립(sudo 프리픽스 검증 — fail-closed): %w", err)
	}

	// P8: 헬스·phaseBudget 튜닝 env를 boot에서 파싱·검증한다(fail-fast). 설정됐으나 파싱
	//     불가면 조용히 기본값으로 삼키지 않고 오류를 낸다 — 잘못된 튜닝이 런타임(Prober.Check)
	//     까지 숨는 것을 막는다. Prober.Check의 런타임 검증은 그대로 두어(선행 방어선 이중화).
	threshold, err := envInt("DEPLOY_HEALTH_SUCCESS_THRESHOLD", defaultHealthThreshold)
	if err != nil {
		return nil, 0, 0, err
	}
	interval, err := envDuration("DEPLOY_HEALTH_INTERVAL", defaultHealthInterval)
	if err != nil {
		return nil, 0, 0, err
	}
	timeout, err := envDuration("DEPLOY_HEALTH_TIMEOUT", defaultHealthTimeout)
	if err != nil {
		return nil, 0, 0, err
	}
	healthDeadline, err := envDuration("DEPLOY_HEALTH_DEADLINE", defaultHealthDeadline)
	if err != nil {
		return nil, 0, 0, err
	}
	phaseBudget, err := envDuration("DEPLOY_DISPATCH_PHASE_BUDGET", defaultDispatchPhaseBudget)
	if err != nil {
		return nil, 0, 0, err
	}
	if threshold < 1 {
		return nil, 0, 0, fmt.Errorf("DEPLOY_HEALTH_SUCCESS_THRESHOLD(N)는 1 이상이어야 한다(fail-closed): %d", threshold)
	}
	if interval <= 0 || timeout <= 0 || healthDeadline <= 0 || phaseBudget <= 0 {
		return nil, 0, 0, fmt.Errorf("헬스 간격·타임아웃·deadline과 phaseBudget은 모두 >0 이어야 한다(fail-closed): interval=%s timeout=%s deadline=%s phaseBudget=%s", interval, timeout, healthDeadline, phaseBudget)
	}

	prober := dispatch.NewProber(dispatch.HealthConfig{
		URL:              healthURL,
		SuccessThreshold: threshold,
		Interval:         interval,
		Timeout:          timeout,
		Deadline:         healthDeadline,
	}, execr) // 재시작 검사 대상 컨테이너는 compose 프로젝트에서 파생한다(항상 켠다 — CD-1)

	return deploy.LocalDispatcher{Exec: execr, Health: prober, Repos: repos, PhaseBudget: phaseBudget}, healthDeadline, phaseBudget, nil
}

// envInt는 env를 정수로 읽는다. 부재 시 def, 설정됐으나 정수가 아니면 오류(무음 삼킴 금지 — P8).
func envInt(key string, def int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s 값이 정수가 아니다(fail-closed): %q", key, raw)
	}
	return n, nil
}

// envDuration은 env를 Go duration으로 읽는다. 부재 시 def, 설정됐으나 파싱 불가면 오류(P8).
func envDuration(key string, def time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s 값이 Go duration이 아니다(fail-closed): %q", key, raw)
	}
	return d, nil
}

// jwksScaffold는 게이트 2의 JWKS 공개키 페치 자리를 잡는 스캐폴드다(store 스캐폴드와
// 같은 방식). 실제 구현은 발급자 JWKS 엔드포인트를 HTTPS로 페치·캐시하며 키 회전을
// 따라간다 — ⚠️ 발급자 URL·회전·캐시는 [구현 검증]이다. 다음 마일스톤에서 채워질
// 때까지 오류를 반환한다: 공개키를 얻지 못하면 게이트 2가 서명을 검증할 수 없어
// fail-closed로 거절한다(검증 못 하는 경계를 열지 않는다).
type jwksScaffold struct{}

func (jwksScaffold) VerificationKey(context.Context, string) (any, error) {
	return nil, errors.New("JWKS 공개키 페치 미구현 (다음 마일스톤 — 발급자 JWKS HTTPS 페치)")
}

// runAgent는 ROLE=agent의 실행자 역할이다. 아직 미구현이므로 기동을 거부한다
// (fail-closed — 다음 마일스톤에서 채운다).
func runAgent() error {
	// TODO(다음 마일스톤): 메인에서 서명된 명령을 LAN 전용으로 수신하고(DO-22),
	// 서명 검증 통과 후 internal/dispatch로 자기 호스트의 특권 조작을 실행한다(DO-23).
	return errors.New("ROLE=agent 미구현 (다음 마일스톤)")
}
