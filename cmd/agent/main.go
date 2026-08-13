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
	"github.com/jun-bank/infra/internal/compose"
	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/dispatch"
	"github.com/jun-bank/infra/internal/httpentry"
	"github.com/jun-bank/infra/internal/store"
)

// defaultDeployLease는 배포 창 락의 기본 lease다(AGENT_DEPLOY_LEASE로 덮어쓴다). ⚠️ 이
// 값은 [구현 검증]이다 — 한 배포 시퀀스를 넉넉히 덮으면서 죽은 주체를 오래 붙들지 않는
// 실측 값은 배포 시간과 함께 정해진다. store.MinLease(1초) 이상이어야 하고, 기본 설정끼리
// leaseCoversDispatch를 통과해야 한다(기본 phaseBudget 120s + D 60s + cleanup 30s + 전환
// 예산 65s + slack 10s = 285s 하한 — TestDefaultConfigLeaseCoversDispatch가 이 정합성을
// 지킨다). ⚠️ 전환 단계(CD-4 ⑤⑥⑨)가 dispatch에 들어오면서 4분으로는 기본 설정이
// 자기정합하지 않게 되어 6분으로 올렸다 — lease가 길수록 죽은 주체를 오래 붙드는 대가를
// 함께 진다(CD-3 stale 회수가 그만큼 늦다).
const defaultDeployLease = 6 * time.Minute

// defaultDispatchPhaseBudget은 pull+up 단계 상한 phaseBudget의 기본값이다(P3). ⚠️ [구현 검증]:
// 실제 이미지 pull(회수)·compose up(기동) 소요와 함께 sizing한다 — 이미지 pull이 이 budget
// 보다 오래 걸리면 배포가 실패한다(운영자가 이미지 크기에 맞게 조정 · CD-3 무갱신 하한 입력).
const defaultDispatchPhaseBudget = 120 * time.Second

// defaultJWKSCacheTTL은 발급자 JWKS 공개키 캐시의 기본 TTL이다(OIDC_JWKS_CACHE_TTL로
// 덮어쓴다). ⚠️ [구현 검증]: 발급자 키 회전 주기와 함께 sizing한다 — 너무 길면 회전 후
// 폐기된 키를 오래 신뢰하고, 너무 짧으면 발급자를 자주 두드린다. 미지 kid는 TTL과 무관하게
// 재페치하므로(회전 계약) 이 값은 known kid의 재검증 주기다(기본 10분은 합리 가정).
const defaultJWKSCacheTTL = 10 * time.Minute

// dispatchLeaseSlack은 lease 하한식의 여유 상수다 — 락 획득~dispatch 진입 사이(모드·manifest
// 검증·fencing 재확인)와 단계 경계 오버헤드(context 전환·조회 왕복)를 흡수한다. ⚠️ [구현 검증]:
// 실측으로 조정한다(기본 10s는 합리 가정 — 이 창을 넘는 지연이 관측되면 늘린다).
const dispatchLeaseSlack = 10 * time.Second

// maxDispatchDuration은 phaseBudget·healthDeadline 각각의 상한이다 — 이보다 큰 값을 설정으로
// 받으면 하한식 덧셈이 int64 overflow로 음수가 되어 lease 검증이 fail-open이 될 수 있다(H3).
// 실제 배포 단계가 이 값을 넘는 일은 없으므로, 넘으면 오설정으로 보고 fail-closed로 거부한다.
const maxDispatchDuration = time.Hour

// cutoverBudget은 전환 단계(CD-4 ⑤⑥⑨)의 소요 상한이다 — 게이트웨이가 설정되지 않았으면
// 그 단계가 아예 없으므로 0이다(그때는 이 함수를 부르지 않는다). 항은 셋이다:
//
//	게이트웨이 왕복 2회(배포 시작 전 active slot 조회 + ⑤ 전환) + 드레인 대기(⑥) + 구 slot down(⑨)
//
// 각 게이트웨이 요청은 클라이언트 타임아웃으로, 드레인은 선언값으로, down은 CleanupTimeout
// 으로 상한되므로 이 합이 전환 구간의 상한이 된다(락 안에서 완주하도록 lease 하한에 더한다 —
// BG-4: 전환은 락 보유 단계다).
//
// ⚠️ 합산 **전에** 각 항을 개별로 상한한다(H3와 같은 축) — 거대 env 값(예: DEPLOY_DRAIN_WAIT
// =2562047h)이 들어오면 2*gatewayTimeout+drainWait이 int64 overflow로 음수가 되고, 그 음수
// 예산은 leaseCoversDispatch의 [0, max] 검사를 "작은 값"으로 통과해 하한식 자체를 fail-open
// 시킨다. 항별 검증이 서면 합은 최대 3*maxDispatchDuration + CleanupTimeout이라 넘칠 수 없다.
func cutoverBudget(gatewayTimeout, drainWait time.Duration) (time.Duration, error) {
	if gatewayTimeout <= 0 || gatewayTimeout > maxDispatchDuration {
		return 0, fmt.Errorf("DEPLOY_GATEWAY_TIMEOUT은 (0, %s] 범위여야 한다(fail-closed · 전환 예산 overflow 방지): %s", maxDispatchDuration, gatewayTimeout)
	}
	if drainWait <= 0 || drainWait > maxDispatchDuration {
		return 0, fmt.Errorf("DEPLOY_DRAIN_WAIT은 (0, %s] 범위여야 한다(fail-closed · 전환 예산 overflow 방지): %s", maxDispatchDuration, drainWait)
	}
	return 2*gatewayTimeout + drainWait + deploy.CleanupTimeout, nil
}

// leaseCoversDispatch는 배포 창 락 lease가 dispatch 전체 소요를 덮는지 본다(CD-3 하한식).
// dispatch가 실시간이 되면서 dispatch 중 lease 갱신이 없으므로(CD-3 무갱신 모델을 채택 —
// lease 갱신 goroutine을 두지 않는다), lease가 dispatch보다 짧으면 실행 도중 락이 만료돼
// 다른 주체가 stale 락을 회수하고(P3 동시 배포·버전 스큐), 그때 A의 detached cleanup down이
// fencing 없이 실행돼 B가 재획득·green up한 것을 철거한다(P4 O1 회귀). 그래서 하한을
//
//	lease ≥ phaseBudget(pull+up 상한) + healthDeadline D(헬스) + CleanupTimeout(실패 시 정리)
//	        + cutover(전환·드레인·구 slot 종료 — 게이트웨이 미설정이면 0) + slack
//
// 으로 강화한다 — phaseBudget은 pull+up+무결성대조(H1)를, D는 헬스를, CleanupTimeout은 실패 시
// 정리를, cutover는 ⑤⑥⑨를 각각 상한하므로, 그 합 + slack이 lease를 넘지 않는 한 전체 dispatch가
// lease 안에서 끝나 cleanup·전환 후 단계가 락 상실 뒤 실행되지 않는다(P4 · BG-4). ⚠️ 이 보증은
// slack이 락 획득~dispatch 진입 + 단계 경계 오버헤드를 덮는다는 전제 위에 선다(무한 보증이 아니라
// 예산 기반 — slack은 [구현 검증]). 미달이면 오류(fail-closed). ⚠️ UNKNOWN(전환 이후 상태 불명)이
// lease 만료까지만 유지되는 잔여는 남는다(CD-3 "만료 ≠ 상태 복구" — 사람이 만료 전 개입한다).
func leaseCoversDispatch(lease, phaseBudget, healthDeadline, cutover time.Duration) error {
	// overflow 가드(H3) — 거대 duration이 덧셈을 음수로 뒤집어 검증을 우회하는 것을 막는다.
	if phaseBudget <= 0 || phaseBudget > maxDispatchDuration || healthDeadline <= 0 || healthDeadline > maxDispatchDuration {
		return fmt.Errorf("phaseBudget·healthDeadline은 (0, %s] 범위여야 한다(fail-closed · overflow 방지): phaseBudget=%s healthDeadline=%s", maxDispatchDuration, phaseBudget, healthDeadline)
	}
	// cutover는 게이트웨이 미설정 시 0이다(음수는 없다) — 상한은 같은 이유로 건다.
	if cutover < 0 || cutover > maxDispatchDuration {
		return fmt.Errorf("전환 예산(cutover)은 [0, %s] 범위여야 한다(fail-closed · overflow 방지): cutover=%s", maxDispatchDuration, cutover)
	}
	min := phaseBudget + healthDeadline + deploy.CleanupTimeout + cutover + dispatchLeaseSlack
	if lease < min {
		return fmt.Errorf("배포 창 락 lease가 dispatch 소요를 덮지 못한다(fail-closed): lease=%s < phaseBudget(%s) + 헬스 deadline D(%s) + cleanup(%s) + 전환(%s) + slack(%s) = %s — lease를 늘리거나 phaseBudget·D·드레인을 줄여라(CD-3 하한식)", lease, phaseBudget, healthDeadline, deploy.CleanupTimeout, cutover, dispatchLeaseSlack, min)
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
	// 검증은 발급자 JWKS 공개키로 한다. JWKS는 OIDC_ISSUER를 discovery base로 HTTPS
	// 페치·캐시하며 키 회전을 따라간다(auth.NewHTTPKeySet — fail-closed). OIDC_ISSUER는
	// LoadOIDCPolicy가 이미 필수로 강제한다(미설정이면 여기서 오류로 기동 거부).
	oidcPolicy, err := auth.LoadOIDCPolicy()
	if err != nil {
		return httpentry.Deps{}, fmt.Errorf("게이트 2 정책: %w", err)
	}
	jwksTTL, err := envDuration("OIDC_JWKS_CACHE_TTL", defaultJWKSCacheTTL)
	if err != nil {
		return httpentry.Deps{}, err
	}
	keySet, err := auth.NewHTTPKeySet(oidcPolicy.Issuer, jwksTTL)
	if err != nil {
		return httpentry.Deps{}, fmt.Errorf("게이트 2 JWKS 페치기(https·TTL 검증 — fail-closed): %w", err)
	}
	oidcGate, err := auth.NewOIDCVerifier(auth.NewJWKSTokenVerifier(keySet), oidcPolicy, nil)
	if err != nil {
		return httpentry.Deps{}, fmt.Errorf("게이트 2 verifier: %w", err)
	}
	// 적재된 항목 수를 기동 로그에 남긴다 — .9 이관(파일 배치 + 단일 env 제거) 뒤 재기동이
	// 실제로 새 allowlist를 읽었는지, 몇 저장소가 등재됐는지가 로그 한 줄로 보여야 한다.
	// (설정이 없거나 어긋나면 여기 오기 전에 기동이 거부된다 — 이 줄은 항상 ≥1이다.)
	fmt.Printf("게이트 2 · OIDC allowlist 항목 %d개 적재 (repo↔target 결박 유효)\n", oidcPolicy.Allowlist.Len())

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

	b, err := buildDispatcher()
	if err != nil {
		return nil, fmt.Errorf("실행 지점(dispatcher) 조립: %w", err)
	}

	// C5/C6: 배포 창 락 lease가 실시간 dispatch 전체 소요(pull+up 상한 phaseBudget + 헬스
	//        deadline D + 실패 시 cleanup + 전환·드레인·구 slot 종료)를 덮는지 시동 시
	//        검증한다(CD-3 하한식 — 갱신을 두지 않으므로 lease ≥ 전 단계 소요 합). 미달이면
	//        기동 거부(fail-closed) — lease가 dispatch보다 짧으면 실행 중 락이 만료돼 다른
	//        배포/배치가 stale 락을 회수하고, A의 cleanup down이 락 상실 후 B의 green을
	//        철거한다(P3·P4). 전환 단계는 락 보유 단계이므로 예산에 함께 든다(BG-4).
	if err := leaseCoversDispatch(lease, b.phaseBudget, b.healthDeadline, b.cutoverBudget); err != nil {
		return nil, err
	}

	return deploy.NewCoordinator(deploy.Deps{
		Mode:       st,
		Lock:       st,
		History:    st,
		Dispatcher: b.disp, // 실행 지점 — pull → up → CD-1 헬스 → (게이트웨이 설정 시) 전환 → 드레인 → 구 slot 종료
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

// defaultDrainWait은 전환 후 구 slot의 in-flight 소진을 기다리는 기본 시간이다(CD-4 ⑥).
// ⚠️ [구현 검증] IV-17/CDV-2 — 이 값은 관측이 아니라 **선언값**이다: BG-3 ⑵의 완료 판정은
// "수신 차단이 실제로 선 뒤의 0건"이고, v1은 그 관측 수단(무엇을 계수하나 · 임계값)이
// 미확정이라 고정 대기로 대신한다. 실측으로 정해지면 이 자리가 실관측 판정으로 바뀐다.
const defaultDrainWait = 15 * time.Second

// defaultGatewayTimeout은 게이트웨이 라우트 API 요청 하나의 상한이다(조회·전환 공통).
// ⚠️ [구현 검증]: 실제 SCG 라우트 갱신 소요와 함께 sizing한다(BG-5 — 갱신 수단 자체가
// 미확정이다). lease 하한식의 전환 예산 입력이기도 하다.
const defaultGatewayTimeout = 10 * time.Second

// dispatcherBuild는 조립 결과와 lease 하한식 입력이다(C5/C6). cutoverBudget은 게이트웨이가
// 설정되지 않았으면 0이다 — 그 환경에는 전환 단계 자체가 없다.
type dispatcherBuild struct {
	disp           deploy.Dispatcher
	healthDeadline time.Duration
	phaseBudget    time.Duration
	cutoverBudget  time.Duration
}

// buildDispatcher는 특권 실행 지점을 환경에서 조립한다(DO-23 · DO-18 · CD-1 · CD-4 ⑤⑥⑨).
// 두 모드가 있고 갈림은 DEPLOY_GATEWAY_URL 하나다:
//
//   - 미설정(하위호환): DEPLOY_COMPOSE_FILE·DEPLOY_COMPOSE_PROJECT·DEPLOY_HEALTH_URL 하나씩.
//     전환 단계가 없다 — pull→up→대조→헬스까지가 종단이다.
//   - 설정(블루-그린): 슬롯별로 DEPLOY_COMPOSE_FILE_BLUE/GREEN·DEPLOY_COMPOSE_PROJECT_BLUE/
//     GREEN·DEPLOY_HEALTH_URL_BLUE/GREEN이 필요하다(down이 프로젝트 단위라 blue만 끄려면
//     프로젝트가 갈려 있어야 한다 — BG-3 ⑶). 단일 변수 3종은 이 모드에서 **선택**이며,
//     설정하면 target=gateway 배포(전환 없는 재기동 교체 — DO-20 ⓐ)의 실행기가 된다.
//
// 배포에 필수인 설정이 없으면 오류를 반환해 기동을 막는다(fail-closed — 배포를 수행할 수
// 없는 채로 수신을 열지 않는다, DO-17 ⑷와 같은 축). sudo 프리픽스·비번은 선택이다.
func buildDispatcher() (dispatcherBuild, error) {
	var b dispatcherBuild

	repos := map[deploy.Target]string{}
	for target, env := range map[deploy.Target]string{
		deploy.TargetCore:       "IMAGE_CORE",
		deploy.TargetSettlement: "IMAGE_SETTLEMENT",
		deploy.TargetLedger:     "IMAGE_LEDGER",
		deploy.TargetGateway:    "IMAGE_GATEWAY",
	} {
		if v := os.Getenv(env); v != "" {
			repos[target] = v
		}
	}
	if len(repos) == 0 {
		return b, errors.New("IMAGE_CORE·IMAGE_SETTLEMENT·IMAGE_LEDGER·IMAGE_GATEWAY 중 최소 하나가 필요하다 (배포 대상 이미지 repo — fail-closed)")
	}

	// P8: 헬스·phaseBudget·전환 튜닝 env를 boot에서 파싱·검증한다(fail-fast). 설정됐으나 파싱
	//     불가면 조용히 기본값으로 삼키지 않고 오류를 낸다 — 잘못된 튜닝이 런타임(Prober.Check)
	//     까지 숨는 것을 막는다. Prober.Check의 런타임 검증은 그대로 두어(선행 방어선 이중화).
	threshold, err := envInt("DEPLOY_HEALTH_SUCCESS_THRESHOLD", defaultHealthThreshold)
	if err != nil {
		return b, err
	}
	interval, err := envDuration("DEPLOY_HEALTH_INTERVAL", defaultHealthInterval)
	if err != nil {
		return b, err
	}
	timeout, err := envDuration("DEPLOY_HEALTH_TIMEOUT", defaultHealthTimeout)
	if err != nil {
		return b, err
	}
	healthDeadline, err := envDuration("DEPLOY_HEALTH_DEADLINE", defaultHealthDeadline)
	if err != nil {
		return b, err
	}
	phaseBudget, err := envDuration("DEPLOY_DISPATCH_PHASE_BUDGET", defaultDispatchPhaseBudget)
	if err != nil {
		return b, err
	}
	if threshold < 1 {
		return b, fmt.Errorf("DEPLOY_HEALTH_SUCCESS_THRESHOLD(N)는 1 이상이어야 한다(fail-closed): %d", threshold)
	}
	if interval <= 0 || timeout <= 0 || healthDeadline <= 0 || phaseBudget <= 0 {
		return b, fmt.Errorf("헬스 간격·타임아웃·deadline과 phaseBudget은 모두 >0 이어야 한다(fail-closed): interval=%s timeout=%s deadline=%s phaseBudget=%s", interval, timeout, healthDeadline, phaseBudget)
	}
	healthCfg := dispatch.HealthConfig{SuccessThreshold: threshold, Interval: interval, Timeout: timeout, Deadline: healthDeadline}

	// 단일 경로(게이트웨이 미설정의 전 경로 · 게이트웨이 모드에서는 target=gateway 전용).
	// 게이트웨이 모드에서는 선택이므로, 셋이 다 비면 배선 없이 둔다(그때 target=gateway 배포는
	// 실행 지점에서 요란하게 UNEXECUTED로 거절된다 — 조용한 성공이 아니다).
	composeFile := os.Getenv("DEPLOY_COMPOSE_FILE")
	project := os.Getenv("DEPLOY_COMPOSE_PROJECT")
	healthURL := os.Getenv("DEPLOY_HEALTH_URL")
	gatewayURL := os.Getenv("DEPLOY_GATEWAY_URL")

	// #21 — 사후조건 identity 결박: 이 배포의 대상 app compose 서비스명. 사후조건(이미지
	// 대조·부분기동)과 CD-1 재시작 검사가 이 서비스의 컨테이너만 본다.
	//   - 블루-그린 모드(게이트웨이 설정)에서는 **필수**다. 그 모드에서 결박 없이 판정하면
	//     사이드카가 pinned digest를 실행 중일 때 app이 틀린 이미지여도 통과하고(H2 fail-open),
	//     그 위로 라우트가 전환된다 — 잘못된 이미지에 트래픽을 얹는 경로라 기동을 거부한다.
	//   - 단일 경로 모드에서는 선택이다(하위호환 — 미설정이면 프로젝트 전체 판정 그대로).
	//     조용히 약한 판정으로 도는 것을 막기 위해 기동 로그에 한 줄 남긴다.
	appService := strings.TrimSpace(os.Getenv("DEPLOY_APP_SERVICE"))
	if gatewayURL != "" && appService == "" {
		return b, errors.New("DEPLOY_GATEWAY_URL이 설정되면 DEPLOY_APP_SERVICE(배포 대상 app compose 서비스명 — 현 .9 구조는 \"app\")가 필수다 — 사후조건을 대상 서비스에 결박하지 않으면 사이드카/orphan이 pinned digest를 실행 중일 때 틀린 이미지가 COMPLETED로 기록되고 그 위로 라우트가 전환된다(H2 fail-open · fail-closed)")
	}

	// 동봉이 필수인 배선(= legacy opt-in이 꺼져 있다)에서는 두 값이 **단일 경로를 포함해**
	// 기동 필수다(리뷰 E-4). 둘 다 동봉 검증의 입력이라, 없으면 검증이 성립하지 않는다:
	//   DEPLOY_APP_SERVICE — CP-3 3자 일치의 호스트 쪽 한 자리. 비면 대조할 상대가 없다.
	//   DEPLOY_IMAGE_ENV   — 동봉 compose의 `image: ${...}` 정확일치 대상. 기본값에 기대면
	//                        정본 compose가 쓰는 변수명(.9: CORE_IMAGE)과 어긋난 채 기동하고,
	//                        그 어긋남은 매 배포의 검증 실패로만 드러난다.
	allowLegacy, err := parseAllowLegacy()
	if err != nil {
		return b, err
	}
	if !allowLegacy {
		if appService == "" {
			return b, fmt.Errorf("동봉 compose가 필수인 배선에서는 DEPLOY_APP_SERVICE가 기동 필수다(단일 경로 포함) — CP-3 3자 일치의 호스트 쪽 값이 없으면 서명된 appService와 대조할 상대가 없다(%s=1로 과도기 경로를 켜지 않는 한 fail-closed)", envAllowLegacy)
		}
		if strings.TrimSpace(os.Getenv("DEPLOY_IMAGE_ENV")) == "" {
			return b, fmt.Errorf("동봉 compose가 필수인 배선에서는 DEPLOY_IMAGE_ENV가 기동 필수다 — 정본 compose의 `image: ${...}` 변수명과 정확히 같아야 하며(현 .9: CORE_IMAGE) 기본값에 기대면 어긋남이 매 배포의 검증 실패로만 드러난다(%s=1로 과도기 경로를 켜지 않는 한 fail-closed)", envAllowLegacy)
		}
	}

	if appService == "" {
		fmt.Println("경고: DEPLOY_APP_SERVICE 미설정 — 사후조건·재시작 검사가 compose 프로젝트 전체를 대상으로 한다(대상 app 서비스 결박 없음 · H2·M1 잔여). 배포 대상 서비스명을 설정하면 결박이 켜진다")
	} else {
		fmt.Printf("사후조건 결박: 대상 app compose 서비스=%q (이미지 대조·부분기동·재시작 검사 대상)\n", appService)
	}

	// slotBase는 슬롯 이름 → (기본 실행기·헬스 URL)이다. 동봉 경로에서 candidate에 결박된
	// 실행기를 파생할 때 이 표에서 그 슬롯의 정체성(compose project·sudo·서비스명)을 물려받는다.
	slotBase := map[string]slotWiring{}

	var singleExec deploy.HostExecutor
	var singleHealth deploy.HealthChecker
	if composeFile != "" || project != "" || healthURL != "" || gatewayURL == "" {
		if composeFile == "" || project == "" || healthURL == "" {
			return b, errors.New("DEPLOY_COMPOSE_FILE·DEPLOY_COMPOSE_PROJECT·DEPLOY_HEALTH_URL은 함께 설정한다 (게이트웨이 미설정이면 필수 · 설정 시에도 셋 다 — fail-closed)")
		}
		execr, herr := newSlotExecutor(composeFile, project, appService)
		if herr != nil {
			return b, herr
		}
		singleExec = execr
		singleHealth = newSlotProber(healthCfg, healthURL, execr)
		slotBase[compose.SlotSingle] = slotWiring{exec: execr, healthURL: healthURL}
	}

	disp := deploy.LocalDispatcher{Exec: singleExec, Health: singleHealth, Repos: repos, PhaseBudget: phaseBudget}

	// 게이트웨이 미설정 = 기존 동작 그대로(전환 단계 없음 · 전환 예산 0). 동봉 배선은 이
	// 경로에도 붙는다 — target=gateway 재기동 교체도 서명 바이트로 결박돼야 한다.
	if gatewayURL == "" {
		rt, rerr := composeRuntimeFor(appService, slotBase, healthCfg)
		if rerr != nil {
			return b, rerr
		}
		disp.Compose = rt
		b.disp, b.healthDeadline, b.phaseBudget = disp, healthDeadline, phaseBudget
		return b, nil
	}

	// 블루-그린 모드 — 슬롯별 실행기·프로버와 라우트 전환 클라이언트를 조립한다.
	drain, err := envDuration("DEPLOY_DRAIN_WAIT", defaultDrainWait)
	if err != nil {
		return b, err
	}
	gwTimeout, err := envDuration("DEPLOY_GATEWAY_TIMEOUT", defaultGatewayTimeout)
	if err != nil {
		return b, err
	}
	if drain <= 0 || gwTimeout <= 0 {
		return b, fmt.Errorf("DEPLOY_DRAIN_WAIT·DEPLOY_GATEWAY_TIMEOUT은 >0 이어야 한다(fail-closed · 드레인 0 = in-flight 절단): drain=%s gatewayTimeout=%s", drain, gwTimeout)
	}

	slotExec := map[deploy.Slot]deploy.HostExecutor{}
	slotHealth := map[deploy.Slot]deploy.HealthChecker{}
	slotProject := map[deploy.Slot]string{}
	for _, s := range []deploy.Slot{deploy.SlotBlue, deploy.SlotGreen} {
		suffix := "_" + strings.ToUpper(string(s))
		file, proj, probeURL := os.Getenv("DEPLOY_COMPOSE_FILE"+suffix), os.Getenv("DEPLOY_COMPOSE_PROJECT"+suffix), os.Getenv("DEPLOY_HEALTH_URL"+suffix)
		if file == "" || proj == "" || probeURL == "" {
			return b, fmt.Errorf("DEPLOY_GATEWAY_URL이 설정되면 슬롯별 설정이 필수다 — DEPLOY_COMPOSE_FILE%s·DEPLOY_COMPOSE_PROJECT%s·DEPLOY_HEALTH_URL%s (fail-closed)", suffix, suffix, suffix)
		}
		execr, eerr := newSlotExecutor(file, proj, appService)
		if eerr != nil {
			return b, eerr
		}
		slotExec[s] = execr
		slotHealth[s] = newSlotProber(healthCfg, probeURL, execr)
		slotProject[s] = proj
		slotBase[string(s)] = slotWiring{exec: execr, healthURL: probeURL}
	}
	// compose project가 겹치면 down 하나가 남의 컨테이너를 철거한다(down은 프로젝트 단위다 —
	// BG-3 ⑶). 겹칠 수 있는 쌍은 셋이며(blue·green·단일), **쌍별로** 다 본다:
	//   blue=green   → 구 slot 종료가 방금 올린 slot까지 끈다.
	//   단일=blue|green → target=gateway 배포(단일 경로)의 실패 정리·재기동 down이 core의
	//                     라이브 슬롯을 철거한다(게이트웨이 배포가 코어를 내린다).
	// 단일 변수는 이 모드에서 선택이므로 비어 있으면 그 쌍은 검사 대상이 아니다.
	for _, pair := range []struct{ aName, a, bName, b string }{
		{"DEPLOY_COMPOSE_PROJECT_BLUE", slotProject[deploy.SlotBlue], "DEPLOY_COMPOSE_PROJECT_GREEN", slotProject[deploy.SlotGreen]},
		{"DEPLOY_COMPOSE_PROJECT", project, "DEPLOY_COMPOSE_PROJECT_BLUE", slotProject[deploy.SlotBlue]},
		{"DEPLOY_COMPOSE_PROJECT", project, "DEPLOY_COMPOSE_PROJECT_GREEN", slotProject[deploy.SlotGreen]},
	} {
		if pair.a == "" || pair.b == "" {
			continue
		}
		if pair.a == pair.b {
			return b, fmt.Errorf("%s와 %s가 같다(%q) — compose down은 프로젝트 단위라 한쪽의 종료·정리가 다른 쪽 컨테이너까지 철거한다(BG-3 ⑶ · fail-closed)", pair.aName, pair.bName, pair.a)
		}
	}

	// R4: /internal 관리 표면 서명 키. DEPLOY_GATEWAY_URL이 설정되면(= 이 블루-그린 경로)
	// 키 없이 기동하지 않는다 — 무서명 폴백을 제거해, agent가 서명을 못 붙인 채 전환을
	// 호출하는 경로를 만들지 않는다(fail-closed). 배포 게이트 1 AGENT_HMAC_KEY와 **별도 키**다.
	internalKey := os.Getenv("GATEWAY_INTERNAL_HMAC_KEY")
	if internalKey == "" {
		return b, errors.New("DEPLOY_GATEWAY_URL이 설정되면 GATEWAY_INTERNAL_HMAC_KEY가 필수다 — 이 키 없이는 agent가 /internal 라우트 전환에 canonical-v1 서명을 붙일 수 없다(무서명 폴백 제거 · fail-closed). 배포 게이트 1의 AGENT_HMAC_KEY와는 별도 키다(다른 신뢰 경계)")
	}
	internalSigner, serr := dispatch.NewInternalSigner([]byte(internalKey))
	if serr != nil {
		return b, fmt.Errorf("게이트웨이 /internal 서명자 조립(fail-closed): %w", serr)
	}

	gw, err := dispatch.NewGatewayClient(gatewayURL, gwTimeout, dispatch.WithInternalSigner(internalSigner))
	if err != nil {
		return b, fmt.Errorf("게이트웨이 라우트 클라이언트 조립(fail-closed): %w", err)
	}

	rt, rerr := composeRuntimeFor(appService, slotBase, healthCfg)
	if rerr != nil {
		return b, rerr
	}

	disp.Gateway = gw
	disp.SlotExec = slotExec
	disp.SlotHealth = slotHealth
	disp.DrainWait = drain
	disp.Compose = rt

	cutover, err := cutoverBudget(gwTimeout, drain)
	if err != nil {
		return b, err
	}

	b.disp, b.healthDeadline, b.phaseBudget = disp, healthDeadline, phaseBudget
	b.cutoverBudget = cutover
	return b, nil
}

// newSlotExecutor는 한 compose 파일·프로젝트를 대상으로 하는 특권 실행기를 만든다.
// sudo 프리픽스·비번·image env 변수명은 슬롯과 무관하게 공통이며, appService(사후조건
// 결박 대상 서비스 — #21)도 슬롯마다 같다: 같은 앱의 blue/green은 compose 프로젝트만
// 다르고 서비스 이름은 같은 파일 구조에서 온다.
func newSlotExecutor(composeFile, project, appService string) (*dispatch.Executor, error) {
	execr, err := dispatch.NewExecutor(dispatch.Config{
		SudoPrefix:   strings.Fields(os.Getenv("DEPLOY_SUDO_PREFIX")), // 공백 split · 비면 직접 실행
		SudoPassword: os.Getenv("DEPLOY_SUDO_PASSWORD"),
		ComposeFile:  composeFile,
		Project:      project,
		ImageEnvVar:  os.Getenv("DEPLOY_IMAGE_ENV"), // 비면 dispatch 기본(DEPLOY_IMAGE_REF)
		AppService:   appService,                    // 비면 결박 없음(프로젝트 전체 판정 — 하위호환)
	})
	if err != nil {
		return nil, fmt.Errorf("특권 실행기 조립(sudo 프리픽스 검증 — fail-closed): %w", err)
	}
	return execr, nil
}

// newSlotProber는 한 슬롯의 준비성 프로버를 만든다. 재시작 검사 대상 컨테이너는 그 슬롯의
// compose 프로젝트에서 파생한다(항상 켠다 — CD-1 그린 위장 방어).
func newSlotProber(cfg dispatch.HealthConfig, url string, execr *dispatch.Executor) *dispatch.Prober {
	cfg.URL = url
	return dispatch.NewProber(cfg, execr)
}

// slotWiring은 한 슬롯의 기본 배선이다(동봉 결박이 여기서 파생된다).
type slotWiring struct {
	exec      *dispatch.Executor
	healthURL string
}

// composeRuntimeFor는 동봉 실행 배선을 조립하고, candidate 결박 실행기·프로버를 만드는
// Bind 클로저를 채운다. 이 클로저가 main에 있는 이유는 import 방향 때문이다 — deploy는
// dispatch를 import하지 않으므로(IA-5), 둘을 다 아는 조립 지점만이 구체 타입을 소비 지점
// 인터페이스로 이어 붙일 수 있다.
//
// 프로버도 함께 새로 만드는 것이 요점이다: 재시작 검사는 `compose ps -q`로 대상 컨테이너를
// 파생하므로, 실행기만 candidate에 결박하고 프로버를 놔두면 헬스 판정이 옛 compose 파일로
// 컨테이너를 찾는다(동봉 필수 호스트에는 그 파일이 아예 없을 수도 있다).
func composeRuntimeFor(appService string, slotBase map[string]slotWiring, healthCfg dispatch.HealthConfig) (*deploy.ComposeRuntime, error) {
	imageEnvVar := os.Getenv("DEPLOY_IMAGE_ENV")
	if imageEnvVar == "" {
		imageEnvVar = dispatch.DefaultImageEnvVar
	}

	hostPorts := map[string]string{}
	for _, s := range []string{compose.SlotSingle, string(deploy.SlotBlue), string(deploy.SlotGreen)} {
		key := envHostPort
		if s != compose.SlotSingle {
			key = envHostPortPrefix + strings.ToUpper(s)
		}
		if _, wired := slotBase[s]; !wired {
			continue
		}
		port, err := hostPort(key)
		if err != nil {
			return nil, err
		}
		if port != "" {
			hostPorts[s] = port
		}
	}

	bind := func(slot string, b deploy.ComposeBinding) (deploy.HostExecutor, deploy.HealthChecker, error) {
		base, ok := slotBase[slot]
		if !ok {
			return nil, nil, fmt.Errorf("슬롯 %q의 기본 배선이 없다 — compose project·헬스 URL이 있어야 candidate에 결박할 수 있다(fail-closed)", slot)
		}
		execr, err := base.exec.WithCompose(b.ComposeFile, b.ProjectDirectory, b.Injected)
		if err != nil {
			return nil, nil, err
		}
		return execr, newSlotProber(healthCfg, base.healthURL, execr), nil
	}

	return buildComposeRuntime(appService, imageEnvVar, hostPorts, bind)
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

// runAgent는 ROLE=agent의 실행자 역할이다. 아직 미구현이므로 기동을 거부한다
// (fail-closed — 다음 마일스톤에서 채운다).
func runAgent() error {
	// TODO(다음 마일스톤): 메인에서 서명된 명령을 LAN 전용으로 수신하고(DO-22),
	// 서명 검증 통과 후 internal/dispatch로 자기 호스트의 특권 조작을 실행한다(DO-23).
	return errors.New("ROLE=agent 미구현 (다음 마일스톤)")
}
