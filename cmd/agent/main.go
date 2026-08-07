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
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/jun-bank/infra/internal/auth"
	"github.com/jun-bank/infra/internal/deploy"
	"github.com/jun-bank/infra/internal/httpentry"
	"github.com/jun-bank/infra/internal/store"
)

// defaultDeployLease는 배포 창 락의 기본 lease다(AGENT_DEPLOY_LEASE로 덮어쓴다). ⚠️ 이
// 값은 [구현 검증]이다 — 한 배포 시퀀스를 넉넉히 덮으면서 죽은 주체를 오래 붙들지 않는
// 실측 값은 배포 시간과 함께 정해진다. store.MinLease(1초) 이상이어야 한다.
const defaultDeployLease = 2 * time.Minute

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

	return deploy.NewCoordinator(deploy.Deps{
		Mode:       st,
		Lock:       st,
		History:    st,
		Dispatcher: deploy.StubDispatcher{}, // 실행 지점은 #15 — 지금은 UNEXECUTED(부작용 0)
		HolderID:   holderID,
		Lease:      lease,
	}), nil
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
