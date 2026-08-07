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
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jun-bank/infra/internal/httpentry"
)

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

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpentry.NewHandler(cfg),
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

// runAgent는 ROLE=agent의 실행자 역할이다. 아직 미구현이므로 기동을 거부한다
// (fail-closed — 다음 마일스톤에서 채운다).
func runAgent() error {
	// TODO(다음 마일스톤): 메인에서 서명된 명령을 LAN 전용으로 수신하고(DO-22),
	// 서명 검증 통과 후 internal/dispatch로 자기 호스트의 특권 조작을 실행한다(DO-23).
	return errors.New("ROLE=agent 미구현 (다음 마일스톤)")
}
