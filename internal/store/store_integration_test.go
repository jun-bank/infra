//go:build integration

// 배포 스키마 계약(ADR-022 DT-9..DT-12; ADR-027 DO-10)을 실제 MySQL에 대해 검증하는
// 통합 테스트. store를 인메모리 대체물이 아니라 진짜 MySQL에 대해 검증한다 — UNIQUE
// 제약에 의한 재생 방어, 3분기, grant 강제(append-only)는 인메모리 페이크가 확인할 수
// 없는 것들이다(test-strategy L1 하한). `integration` 태그로 기본 빌드에서 제외되며,
// 실행은 `make test-integration`이다(Docker 필요 — Testcontainers가 MySQL 8을 띄운다).
//
// 스키마는 deploy/schema/의 실제 DDL(00~03)을 init 스크립트로 적재한다 — 테스트가
// 재해석한 스키마가 아니라 프로비저닝될 바로 그 DDL에 대해 계약을 증명한다.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	tcmysql "github.com/testcontainers/testcontainers-go/modules/mysql"
)

// agentPassword는 03_grants.sql이 deploy_agent에 부여한 플레이스홀더 비밀번호다.
// 컨테이너 안에서만 쓰는 테스트 값이며 시크릿이 아니다(DDL과 반드시 일치해야 한다).
const agentPassword = "__PLACEHOLDER_PROVISIONED_FROM_SECRET_STORE__"

// startMySQL은 실제 스키마 DDL을 적재한 MySQL 8 컨테이너를 띄운다. 반환된 정리 함수는
// 테스트 종료 시 컨테이너를 종료한다.
func startMySQL(t *testing.T) (host string, port string) {
	t.Helper()
	ctx := context.Background()

	ctr, err := tcmysql.Run(ctx, "mysql:8.0",
		tcmysql.WithDatabase("deploy"),
		tcmysql.WithScripts(
			"../../deploy/schema/00_schema.sql",
			"../../deploy/schema/01_tables.sql",
			"../../deploy/schema/02_procedures.sql",
			"../../deploy/schema/03_grants.sql",
		),
	)
	if err != nil {
		t.Fatalf("MySQL 컨테이너 기동 실패: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			t.Logf("컨테이너 종료 실패: %v", err)
		}
	})

	h, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("컨테이너 host 조회 실패: %v", err)
	}
	p, err := ctr.MappedPort(ctx, "3306/tcp")
	if err != nil {
		t.Fatalf("컨테이너 port 조회 실패: %v", err)
	}
	return h, p.Port()
}

// openDB는 DSN으로 연결을 열고 준비될 때까지 핑한다.
func openDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open 실패: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		if err := db.PingContext(ctx); err == nil {
			return db
		}
		select {
		case <-ctx.Done():
			t.Fatalf("DB 준비 대기 시간 초과: %v", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// TestReserveReplayContract는 재생 방어 3분기를 실제 MySQL에 대해 검증한다(DO-10 ⑷).
// 거절/재생 경로를 우선 밟는다 — 조용히 재실행되는 것이 이 원장의 치명적 실패이기
// 때문이다.
func TestReserveReplayContract(t *testing.T) {
	host, port := startMySQL(t)
	// 기본 사용자(test)는 WithDatabase("deploy")로 deploy 스키마 전권을 받는다 —
	// Reserve의 INSERT/SELECT 3분기 로직 검증에 충분하다.
	dsn := fmt.Sprintf("test:test@tcp(%s:%s)/deploy?parseTime=true", host, port)
	st := New(openDB(t, dsn))
	ctx := context.Background()

	// ⑴ 신규 requestId → nil.
	if err := st.Reserve(ctx, "req-A", "", "sha256:aaa"); err != nil {
		t.Fatalf("신규 예약이 실패했다: %v", err)
	}

	// ⑵ 동일 requestId + 동일 digest = 재생 → ErrReplay(재실행 금지).
	if err := st.Reserve(ctx, "req-A", "", "sha256:aaa"); !errors.Is(err, ErrReplay) {
		t.Fatalf("동일 id+동일 digest: err = %v, ErrReplay 기대", err)
	}

	// ⑶ 동일 requestId + 다른 digest = 거절 → ErrDigestConflict.
	if err := st.Reserve(ctx, "req-A", "", "sha256:DIFFERENT"); !errors.Is(err, ErrDigestConflict) {
		t.Fatalf("동일 id+다른 digest: err = %v, ErrDigestConflict 기대", err)
	}

	// ⑷ jti 재사용 = 재전송 → ErrReplay(신규 requestId여도 토큰 재사용은 재생).
	if err := st.Reserve(ctx, "req-B", "jti-1", "sha256:bbb"); err != nil {
		t.Fatalf("jti 최초 예약이 실패했다: %v", err)
	}
	if err := st.Reserve(ctx, "req-C", "jti-1", "sha256:ccc"); !errors.Is(err, ErrReplay) {
		t.Fatalf("jti 재사용: err = %v, ErrReplay 기대", err)
	}

	// 빈 jti는 UNIQUE 충돌로 보지 않는다 — 여러 요청이 jti 없이 공존할 수 있어야 한다.
	if err := st.Reserve(ctx, "req-D", "", "sha256:ddd"); err != nil {
		t.Fatalf("빈 jti 두 번째 예약이 실패했다: %v", err)
	}
}

// TestLedgerAppendOnlyEnforced는 deploy_agent 계정에게 원장 행의 UPDATE/DELETE가
// grant 수준에서 거부됨을 확인한다(DT-12 — 재생 방어를 writer가 되돌릴 수 없다).
// 이것은 인메모리 페이크가 절대 증명할 수 없는 계약이다.
func TestLedgerAppendOnlyEnforced(t *testing.T) {
	host, port := startMySQL(t)
	agentDSN := fmt.Sprintf("deploy_agent:%s@tcp(%s:%s)/deploy", agentPassword, host, port)
	db := openDB(t, agentDSN)
	ctx := context.Background()

	// INSERT는 허용된다(예약 경로).
	if _, err := db.ExecContext(ctx,
		"INSERT INTO `deploy_request_ledger` (`request_id`, `body_digest`) VALUES (?, ?)",
		"req-append", "sha256:x"); err != nil {
		t.Fatalf("deploy_agent INSERT가 거부됐다(허용되어야 한다): %v", err)
	}

	// UPDATE는 거부되어야 한다.
	if _, err := db.ExecContext(ctx,
		"UPDATE `deploy_request_ledger` SET `body_digest` = ? WHERE `request_id` = ?",
		"sha256:tampered", "req-append"); err == nil {
		t.Error("deploy_agent UPDATE가 성공했다 (append-only 위반 — 거부 기대)")
	}

	// DELETE도 거부되어야 한다.
	if _, err := db.ExecContext(ctx,
		"DELETE FROM `deploy_request_ledger` WHERE `request_id` = ?", "req-append"); err == nil {
		t.Error("deploy_agent DELETE가 성공했다 (append-only 위반 — 거부 기대)")
	}
}

// TestModeCurrentContract는 모드 조회·append의 실 계약을 실제 MySQL에 대해 검증한다
// (ADR-027 DO-5·DO-17). 인메모리 페이크가 확인할 수 없는 것들을 우선 밟는다 — 대상별
// 최신 행 선택, 행 부재 시 ErrNoMode(조용한 dev 금지), 그리고 sp_mode_append가 강제하는
// 단조 version(호출자가 version을 정하지 않는다 → 임의·저 version 삽입 경로 부재).
func TestModeCurrentContract(t *testing.T) {
	host, port := startMySQL(t)
	dsn := fmt.Sprintf("test:test@tcp(%s:%s)/deploy?parseTime=true", host, port)
	db := openDB(t, dsn)
	st := New(db)
	ctx := context.Background()

	// ⑴ 행이 없으면 ErrNoMode — store는 기본값을 지어내지 않는다(fail-closed 판정은
	//    호출자 몫). 이것이 조용히 dev로 뭉개지면 승인 게이트가 장애로 열린다.
	if _, _, err := st.Current(ctx, "core"); !errors.Is(err, ErrNoMode) {
		t.Fatalf("행 부재: err = %v, ErrNoMode 기대", err)
	}

	// ⑵ append는 version을 자동으로 「현재 max + 1」로 매긴다(호출자가 정하지 않는다).
	//    operational 위에 dev를 쌓으면 Current는 최신 행(dev·2)을 준다 — 최신 행 선택.
	if err := st.AppendMode(ctx, "core", "operational", "tester"); err != nil {
		t.Fatalf("mode append(#1) 실패: %v", err)
	}
	if err := st.AppendMode(ctx, "core", "dev", "tester"); err != nil {
		t.Fatalf("mode append(#2) 실패: %v", err)
	}
	mode, version, err := st.Current(ctx, "core")
	if err != nil {
		t.Fatalf("Current(core) 실패: %v", err)
	}
	if mode != "dev" || version != 2 {
		t.Fatalf("Current(core) = (%q, %d), (dev, 2) 기대 — 자동 단조 version·최신 행", mode, version)
	}

	// ⑶ 대상은 격리된다: settlement에 행이 없으면 core의 행과 무관하게 ErrNoMode.
	if _, _, err := st.Current(ctx, "settlement"); !errors.Is(err, ErrNoMode) {
		t.Fatalf("대상 격리: settlement err = %v, ErrNoMode 기대", err)
	}

	// ⑷ 단조 강제 + 토글 반영(HIGH fail-open 회귀 방지). 현재 dev/v2인 상태에서
	//    operational로 토글하면, 그 행이 「max + 1 = v3」으로 들어가 Current가 곧바로
	//    operational/v3을 반환한다. 임의 version이었다면 operational/v1이 들어가도
	//    Current는 dev/v2 그대로 — 운영 토글이 무반영되는 fail-open이었다.
	if err := st.AppendMode(ctx, "core", "operational", "tester"); err != nil {
		t.Fatalf("operational 토글 append 실패: %v", err)
	}
	mode, version, err = st.Current(ctx, "core")
	if err != nil {
		t.Fatalf("토글 후 Current(core) 실패: %v", err)
	}
	if mode != "operational" || version != 3 {
		t.Fatalf("토글 후 Current(core) = (%q, %d), (operational, 3) 기대 — 토글이 Current에 반영", mode, version)
	}

	// ⑸ 저 version 삽입은 Current를 끌어내리지 못한다(단조 강제). deploy_mode는 append-only
	//    INSERT를 허용하지만(위 grant), 이미 쓰인 version(≤ 현재 max)은 UNIQUE가 거부하고,
	//    설령 미사용 저 version이 들어가더라도 Current = MAX(version)이므로 최신을 밀어낼 수
	//    없다. 여기서는 현재 max(3)에 대한 raw 재삽입이 UNIQUE로 거부됨을 확인한다.
	if _, err := db.ExecContext(ctx,
		"INSERT INTO `deploy_mode` (`target`, `mode`, `mode_version`, `actor`) VALUES (?, ?, ?, ?)",
		"core", "dev", 3, "tester"); err == nil {
		t.Error("현재 max version(3) 재삽입이 성공했다 — UNIQUE 거부 기대(단조 위반)")
	}
	mode, version, err = st.Current(ctx, "core")
	if err != nil {
		t.Fatalf("저 version 삽입 시도 후 Current(core) 실패: %v", err)
	}
	if mode != "operational" || version != 3 {
		t.Fatalf("저 version 삽입 시도 후 Current(core) = (%q, %d), (operational, 3) 불변 기대", mode, version)
	}
}

// TestModeAppendOnlyEnforced는 deploy_agent 계정에게 mode 행의 UPDATE/DELETE가 grant
// 수준에서 거부됨을 확인한다(DT-12 — 토글 이력을 writer가 되돌릴 수 없다). 인메모리
// 페이크가 절대 증명할 수 없는 계약이다.
func TestModeAppendOnlyEnforced(t *testing.T) {
	host, port := startMySQL(t)
	agentDSN := fmt.Sprintf("deploy_agent:%s@tcp(%s:%s)/deploy", agentPassword, host, port)
	db := openDB(t, agentDSN)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		"INSERT INTO `deploy_mode` (`target`, `mode`, `mode_version`, `actor`) VALUES (?, ?, ?, ?)",
		"core", "operational", 1, "agent"); err != nil {
		t.Fatalf("deploy_agent INSERT가 거부됐다(허용되어야 한다): %v", err)
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE `deploy_mode` SET `mode` = ? WHERE `target` = ?", "dev", "core"); err == nil {
		t.Error("deploy_agent UPDATE가 성공했다 (append-only 위반 — 거부 기대)")
	}
	if _, err := db.ExecContext(ctx,
		"DELETE FROM `deploy_mode` WHERE `target` = ?", "core"); err == nil {
		t.Error("deploy_agent DELETE가 성공했다 (append-only 위반 — 거부 기대)")
	}
}

// TestLockContract는 일곱 개 전이와 그 불변식을 다룬다(DT-12, R6).
//
// 케이스(다음 단계에서 SQLStore 락 메서드가 구현될 때 연결한다):
//   - 비어 있는 락 acquire는 ok·token=N; 동시 두 번째 acquire는 ok=false(양방향 경합).
//   - fencing token은 release/재획득에 걸쳐 단조 증가하며 리셋되지 않는다.
//   - renew/release는 현재 holder(kind+id+token)에 대해서만 성공한다.
//   - deploy_window_lock에 대한 raw UPDATE/DELETE는 두 계정 모두에 거부된다(DT-12).
func TestLockContract(t *testing.T) {
	t.Skip("integration scaffold: SQLStore 락 전이 구현 후 연결한다(다음 단계)")
}

// TestHandshake는 ADR-024 §2.4 "정지 후 인계" 긴급 롤백 인계를 다룬다(다음 단계).
func TestHandshake(t *testing.T) {
	t.Skip("integration scaffold: SQLStore 락 전이 구현 후 연결한다(다음 단계)")
}
