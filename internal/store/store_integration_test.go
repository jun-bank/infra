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
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

// openStore는 주어진 배포 스키마 계정으로 연 SQLStore를 만든다. parseTime=true는
// lease_expires_at(DATETIME) 스냅샷 읽기에 필요하다. 두 계정(deploy_agent, cutoff_lock)은
// DDL에서 같은 플레이스홀더 비밀번호를 쓴다.
func openStore(t *testing.T, host, port, account string) *SQLStore {
	t.Helper()
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/deploy?parseTime=true", account, agentPassword, host, port)
	return New(openDB(t, dsn))
}

// TestLockContract는 정상 경로 락 전이(acquire/renew/release/read)와 그 불변식을 실제
// MySQL에 대해, 그리고 deploy_agent 계정으로 검증한다(CD-3 · DT-12). deploy_agent를
// 경유하므로 SQL SECURITY DEFINER + EXECUTE 전용 계약(테이블 raw DML 없이 전이가 도는가 —
// CDV-19)이 동시에 실증된다. 거절/안전 경로를 우선 밟는다.
func TestLockContract(t *testing.T) {
	host, port := startMySQL(t)
	st := openStore(t, host, port, "deploy_agent")
	ctx := context.Background()

	// ⑴ 초기 상태: 점유 없음, 토큰 0(단일 행 시드).
	ls, err := st.Read(ctx)
	if err != nil {
		t.Fatalf("초기 Read 실패: %v", err)
	}
	if ls.HolderKind != HolderNone || ls.FencingToken != 0 {
		t.Fatalf("초기 락 = %+v, HolderNone·token 0 기대", ls)
	}

	// ⑵ 빈 락 획득 → ok·새 토큰. deploy_agent가 EXECUTE로 프로시저를 도는 것(DEFINER)이
	//    여기서 실증된다.
	tok1, ok, err := st.Acquire(ctx, HolderAgent, "deploy-1", 60*time.Second)
	if err != nil {
		t.Fatalf("Acquire 실패(EXECUTE/DEFINER 계약 확인): %v", err)
	}
	if !ok || tok1 == 0 {
		t.Fatalf("빈 락 획득 = (token %d, ok %v), 획득·token>0 기대", tok1, ok)
	}

	// ⑶ 경합: 유효 lease로 점유 중이면 두 번째 획득은 거절(ok=false) — 오류가 아니다.
	if _, ok, err := st.Acquire(ctx, HolderAgent, "deploy-2", 60*time.Second); err != nil || ok {
		t.Fatalf("점유 중 재획득 = (ok %v, err %v), 거절(ok=false) 기대", ok, err)
	}

	// ⑷ Read는 현재 holder를 비춘다.
	ls, err = st.Read(ctx)
	if err != nil {
		t.Fatalf("점유 중 Read 실패: %v", err)
	}
	if ls.HolderKind != HolderAgent || ls.HolderID != "deploy-1" || ls.FencingToken != tok1 {
		t.Fatalf("점유 중 락 = %+v, (AGENT, deploy-1, %d) 기대", ls, tok1)
	}

	// ⑸ Renew(보유 재확인/fencing): 틀린 토큰은 거짓, 내 토큰은 참.
	if ok, _ := st.Renew(ctx, HolderAgent, "deploy-1", tok1+99, 60*time.Second); ok {
		t.Fatal("틀린 fencing 토큰 Renew가 성공했다 — 거짓 기대(좀비 차단)")
	}
	if ok, err := st.Renew(ctx, HolderAgent, "deploy-1", tok1, 60*time.Second); err != nil || !ok {
		t.Fatalf("현재 holder Renew = (ok %v, err %v), 참 기대", ok, err)
	}

	// ⑹ Release: 틀린 토큰은 거짓, 내 토큰은 참 → 이후 점유 없음.
	if ok, _ := st.Release(ctx, HolderAgent, "deploy-1", tok1+99); ok {
		t.Fatal("틀린 토큰 Release가 성공했다 — 거짓 기대")
	}
	if ok, err := st.Release(ctx, HolderAgent, "deploy-1", tok1); err != nil || !ok {
		t.Fatalf("현재 holder Release = (ok %v, err %v), 참 기대", ok, err)
	}
	if ls, _ := st.Read(ctx); ls.HolderKind != HolderNone {
		t.Fatalf("해제 후 락 = %+v, HolderNone 기대", ls)
	}

	// ⑺ fencing 단조: 재획득 토큰은 직전보다 크다(해제로 리셋되지 않는다).
	tok2, ok, err := st.Acquire(ctx, HolderAgent, "deploy-3", 60*time.Second)
	if err != nil || !ok {
		t.Fatalf("해제 후 재획득 실패: ok=%v err=%v", ok, err)
	}
	if tok2 <= tok1 {
		t.Fatalf("fencing 토큰이 단조 증가하지 않았다: 재획득 %d ≤ 직전 %d", tok2, tok1)
	}
	if ok, _ := st.Release(ctx, HolderAgent, "deploy-3", tok2); !ok {
		t.Fatal("정리 Release 실패")
	}

	// ⑻ stale 회수: 짧은 lease로 잡고 만료된 뒤 다른 주체가 회수 획득한다 — 토큰은 계속
	//    증가한다. lease는 정수 초 정밀도라 1초로 잡고 여유 있게 대기한다.
	tok3, ok, err := st.Acquire(ctx, HolderAgent, "deploy-4", 1*time.Second)
	if err != nil || !ok {
		t.Fatalf("짧은 lease 획득 실패: ok=%v err=%v", ok, err)
	}
	time.Sleep(1500 * time.Millisecond)
	tok4, ok, err := st.Acquire(ctx, HolderAgent, "deploy-5", 60*time.Second)
	if err != nil || !ok {
		t.Fatalf("만료 lease 회수 획득 실패: ok=%v err=%v (만료가 회수하지 못했다)", ok, err)
	}
	if tok4 <= tok3 {
		t.Fatalf("회수 획득 토큰 %d ≤ 만료 토큰 %d — 단조 위반", tok4, tok3)
	}
	if ls, _ := st.Read(ctx); ls.HolderID != "deploy-5" {
		t.Fatalf("회수 후 holder = %q, deploy-5 기대", ls.HolderID)
	}
	if ok, _ := st.Release(ctx, HolderAgent, "deploy-5", tok4); !ok {
		t.Fatal("정리 Release 실패")
	}
}

// TestLockBidirectional은 배포 ↔ 배치 상호 배제를 실제 두 계정(deploy_agent · cutoff_lock)
// 으로 검증한다(CD-3 양방향). 한 주체가 같은 단일 행을 점유하면 반대 주체의 획득은 거절된다.
func TestLockBidirectional(t *testing.T) {
	host, port := startMySQL(t)
	agent := openStore(t, host, port, "deploy_agent")
	cutoff := openStore(t, host, port, "cutoff_lock")
	ctx := context.Background()

	// 배치·커트오프가 점유 → 배포 획득 거절.
	cTok, ok, err := cutoff.Acquire(ctx, HolderBatchCutoff, "cutoff-1", 60*time.Second)
	if err != nil || !ok {
		t.Fatalf("커트오프 획득 실패: ok=%v err=%v", ok, err)
	}
	if _, ok, err := agent.Acquire(ctx, HolderAgent, "deploy-1", 60*time.Second); err != nil || ok {
		t.Fatalf("배치 점유 중 배포 획득 = (ok %v, err %v), 거절 기대(양방향)", ok, err)
	}

	// 커트오프 해제 → 배포 획득 성공.
	if ok, err := cutoff.Release(ctx, HolderBatchCutoff, "cutoff-1", cTok); err != nil || !ok {
		t.Fatalf("커트오프 해제 실패: ok=%v err=%v", ok, err)
	}
	aTok, ok, err := agent.Acquire(ctx, HolderAgent, "deploy-1", 60*time.Second)
	if err != nil || !ok {
		t.Fatalf("해제 후 배포 획득 실패: ok=%v err=%v", ok, err)
	}

	// 역방향: 배포가 점유 중이면 커트오프 획득 거절.
	if _, ok, err := cutoff.Acquire(ctx, HolderBatchCutoff, "cutoff-2", 60*time.Second); err != nil || ok {
		t.Fatalf("배포 점유 중 커트오프 획득 = (ok %v, err %v), 거절 기대(역방향)", ok, err)
	}
	if ok, _ := agent.Release(ctx, HolderAgent, "deploy-1", aTok); !ok {
		t.Fatal("정리 Release 실패")
	}
}

// TestLockRawDMLDenied는 두 계정 모두 deploy_window_lock에 raw UPDATE/DELETE를 갖지
// 않음을 확인한다(DT-12 — 락 행은 전이 프로시저로만 바뀐다). 인메모리 페이크가 증명할
// 수 없는 grant 계약이며, EXECUTE로 도는 프로시저와 raw DML 금지가 공존함을 못박는다.
func TestLockRawDMLDenied(t *testing.T) {
	host, port := startMySQL(t)
	ctx := context.Background()
	for _, account := range []string{"deploy_agent", "cutoff_lock"} {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/deploy", account, agentPassword, host, port)
		db := openDB(t, dsn)
		if _, err := db.ExecContext(ctx,
			"UPDATE `deploy_window_lock` SET `holder_kind` = 'AGENT' WHERE `lock_id` = 1"); err == nil {
			t.Errorf("%s: 락 행 raw UPDATE가 성공했다 (DT-12 위반 — 거부 기대)", account)
		}
		if _, err := db.ExecContext(ctx,
			"DELETE FROM `deploy_window_lock` WHERE `lock_id` = 1"); err == nil {
			t.Errorf("%s: 락 행 raw DELETE가 성공했다 (DT-12 위반 — 거부 기대)", account)
		}
	}
}

// TestFencingLeaseHeldContract는 위성 fence-confirm의 DB시각 판정(G-4 · FencingLeaseHeld)을
// 실 MySQL로 검증한다: 같은 holder+token은 살아있을 때만 held=true이고, token 불일치·holder
// 불일치·lease 만료·미점유는 전부 held=false다(확인 실패 = fence deny). 만료 판정을 **DB의
// NOW(6)로** 하는 것(Go 시계 아님)이 핵심이라, 짧은 lease를 만료시킨 뒤 held=false를 본다.
func TestFencingLeaseHeldContract(t *testing.T) {
	host, port := startMySQL(t)
	st := openStore(t, host, port, "deploy_agent")
	ctx := context.Background()

	// 미점유 — 어떤 token도 held=false.
	if held, err := st.FencingLeaseHeld(ctx, "main-1", 1); err != nil || held {
		t.Fatalf("미점유 락은 held=false여야 한다: held=%v err=%v", held, err)
	}

	// 점유(넉넉한 lease) — 같은 holder+token만 held=true.
	tok, ok, err := st.Acquire(ctx, HolderAgent, "main-1", 60*time.Second)
	if err != nil || !ok {
		t.Fatalf("Acquire 실패: ok=%v err=%v", ok, err)
	}
	if held, err := st.FencingLeaseHeld(ctx, "main-1", tok); err != nil || !held {
		t.Fatalf("현 holder+token은 held=true여야 한다: held=%v err=%v", held, err)
	}
	// token 불일치 → false.
	if held, _ := st.FencingLeaseHeld(ctx, "main-1", tok+1); held {
		t.Fatal("token 불일치인데 held=true — fencing 판정 실패")
	}
	// holder 불일치 → false(main holder가 다르면 내 lock이 아니다).
	if held, _ := st.FencingLeaseHeld(ctx, "other-main", tok); held {
		t.Fatal("holder 불일치인데 held=true — 판정 실패")
	}
	if ok, _ := st.Release(ctx, HolderAgent, "main-1", tok); !ok {
		t.Fatal("정리 Release 실패")
	}

	// lease 만료 — DB시각 기준으로 held=false여야 한다(Go 시계 편차와 무관). lease 정밀도는
	// 정수 초라 1초로 잡고 여유 있게 기다린다.
	tok2, ok, err := st.Acquire(ctx, HolderAgent, "main-1", 1*time.Second)
	if err != nil || !ok {
		t.Fatalf("짧은 lease 획득 실패: ok=%v err=%v", ok, err)
	}
	if held, err := st.FencingLeaseHeld(ctx, "main-1", tok2); err != nil || !held {
		t.Fatalf("만료 전에는 held=true여야 한다: held=%v err=%v", held, err)
	}
	time.Sleep(1500 * time.Millisecond)
	if held, err := st.FencingLeaseHeld(ctx, "main-1", tok2); err != nil || held {
		t.Fatalf("lease 만료 후에는 held=false여야 한다(DB시각 판정): held=%v err=%v", held, err)
	}
}

// --- S2-1 보안 회귀 + 동시성 -------------------------------------------------

// TestLockCrossAccountReleaseDenied는 반대 계정이 남의 락을 해제할 수 없음을 실 MySQL로
// 검증한다(S2-1 결함1 · DT-12 §153 ⑵ "남의 token으로 해제 거부"). 실증된 구멍이다:
// 두 계정이 공유 프로시저에 EXECUTE를 갖고 락 행 SELECT로 상대 token을 읽으면 상대 락을
// 해제할 수 있었다. 역할별 wrapper(kind 결박) + impl 무권한으로 그 경로를 닫는다.
func TestLockCrossAccountReleaseDenied(t *testing.T) {
	host, port := startMySQL(t)
	agent := openStore(t, host, port, "deploy_agent")
	cutoff := openStore(t, host, port, "cutoff_lock")
	ctx := context.Background()

	// agent가 락을 잡는다.
	aTok, ok, err := agent.Acquire(ctx, HolderAgent, "deploy-1", 60*time.Second)
	if err != nil || !ok {
		t.Fatalf("agent 획득 실패: ok=%v err=%v", ok, err)
	}

	// cutoff가 락 행 SELECT로 agent의 holder_id·token을 읽는다(두 계정 다 SELECT 보유).
	ls, err := cutoff.Read(ctx)
	if err != nil {
		t.Fatalf("cutoff Read 실패: %v", err)
	}
	if ls.HolderKind != HolderAgent || ls.FencingToken != aTok {
		t.Fatalf("cutoff가 본 락 = %+v, agent 보유(token %d) 기대", ls, aTok)
	}

	// 공격 ⑴: 상대 kind(AGENT) wrapper로 해제 시도 → cutoff에는 sp_lock_release_agent
	// EXECUTE가 없어 권한 오류(해제되지 않는다).
	if released, err := cutoff.Release(ctx, HolderAgent, ls.HolderID, ls.FencingToken); released {
		t.Fatal("cutoff가 AGENT wrapper로 agent 락 해제에 성공했다 (권한 경계 위반)")
	} else if err == nil {
		t.Fatal("cutoff의 상대 kind 해제가 오류 없이 통과했다 — 권한 거부(err) 기대")
	}

	// 공격 ⑵: 자기 kind(BATCH_CUTOFF) wrapper로 시도 → 프로시저가 kind='BATCH_CUTOFF'로
	// 결박돼 AGENT 보유 행에 매치되지 않는다(ok=false, 오류는 아니다).
	if released, _ := cutoff.Release(ctx, HolderBatchCutoff, ls.HolderID, ls.FencingToken); released {
		t.Fatal("cutoff가 BATCH_CUTOFF wrapper로 AGENT 락 해제에 성공했다 — 거부 기대")
	}

	// agent 락은 그대로여야 한다.
	ls2, err := agent.Read(ctx)
	if err != nil {
		t.Fatalf("Read 실패: %v", err)
	}
	if ls2.HolderKind != HolderAgent || ls2.HolderID != "deploy-1" || ls2.FencingToken != aTok {
		t.Fatalf("공격 후 락 = %+v, agent(deploy-1, token %d) 불변 기대", ls2, aTok)
	}

	// 대칭 확인: agent 자신은 여전히 정상 해제할 수 있다(잡은 주체만 해제).
	if released, err := agent.Release(ctx, HolderAgent, "deploy-1", aTok); err != nil || !released {
		t.Fatalf("잡은 주체(agent) 해제 실패: released=%v err=%v", released, err)
	}
}

// TestLockLeaseFloorEnforced는 최소 1초 lease가 Go 경계와 프로시저 양쪽에서 강제됨을
// 검증한다(S2-1 결함2). sub-second/0/음수 lease는 ok=true인 무보호 락을 만들면 안 되고,
// Renew(...,0)은 살아있는 lease를 줄이면 안 된다.
func TestLockLeaseFloorEnforced(t *testing.T) {
	host, port := startMySQL(t)
	agent := openStore(t, host, port, "deploy_agent")
	ctx := context.Background()

	// ⑴ Go 경계: sub-second/0/음수 lease 획득은 ErrLeaseTooShort + 락 미생성.
	for _, d := range []time.Duration{0, 500 * time.Millisecond, -1 * time.Second} {
		if _, ok, err := agent.Acquire(ctx, HolderAgent, "deploy-1", d); !errors.Is(err, ErrLeaseTooShort) || ok {
			t.Fatalf("lease %v 획득 = (ok %v, err %v), ErrLeaseTooShort·미획득 기대(fail-closed)", d, ok, err)
		}
	}
	if ls, _ := agent.Read(ctx); ls.HolderKind != HolderNone {
		t.Fatalf("짧은 lease 시도 후 락 = %+v, 미점유 기대", ls)
	}

	// ⑵ 프로시저 계층(Go 우회): test 계정으로 wrapper를 직접 CALL해 lease=0을 넣어도 ok=0.
	//    이것이 없으면 Go만 뚫으면 무보호 락이 열린다(계층 이중 강제 실증).
	rdb := openDB(t, fmt.Sprintf("test:test@tcp(%s:%s)/deploy?parseTime=true", host, port))
	conn, err := rdb.Conn(ctx)
	if err != nil {
		t.Fatalf("root conn 실패: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "CALL `sp_lock_acquire_agent`('ghost', 0, @t, @o)"); err != nil {
		t.Fatalf("직접 CALL 실패: %v", err)
	}
	var procOK int64
	if err := conn.QueryRowContext(ctx, "SELECT @o").Scan(&procOK); err != nil {
		t.Fatalf("@o 읽기 실패: %v", err)
	}
	if procOK != 0 {
		t.Fatal("프로시저가 lease=0 획득을 ok=1로 허용했다 (proc 계층 floor 미작동)")
	}
	if ls, _ := agent.Read(ctx); ls.HolderKind != HolderNone {
		t.Fatalf("proc 우회 시도 후 락 = %+v, 미점유 기대", ls)
	}

	// ⑶ Renew(...,0)은 살아있는 lease를 줄이지 못한다(Go에서 ErrLeaseTooShort로 거절).
	aTok, ok, err := agent.Acquire(ctx, HolderAgent, "deploy-1", 60*time.Second)
	if err != nil || !ok {
		t.Fatalf("정상 획득 실패: ok=%v err=%v", ok, err)
	}
	before, _ := agent.Read(ctx)
	if _, err := agent.Renew(ctx, HolderAgent, "deploy-1", aTok, 0); !errors.Is(err, ErrLeaseTooShort) {
		t.Fatalf("Renew(...,0): err=%v, ErrLeaseTooShort 기대", err)
	}
	after, _ := agent.Read(ctx)
	if !after.LeaseExpiresAt.Equal(before.LeaseExpiresAt) {
		t.Fatalf("Renew(...,0)이 lease 만료를 바꿨다: %v → %v (줄이면 안 됨)", before.LeaseExpiresAt, after.LeaseExpiresAt)
	}

	// 정상 Renew(연장)는 통과해야 한다(정상 경로 계약 불변).
	if ok, err := agent.Renew(ctx, HolderAgent, "deploy-1", aTok, 120*time.Second); err != nil || !ok {
		t.Fatalf("정상 Renew(연장) = (ok %v, err %v), 참 기대", ok, err)
	}
	if _, err := agent.Release(ctx, HolderAgent, "deploy-1", aTok); err != nil {
		t.Fatalf("정리 Release 오류: %v", err)
	}
}

// TestLockHolderKindRejected는 holder_kind ∈ {AGENT, BATCH_CUTOFF}만 허용됨을 검증한다
// (S2-1 결함3 — 유령 락 방지). impl은 계정에 EXECUTE가 없으므로 전권 test 계정으로 직접
// CALL해 proc 계층의 명시 검증을 실증한다.
func TestLockHolderKindRejected(t *testing.T) {
	host, port := startMySQL(t)
	rdb := openDB(t, fmt.Sprintf("test:test@tcp(%s:%s)/deploy?parseTime=true", host, port))
	ctx := context.Background()
	conn, err := rdb.Conn(ctx)
	if err != nil {
		t.Fatalf("root conn 실패: %v", err)
	}
	defer conn.Close()

	acquireImpl := func(kind string) int64 {
		if _, err := conn.ExecContext(ctx,
			"CALL `sp_lock_acquire_impl`(?, 'h', 60, @t, @o)", kind); err != nil {
			t.Fatalf("impl CALL(%s) 실패: %v", kind, err)
		}
		var ok int64
		if err := conn.QueryRowContext(ctx, "SELECT @o").Scan(&ok); err != nil {
			t.Fatalf("@o 읽기(%s) 실패: %v", kind, err)
		}
		return ok
	}

	if got := acquireImpl("NONE"); got != 0 {
		t.Fatalf("holder_kind='NONE' → ok=%d, 0 기대(유령 락 거절)", got)
	}
	if got := acquireImpl("BOGUS"); got != 0 {
		t.Fatalf("holder_kind='BOGUS' → ok=%d, 0 기대(미지 kind 거절)", got)
	}
	// sanity: 유효 kind는 통과(그리고 Go 디스패치도 미지 kind를 거절하는지 확인).
	if got := acquireImpl("AGENT"); got != 1 {
		t.Fatalf("holder_kind='AGENT' → ok=%d, 1 기대(유효 kind 통과)", got)
	}

	// Go 계층: 미지 kind는 ErrInvalidHolderKind로 거절(프로시저에 도달하지 않는다).
	agent := openStore(t, host, port, "deploy_agent")
	if _, _, err := agent.Acquire(ctx, HolderNone, "x", 60*time.Second); !errors.Is(err, ErrInvalidHolderKind) {
		t.Fatalf("Go Acquire(NONE): err=%v, ErrInvalidHolderKind 기대", err)
	}
	if _, err := agent.Release(ctx, HolderKind("BOGUS"), "x", 1); !errors.Is(err, ErrInvalidHolderKind) {
		t.Fatalf("Go Release(BOGUS): err=%v, ErrInvalidHolderKind 기대", err)
	}
}

// procExists는 deploy 스키마에 주어진 이름의 프로시저가 존재하는지 information_schema로 본다.
func procExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var cnt int
	if err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM information_schema.ROUTINES "+
			"WHERE ROUTINE_SCHEMA = 'deploy' AND ROUTINE_TYPE = 'PROCEDURE' AND ROUTINE_NAME = ?",
		name).Scan(&cnt); err != nil {
		t.Fatalf("ROUTINES 조회(%s) 실패: %v", name, err)
	}
	return cnt > 0
}

// extractOldDrops는 02_procedures.sql에서 구 flat 이름(oldNames)에 대한 정확한
// `DROP PROCEDURE IF EXISTS` 문만 뽑는다. _impl/_agent/_cutoff 접미사 이름은 백틱 경계가
// 달라 매치되지 않는다. 파일에 구 이름 DROP이 없으면 빈 슬라이스를 돌려주므로, 재적용
// 정리 누락(회귀)이 곧 테스트 실패가 된다.
func extractOldDrops(t *testing.T, path string, oldNames []string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s 읽기 실패: %v", path, err)
	}
	want := map[string]bool{}
	for _, n := range oldNames {
		want["DROP PROCEDURE IF EXISTS `"+n+"`"] = true
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		s := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), "$$"))
		if want[s] {
			out = append(out, s)
		}
	}
	return out
}

// TestOldVulnerableProceduresDropped는 S2-1 이전 kind-공유 flat 구판(sp_lock_acquire /
// renew / release)이 스키마 재적용으로 제거됨을 실 MySQL로 검증한다(재점검 fix ⑴). 이미
// 프로비저닝된 DB에 그 구판이 남으면 두 계정이 상대 락을 해제·갱신하던 결함1 구멍이
// 구판을 통해 계속 열려 있다. 레거시 DB를 시뮬레이션한 뒤 02_procedures.sql이 발행하는
// 구 이름 DROP을 그 파일에서 뽑아 실행해, 구판 부재 + 새 wrapper 불변을 확인한다.
func TestOldVulnerableProceduresDropped(t *testing.T) {
	host, port := startMySQL(t)
	// 전권 test 계정(deploy 스키마)으로 구판 생성·정리 DDL을 실행한다.
	db := openDB(t, fmt.Sprintf("test:test@tcp(%s:%s)/deploy", host, port))
	ctx := context.Background()

	oldNames := []string{"sp_lock_acquire", "sp_lock_renew", "sp_lock_release"}

	// ⑴ 신규 스키마는 구 flat 이름을 만들지 않는다(회귀 가드 — 누가 flat 판을 되살리면 잡힌다).
	for _, n := range oldNames {
		if procExists(t, db, n) {
			t.Fatalf("신규 스키마가 구 flat 프로시저 %s 를 만들었다 (없어야 한다)", n)
		}
	}

	// ⑵ 레거시 DB 시뮬레이션: S2-1 이전의 취약 flat 구판을 만든다(스텁 바디면 존재 확인에 충분).
	for _, n := range oldNames {
		if _, err := db.ExecContext(ctx,
			fmt.Sprintf("CREATE PROCEDURE `%s`() BEGIN SELECT 1; END", n)); err != nil {
			t.Fatalf("구판 %s 생성 실패: %v", n, err)
		}
		if !procExists(t, db, n) {
			t.Fatalf("구판 %s 가 생성되지 않았다", n)
		}
	}

	// ⑶ 스키마 재적용의 정리 경로: 02_procedures.sql이 구 이름에 발행하는 DROP을 실행한다.
	//    파일에 그 DROP이 없으면(수정 전 = red) 구판이 남아 아래 부재 확인이 실패한다.
	drops := extractOldDrops(t, "../../deploy/schema/02_procedures.sql", oldNames)
	if len(drops) != len(oldNames) {
		t.Fatalf("02_procedures.sql에서 구 이름 DROP을 %d개만 찾았다(=%v), %d개 기대 (재적용 정리 누락)",
			len(drops), drops, len(oldNames))
	}
	for _, stmt := range drops {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("DROP 실행 실패(%q): %v", stmt, err)
		}
	}

	// ⑷ 구 취약 프로시저 부재.
	for _, n := range oldNames {
		if procExists(t, db, n) {
			t.Errorf("재적용 후에도 구 취약 프로시저 %s 가 남아 있다 (정리 실패)", n)
		}
	}
	// ⑸ 새 wrapper는 그대로여야 한다(정상 경로 계약 불변).
	for _, n := range []string{
		"sp_lock_acquire_agent", "sp_lock_acquire_cutoff",
		"sp_lock_release_agent", "sp_lock_release_cutoff",
	} {
		if !procExists(t, db, n) {
			t.Errorf("새 wrapper %s 가 사라졌다 (재적용이 정상 경로를 깼다)", n)
		}
	}
}

// TestLockNullInputRejected는 acquire/renew impl이 NULL holder_kind·NULL lease를 명시적으로
// fail-closed 거절함을 실 MySQL로 검증한다(재점검 fix ⑵). NULL이면 NOT IN·< 1 비교가 전부
// UNKNOWN이 돼 IF를 못 타고 ELSE로 빠지면, 빈 락에 holder_kind=NULL·lease_expires_at=NULL인
// 만료 없는 무보호/유령 락이 ok=1로 만들어지는 fail-open이 열렸다(수정 전 acquire = red).
// impl은 계정 EXECUTE가 없으므로 전권 test 계정으로 직접 CALL한다.
func TestLockNullInputRejected(t *testing.T) {
	host, port := startMySQL(t)
	rdb := openDB(t, fmt.Sprintf("test:test@tcp(%s:%s)/deploy?parseTime=true", host, port))
	agent := openStore(t, host, port, "deploy_agent")
	ctx := context.Background()
	conn, err := rdb.Conn(ctx)
	if err != nil {
		t.Fatalf("root conn 실패: %v", err)
	}
	defer conn.Close()

	acquireImpl := func(kindSQL, leaseSQL string) int64 {
		if _, err := conn.ExecContext(ctx,
			fmt.Sprintf("CALL `sp_lock_acquire_impl`(%s, 'h', %s, @t, @o)", kindSQL, leaseSQL)); err != nil {
			t.Fatalf("acquire impl CALL(kind=%s,lease=%s) 실패: %v", kindSQL, leaseSQL, err)
		}
		var ok int64
		if err := conn.QueryRowContext(ctx, "SELECT @o").Scan(&ok); err != nil {
			t.Fatalf("@o 읽기 실패: %v", err)
		}
		return ok
	}

	// NULL holder_kind → ok=0 (유령 락 거절). 수정 전에는 ELSE로 빠져 holder_kind=NULL·ok=1.
	if got := acquireImpl("NULL", "60"); got != 0 {
		t.Fatalf("acquire(kind=NULL) → ok=%d, 0 기대(NULL fail-closed)", got)
	}
	if ls, _ := agent.Read(ctx); ls.HolderKind != HolderNone {
		t.Fatalf("NULL kind 시도 후 락 = %+v, 미점유 기대", ls)
	}
	// NULL lease → ok=0 (만료 없는 무보호 락 거절). 수정 전에는 lease_expires_at=NULL·ok=1.
	if got := acquireImpl("'AGENT'", "NULL"); got != 0 {
		t.Fatalf("acquire(lease=NULL) → ok=%d, 0 기대(NULL fail-closed)", got)
	}
	if ls, _ := agent.Read(ctx); ls.HolderKind != HolderNone {
		t.Fatalf("NULL lease 시도 후 락 = %+v, 미점유 기대", ls)
	}
	// sanity: 유효 입력은 통과(정상 경로 계약 불변) — 이후 renew 테스트가 이 락을 재확인한다.
	if got := acquireImpl("'AGENT'", "60"); got != 1 {
		t.Fatalf("acquire(AGENT,60) → ok=%d, 1 기대(유효 입력 통과)", got)
	}

	// renew impl NULL 거절. 방금 잡은 유효 락(AGENT 'h')의 token·만료를 읽어 둔다.
	ls, err := agent.Read(ctx)
	if err != nil {
		t.Fatalf("Read 실패: %v", err)
	}
	tok := int64(ls.FencingToken)
	before := ls.LeaseExpiresAt

	renewImpl := func(kindSQL, leaseSQL string) int64 {
		if _, err := conn.ExecContext(ctx,
			fmt.Sprintf("CALL `sp_lock_renew_impl`(%s, 'h', %d, %s, @o)", kindSQL, tok, leaseSQL)); err != nil {
			t.Fatalf("renew impl CALL(kind=%s,lease=%s) 실패: %v", kindSQL, leaseSQL, err)
		}
		var ok int64
		if err := conn.QueryRowContext(ctx, "SELECT @o").Scan(&ok); err != nil {
			t.Fatalf("@o 읽기 실패: %v", err)
		}
		return ok
	}
	if got := renewImpl("'AGENT'", "NULL"); got != 0 {
		t.Fatalf("renew(lease=NULL) → ok=%d, 0 기대(NULL fail-closed)", got)
	}
	if got := renewImpl("NULL", "60"); got != 0 {
		t.Fatalf("renew(kind=NULL) → ok=%d, 0 기대(NULL fail-closed)", got)
	}
	// NULL renew가 살아있는 lease를 NULL(무보호)로 훼손하지 않았는지 확인(정상 경로 불변).
	after, _ := agent.Read(ctx)
	if !after.LeaseExpiresAt.Equal(before) {
		t.Fatalf("NULL renew가 lease 만료를 바꿨다: %v → %v (불변 기대)", before, after.LeaseExpiresAt)
	}
	if after.HolderKind != HolderAgent {
		t.Fatalf("NULL renew 후 holder = %v, AGENT 불변 기대", after.HolderKind)
	}
}

// TestLockConcurrentAcquire는 N개 goroutine이 동시에 빈 락을 획득하면 정확히 하나만 성공함을
// 실 MySQL로 검증한다(CD-3 원자 획득). 세션변수(@tok/@ok) 오염 회귀도 함께 밟는다: 여러
// 커넥션을 강제(MaxOpenConns)해 풀 재사용 하에서도 승자 token이 락 행과 일치하는지 본다
// — callProc가 CALL과 SELECT를 하나의 고정 커넥션에서 돌리므로 오염이 없어야 한다.
func TestLockConcurrentAcquire(t *testing.T) {
	host, port := startMySQL(t)
	st := openStore(t, host, port, "deploy_agent")
	st.db.SetMaxOpenConns(8) // 풀 재사용·세션변수 오염 회귀를 유도한다
	ctx := context.Background()

	const N = 24
	var (
		wg        sync.WaitGroup
		start     = make(chan struct{})
		winners   int64
		winnerTok int64
	)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // 모두를 같은 순간에 풀어 실제 경합을 만든다
			tok, ok, err := st.Acquire(ctx, HolderAgent, fmt.Sprintf("deploy-%d", i), 60*time.Second)
			if err != nil {
				t.Errorf("goroutine %d Acquire 오류: %v", i, err)
				return
			}
			if ok {
				atomic.AddInt64(&winners, 1)
				atomic.StoreInt64(&winnerTok, int64(tok))
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Fatalf("동시 Acquire 승자 = %d, 정확히 1 기대(CD-3 원자 획득)", winners)
	}
	// 승자 token이 실제 락 행에 반영됐는지 교차 확인(세션변수 오염이었다면 어긋난다).
	ls, err := st.Read(ctx)
	if err != nil {
		t.Fatalf("Read 실패: %v", err)
	}
	if int64(ls.FencingToken) != atomic.LoadInt64(&winnerTok) {
		t.Fatalf("승자 token %d ≠ 락 행 token %d (세션변수 오염 의심)", atomic.LoadInt64(&winnerTok), ls.FencingToken)
	}
	if ls.HolderKind != HolderAgent {
		t.Fatalf("동시 획득 후 holder = %v, AGENT 기대", ls.HolderKind)
	}
	// 정리.
	if _, err := st.Release(ctx, HolderAgent, ls.HolderID, ls.FencingToken); err != nil {
		t.Fatalf("정리 Release 오류: %v", err)
	}
}

// TestHistoryAppendReadContract는 배포 이력 append·최신 조회를 실제 MySQL에 대해
// 검증한다(DO-16 상태 기록·조회). 인메모리 페이크가 확인할 수 없는 것들을 우선 밟는다 —
// 이력 부재 시 빈 이벤트(오류 아님), 최신 행 선택(event_at·id DESC), NULL 허용 칸의 빈 값
// 접기(특히 target ENUM에 빈 문자열이 들어가지 않는지).
func TestHistoryAppendReadContract(t *testing.T) {
	host, port := startMySQL(t)
	st := openStore(t, host, port, "deploy_agent")
	ctx := context.Background()

	// ⑴ 이력이 없으면 빈 이벤트 + nil(재개 대상 기본값). 조용한 오류가 아니다.
	ev, err := st.ReadLatest(ctx, "req-h")
	if err != nil {
		t.Fatalf("이력 부재 ReadLatest 오류: %v", err)
	}
	if ev.EventType != "" {
		t.Fatalf("이력 부재인데 이벤트 반환: %+v", ev)
	}

	// ⑵ 예약 후 dispatch 상태를 append한다. target 등 일부 칸은 비워(NULL로 접힘) 넣는다.
	if err := st.AppendEvent(ctx, HistoryEvent{RequestID: "req-h", EventType: "RESERVED", ManifestDigest: "sha256:x"}); err != nil {
		t.Fatalf("RESERVED append 실패(빈 target NULL 접기 확인): %v", err)
	}
	if err := st.AppendEvent(ctx, HistoryEvent{
		RequestID: "req-h", EventType: "STEP_RESULT", Target: "core", CommitSHA: "c1",
		ManifestDigest: "sha256:x", Step: "dispatch", Result: "UNEXECUTED", FencingToken: 7,
	}); err != nil {
		t.Fatalf("STEP_RESULT append 실패: %v", err)
	}

	// ⑶ ReadLatest는 최신 행(STEP_RESULT)을 준다 — 최신 상태 선택.
	got, err := st.ReadLatest(ctx, "req-h")
	if err != nil {
		t.Fatalf("ReadLatest 오류: %v", err)
	}
	if got.EventType != "STEP_RESULT" || got.Result != "UNEXECUTED" || got.Target != "core" || got.FencingToken != 7 {
		t.Fatalf("최신 이력 = %+v, STEP_RESULT·UNEXECUTED·core·token 7 기대", got)
	}

	// ⑷ 대상 격리: 다른 requestId는 이 이력에 영향받지 않는다.
	if other, _ := st.ReadLatest(ctx, "req-other"); other.EventType != "" {
		t.Fatalf("무관 requestId 이력 = %+v, 빈 이벤트 기대", other)
	}
}

// TestHistoryAppendOnlyEnforced는 deploy_agent 계정에게 이력 행의 UPDATE/DELETE가 grant
// 수준에서 거부됨을 확인한다(DT-12 — "배포 이력이 곧 사실"을 writer가 되돌릴 수 없다).
func TestHistoryAppendOnlyEnforced(t *testing.T) {
	host, port := startMySQL(t)
	agentDSN := fmt.Sprintf("deploy_agent:%s@tcp(%s:%s)/deploy", agentPassword, host, port)
	db := openDB(t, agentDSN)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		"INSERT INTO `deploy_history` (`request_id`, `event_type`) VALUES (?, ?)",
		"req-append", "RESERVED"); err != nil {
		t.Fatalf("deploy_agent 이력 INSERT가 거부됐다(허용되어야 한다): %v", err)
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE `deploy_history` SET `event_type` = ? WHERE `request_id` = ?", "TAMPERED", "req-append"); err == nil {
		t.Error("deploy_agent 이력 UPDATE가 성공했다 (append-only 위반 — 거부 기대)")
	}
	if _, err := db.ExecContext(ctx,
		"DELETE FROM `deploy_history` WHERE `request_id` = ?", "req-append"); err == nil {
		t.Error("deploy_agent 이력 DELETE가 성공했다 (append-only 위반 — 거부 기대)")
	}
}

// TestHandshake는 ADR-024 §2.4 "정지 후 인계" 긴급 롤백 인계를 다룬다(다음 단계).
func TestHandshake(t *testing.T) {
	t.Skip("integration scaffold: 핸드셰이크 전이(preempt·ack·override·debt)는 S3에서 연결한다")
}
