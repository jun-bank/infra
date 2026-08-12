// Package store는 배포 스키마에 대한 유일한 관문이다(ADR-022 DT-9..DT-12).
// DB 권한 모델의 코드 측 절반이다: 배포 스키마는 락 행에 대한 raw DML을 허용하지
// 않고 나머지는 append-only이며, 이 패키지는 일반 exec/query 메서드를 전혀 노출하지
// 않음으로써 그것을 그대로 반영한다. 이 패키지를 통해 락을 변경하는 유일한 방법은
// 일곱 개의 명명된 전이 중 하나(각각 CALL sp_lock_*를 발행)이고, ledger·mode·history를
// 쓰는 유일한 방법은 Append/Reserve(각각 하나의 INSERT를 발행)뿐이다. 따라서 raw
// DML은 grant에서 금지된 것과 마찬가지로 코드에서도 도달 불가능하다(DT-12) — 동일한
// 규칙을 두 계층에서 강제한다.
//
// 구현 상태: 재생 방어 원장 Reserve(DO-10), mode 조회·append(DO-17), 정상 경로 락 —
// Acquire·Renew·Release·Read(CD-3), 배포 이력 AppendEvent·ReadLatest(DO-16 상태 기록·조회)
// 가 실제 *sql.DB 위에 구현돼 있다. 핸드셰이크 전이(RecordPreempt·AckSafetyBoundary·
// OverrideAcquire·ResolveOpenDebt — ADR-024 §2.4 긴급 롤백 인계)는 S3라 아직
// ErrNotImplemented를 반환한다. 실 MySQL에 대해 프로시저·grant 계약을 증명하는 것은
// Testcontainers 통합 스위트다(store_integration_test.go 참조).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-sql-driver/mysql"
)

// ErrNotImplemented는 스캐폴드 표면을 표시한다.
var ErrNotImplemented = errors.New("store: not implemented (scaffold)")

// ErrReplay는 요청이 이미 예약된 경우 — 즉 재생 — Reserve가 반환한다. 두 형태다:
// 동일 requestId + 동일 body digest(같은 요청의 재전송), 또는 재사용된 OIDC jti
// (토큰 재사용). 어느 쪽이든 재실행하지 않고 그 요청의 현재 상태를 반환해야 한다
// (ADR-027 DO-10 ⑷ 앞가지). ledger의 UNIQUE 제약이 INSERT 시점에 재생을 거부하므로,
// 이 방어는 writer의 선의에 의존하지 않는다.
var ErrReplay = errors.New("store: request already reserved (replay)")

// ErrDigestConflict는 동일 requestId가 다른 body digest로 다시 온 경우 Reserve가
// 반환한다(ADR-027 DO-10 ⑷ 뒷가지 — "동일 requestId + 다른 digest = 거절·기록").
// 재생과 달리 이것은 현재 상태 반환이 아니라 거절·기록해야 하는 충돌이다: 같은 멱등
// 키로 다른 내용을 배포하려는 시도이기 때문이다.
var ErrDigestConflict = errors.New("store: same requestId reused with a different body digest")

// ErrNoMode는 대상에 아직 mode 행이 하나도 없을 때 Current가 반환한다. store는
// 기본값을 지어내지 않는다(ModeStore 주석) — "행이 없다"를 조용한 dev로 뭉개지 않고
// 명시적 오류로 올려, 호출자가 fail-closed로 operational로 닫게 한다(ADR-027 DO-17 ⑷).
var ErrNoMode = errors.New("store: no mode row for target (fail-closed decision belongs to caller)")

// mysqlErrDupEntry는 MySQL의 중복 키 오류 코드다(ER_DUP_ENTRY). requestId(PK) 또는
// jti(UNIQUE) 충돌이 이 코드로 온다.
const mysqlErrDupEntry = 1062

// MinLease는 강제되는 최소 lease다(S2-1 결함2 — fail-closed). sub-second/0/음수 lease는
// ok=true인 무보호 락으로 만들어져 Confirm 직후 탈취되는 footgun을 연다 — 그래서 1초
// 미만은 Go 경계와 프로시저 양쪽에서 거절한다(계층 이중 강제).
const MinLease = time.Second

// ErrLeaseTooShort는 lease가 MinLease 미만일 때(0·음수 포함) Acquire/Renew가 반환한다.
// 조용한 절삭(int(lease.Seconds())가 sub-second를 0으로)이 아니라 명시적 오류로 올린다.
var ErrLeaseTooShort = errors.New("store: lease must be at least 1s (fail-closed — no sub-second/zero/negative lease)")

// ErrInvalidHolderKind는 kind가 AGENT·BATCH_CUTOFF가 아닐 때 락 전이 메서드가 반환한다
// (S2-1 결함3 — 유령 락 방지). 역할별 wrapper 프로시저로의 디스패치가 여기서 갈린다.
var ErrInvalidHolderKind = errors.New("store: holder kind must be AGENT or BATCH_CUTOFF")

// HolderKind는 배포 윈도우 락을 누가 보유하는지 식별한다. agent와 batch/cutoff
// 스케줄러가 동일한 단일 행을 두고 경합한다(CD-3).
type HolderKind string

const (
	HolderNone        HolderKind = "NONE"
	HolderAgent       HolderKind = "AGENT"
	HolderBatchCutoff HolderKind = "BATCH_CUTOFF"
)

// FencingToken은 엄격히 단조 증가하는 락 토큰이다(DT-12): 모든 (override-)acquire마다
// 증가하며 절대 리셋되지 않으므로, 낡은 holder는 다음 재확인 시 토큰 불일치로
// 감지된다(ADR-024 §2.4).
type FencingToken uint64

// LockState는 단일 락 행의 읽기 스냅샷이다(SELECT — 두 계정이 락 테이블에 대해
// 부여받은 유일한 읽기).
type LockState struct {
	HolderKind       HolderKind
	HolderID         string
	FencingToken     FencingToken
	LeaseExpiresAt   time.Time
	PreemptRequested bool
	SafetyAck        bool
	OpenDebt         bool // 「열림」 미적재 채무 (ADR-024 §2.4)
}

// LockStore는 배포 윈도우 락에 대한 관문이다. 정확히 일곱 개의 전이와 하나의 읽기만
// 노출하며 — 의도적으로 그 밖의 것은 전혀 노출하지 않는다. 각 변경 메서드는 저장
// 프로시저와 1:1로 대응하고(CALL sp_lock_*), 임의의 SQL을 받는 메서드는 없으므로,
// 호출자는 락 행에 raw UPDATE를 발행할 수 없다.
//
// 어느 호출자가 어느 전이를 호출할 수 있는지도 DB grant 수준에서 강제된다
// (03_grants.sql); 여기 주석은 두 계층을 함께 읽을 수 있도록 의도된 호출자를 명시한다.
type LockStore interface {
	// Acquire — sp_lock_acquire_{agent,cutoff} (전이 1; 두 호출자, kind별 역할 wrapper로
	// 디스패치 — S2-1). 락이 비어 있거나 lease가 만료된 경우 성공하며; 새 토큰을 반환하고,
	// 경합 시 ok=false를 반환한다. lease < 1초·미지 kind는 오류로 거절한다.
	Acquire(ctx context.Context, kind HolderKind, holderID string, lease time.Duration) (token FencingToken, ok bool, err error)

	// Renew — sp_lock_renew_{agent,cutoff} (전이 2; 두 호출자, kind별 역할 wrapper). 호출자가
	// 여전히 holder이고 (kind+id+token) lease가 살아 있는 동안에만 lease를 연장한다(줄이지
	// 못한다). lease < 1초는 오류로 거절한다(S2-1).
	Renew(ctx context.Context, kind HolderKind, holderID string, token FencingToken, lease time.Duration) (ok bool, err error)

	// RecordPreempt — sp_lock_record_preempt (전이 3; DEPLOY-AGENT 전용).
	// 행을 표시한다; holder는 그대로 남고 롤백은 아직 시작되지 않는다(§2.4 ⑶).
	RecordPreempt(ctx context.Context, requester, requestID string, deadline time.Time) (ok bool, err error)

	// AckSafetyBoundary — sp_lock_ack_safety_boundary (전이 4; CUTOFF 전용).
	// 선점된 스케줄러가 BR-52 단계 경계에서 멈췄음을 기록한다.
	AckSafetyBoundary(ctx context.Context, holderID string, token FencingToken) (ok bool, err error)

	// OverrideAcquire — sp_lock_override_acquire (전이 5; DEPLOY-AGENT 전용).
	// 긴급 롤백 인계: preempt가 있고 ack 또는 lease 만료가 있은 뒤에만 성공하며;
	// lease 만료 분기에서는 open-debt를 설정한다(§2.4 ⑶⑷).
	OverrideAcquire(ctx context.Context, holderID string, lease time.Duration) (token FencingToken, ok bool, err error)

	// ResolveOpenDebt — sp_lock_resolve_open_debt (전이 6; CUTOFF 전용).
	ResolveOpenDebt(ctx context.Context) (ok bool, err error)

	// Release — sp_lock_release_{agent,cutoff} (전이 7; 두 호출자, kind별 역할 wrapper —
	// 상대 계정이 남의 락을 해제할 수 없다 · S2-1). 호출자가 현재 holder인 경우에만
	// 해제한다; 토큰은 리셋되지 않고 채무도 지워지지 않는다.
	Release(ctx context.Context, kind HolderKind, holderID string, token FencingToken) (ok bool, err error)

	// Read는 락 행의 스냅샷을 반환한다(SELECT).
	Read(ctx context.Context) (LockState, error)
}

// LedgerStore는 어떤 부작용이 있기 전에 requestId/jti를 예약한다(ADR-027 DO-10 ⑶).
// Reserve(INSERT)만 노출한다 — append-only이며, 삭제 메서드가 없으므로 재생 방어를
// writer가 되돌릴 수 없다.
type LedgerStore interface {
	// Reserve는 부작용 전에 requestId(와 OIDC jti)를 하나의 INSERT로 선점한다
	// (DO-10 ⑶). 세 갈래로 갈린다(DO-10 ⑷):
	//   - 신규          → nil (진행)
	//   - 동일 id·동일 digest, 또는 jti 재사용 → ErrReplay (재실행 금지, 현재 상태 반환)
	//   - 동일 id·다른 digest → ErrDigestConflict (거절·기록)
	// 판정은 UNIQUE 제약에 의해 INSERT 시점에 서며, writer의 선의에 의존하지 않는다.
	Reserve(ctx context.Context, requestID, jti, bodyDigest string) error
}

// ModeStore는 대상별 mode를 읽고 append한다(ADR-027 DO-17 ⑵). 토글은 단조 증가하는
// 버전을 가진 INSERT이며 절대 덮어쓰기가 아니다; 최신 행이 현재 mode다. fail-closed
// 기본값은 operational이다(DO-17 ⑷) — 그 판정은 읽었을 때 행이 없을 경우 호출자의
// 몫이며, 이 store는 기본값을 지어내지 않는다.
type ModeStore interface {
	// Current는 대상의 최신 mode와 버전을 반환한다(SELECT).
	Current(ctx context.Context, target string) (mode string, version uint64, err error)
	// AppendMode는 새 mode 행을 append한다 — version은 호출자가 정하지 않는다.
	// 「현재 max + 1」을 원자적으로 계산·삽입하는 sp_mode_append를 경유하므로, append된
	// 행은 항상 최신(= Current)이 되어 단조 version이 강제된다(DO-17 ⑵). 임의 version
	// 삽입 경로는 없다 — 더 작은 version이 들어가 토글이 Current에 반영되지 않는 fail-open을
	// 원천 차단한다. actor는 인증된 subject에서 파생되며, 절대 자기 보고가 아니다(DO-12 ⑶).
	AppendMode(ctx context.Context, target, mode, actor string) error
}

// detailJSON은 자유 형식 detail 문자열을 JSON 컬럼(deploy_history.detail JSON)에 넣을 수 있는
// 유효한 JSON 값으로 인코딩한다. 평문을 그대로 바인딩하면 MySQL이 "Invalid JSON text"로 INSERT
// 전체를 거부해, 하필 UNKNOWN 이력이 통째로 유실되고(durable 근거 소실) 재전송이 재실행될 수
// 있다(리뷰 P1 · .9 CAST 실측). 문자열을 JSON 문자열 값으로 감싼다 — json.Marshal(string)은
// 실패하지 않으므로 항상 유효 JSON이며, 만에 하나 실패해도 NULL로 두어 INSERT 자체는 살린다.
//
// ⚠️ 비 UTF-8 바이트(실행기 stdout/stderr 원시 바이트가 섞일 수 있다 — 드묾)는 json.Marshal이
// U+FFFD로 치환한다(오류가 아니라 치환 — INSERT는 여전히 성공). detail은 바이트 정밀 기록이
// 아니라 사람이 읽는 진단 단서이므로 이 손실은 수용한다(리뷰 P3): INSERT 안전(P1의 핵심)을
// 지키는 것이 우선이고, docker/compose 출력은 사실상 UTF-8이다. 바이트 무손실이 필요해지면
// base64 등 가역 표현으로 바꾼다(현재는 불필요 — 오버킬).
func detailJSON(s string) any {
	b, err := json.Marshal(s)
	if err != nil {
		return nil
	}
	return string(b)
}

// codedDetailJSON은 기계 판독 코드가 있는 이력 행의 detail을 만든다: `{"code":…,"detail":…}`
// 형태의 JSON 객체다. 코드를 **detail(JSON 컬럼) 안에** 넣는 것은 스키마 ALTER 없이
// 구조화된 질의를 얻기 위해서다 — MySQL은 JSON 컬럼을 `detail->>'$.code'`로 조회·인덱싱할
// 수 있으므로, 컬럼 추가 없이도 코드별 집계가 문자열 LIKE에 기대지 않는다.
//
// detail이 비어 있으면 code만 담는다(빈 문자열 키를 남기지 않는다). 인코딩 실패 시 NULL이
// 아니라 코드만이라도 남기는 최소 표현으로 물러난다 — 진단의 핵심은 코드이기 때문이다.
func codedDetailJSON(code, detail string) any {
	payload := map[string]string{"code": code}
	if detail != "" {
		payload["detail"] = detail
	}
	b, err := json.Marshal(payload)
	if err != nil {
		// map[string]string는 실패하지 않지만, 실패하더라도 INSERT를 깨지 않는다(P1).
		return detailJSON(code)
	}
	return string(b)
}

// HistoryEvent는 배포 이력에 대한 하나의 append다.
type HistoryEvent struct {
	RequestID      string
	EventType      string // RESERVED / PROGRESS / STEP_RESULT / COMPLETED / REJECTED / ...
	Target         string
	CommitSHA      string
	ManifestDigest string
	Step           string
	Result         string // 예: UNEXECUTED / DONE / UNKNOWN (ADR-027 DO-16)
	RejectReason   string // RL-8: 기록된 거부 사유(사람이 읽는 문장)
	// ReasonCode는 거절 사유의 **기계 판독 코드**다(예: TARGET_FORBIDDEN). RejectReason은
	// 사람을 위한 문장이라 문면이 바뀌면 집계·알림이 조용히 깨진다 — 운영 대응이 갈리는
	// 사유에는 코드를 함께 남겨, 이력 질의가 문자열 매칭에 기대지 않게 한다.
	// 코드 어휘의 정본은 그것을 내는 층이다(auth: 게이트 2 · httpentry: 결박).
	ReasonCode   string
	Detail       string // dispatch 오류 등 진단 단서 — 특히 UNKNOWN은 사람 개입의 근거가 된다(무음 금지)
	FencingToken FencingToken
}

// HistoryStore는 배포 이력에 append한다(DT-9 ⑵). Append(INSERT)와 읽기만 노출한다
// — Update/Delete 메서드는 존재하지 않으며, append-only grant를 그대로 반영해
// "배포 이력이 곧 사실"을 writer가 다시 쓸 수 없도록 한다.
type HistoryStore interface {
	// AppendEvent는 하나의 이력 행을 INSERT한다(INSERT 전용).
	AppendEvent(ctx context.Context, ev HistoryEvent) error
	// ReadLatest는 requestId에 대한 가장 최근 이벤트를 반환한다(SELECT).
	ReadLatest(ctx context.Context, requestID string) (HistoryEvent, error)
}

// --- 스캐폴드 스텁 ---------------------------------------------------------

// SQLStore는 네 개 store 모두의 SQL 기반 구현이다. *sql.DB(배포 스키마 전용, LAN 전용
// — ADR-022 DT-10)를 보유한다. 구현된 것은 재생 방어 원장 Reserve(DO-10), mode
// 조회·append(DO-17), 정상 경로 락 Acquire·Renew·Release·Read(CD-3), 배포 이력
// AppendEvent·ReadLatest(DO-16)다. 핸드셰이크 전이(preempt·ack·override·debt —
// ADR-024 §2.4, S3)만 아직 ErrNotImplemented를 반환한다.
type SQLStore struct {
	db *sql.DB
}

// New는 열린 *sql.DB를 감싸 SQLStore를 만든다. DB 연결의 생애주기(열기·풀 설정·닫기)는
// 호출자가 소유한다 — 이 store는 자격증명을 파싱하지 않고 이미 열린 핸들만 받는다
// (DEPLOY_DB_DSN에 대해 배포 스키마 전용으로 열린다; DT-10).
func New(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

// SQLStore가 모든 store 인터페이스를 만족한다는 컴파일 타임 단언.
var (
	_ LockStore    = (*SQLStore)(nil)
	_ LedgerStore  = (*SQLStore)(nil)
	_ ModeStore    = (*SQLStore)(nil)
	_ HistoryStore = (*SQLStore)(nil)
)

// callProc는 OUT 플래그(와 선택적 토큰)를 세션 변수로 돌려주는 락 전이 프로시저를
// 실행한다. MySQL은 OUT 파라미터를 플레이스홀더로 바인딩하지 않는다 — CALL 텍스트 안에서
// 세션 변수(@…)로 지정하고, 그 세션 변수를 같은 커넥션에서 다시 SELECT해 읽어야 한다.
// 그래서 IN 인자만 ?이고 OUT은 리터럴 @var이며, 두 문장(CALL·SELECT)은 반드시 하나의
// 고정된 커넥션에서 돌아야 한다(세션 변수는 커넥션 로컬이다). 매 호출은 자기 CALL이
// @var를 먼저 덮어쓰므로 풀에서 재사용된 커넥션의 이전 값에 오염되지 않는다.
// ValidateLease는 lease가 최소 1초 이상인지 확인한다(S2-1 결함2 — fail-closed). 락을 잡는
// 오케스트레이션 경계(lock.go)와 store 진입 양쪽에서 같은 규칙을 부르도록 export한다.
func ValidateLease(lease time.Duration) error {
	if lease < MinLease {
		return ErrLeaseTooShort
	}
	return nil
}

// roleSuffix는 holder kind를 역할별 wrapper 프로시저 접미사로 사상한다(S2-1). 이 접미사로
// 각 계정은 자기 kind가 결박된 wrapper만 호출하게 되고, 상대 kind로는 호출 경로 자체가
// 없다(DB grant가 그것을 강제). 미지 kind는 유령 락을 막기 위해 여기서 거절한다(결함3).
func roleSuffix(kind HolderKind) (string, error) {
	switch kind {
	case HolderAgent:
		return "_agent", nil
	case HolderBatchCutoff:
		return "_cutoff", nil
	default:
		return "", ErrInvalidHolderKind
	}
}

// leaseSeconds는 lease를 정수 초로 변환한다. 조용한 sub-second 절삭이 아니라, 호출부가
// ValidateLease로 1초 하한을 먼저 강제한 뒤에만 이 변환에 도달한다(그래서 최소 1이 보장된다).
func leaseSeconds(lease time.Duration) int { return int(lease / time.Second) }

func (s *SQLStore) callProc(ctx context.Context, callSQL string, args []any, selectSQL string, dest ...any) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, callSQL, args...); err != nil {
		return err
	}
	return conn.QueryRowContext(ctx, selectSQL).Scan(dest...)
}

// Acquire는 kind별 역할 wrapper sp_lock_acquire_{agent,cutoff}를 호출한다(전이 1 — S2-1). 락이 비어 있거나 lease가
// 만료된 경우에만 성공한다: stale 회수도 여기서 일어난다(CD-3) — 비정상 종료로 만료된
// 직전 점유는 이 획득이 회수하며, 호출자는 새 토큰을 받는 것 외에 특별히 할 일이 없다.
// 성공하면 새 fencing 토큰(프로시저가 단조 증가시킨다)과 ok=true를, 경합(다른 배포·배치가
// 유효 lease로 점유 중)이면 ok=false를 반환한다 — 경합은 오류가 아니라 거절이다(RL-4).
// 연결·권한 오류만 err로 올린다. lease 정밀도는 프로시저 계약상 정수 초이며, 1초 미만은
// ErrLeaseTooShort로 거절한다(S2-1 결함2). kind에 따라 역할별 wrapper로 디스패치하므로,
// 각 계정은 자기 kind가 결박된 프로시저만 호출한다(결함1) — 미지 kind는 ErrInvalidHolderKind.
func (s *SQLStore) Acquire(ctx context.Context, kind HolderKind, holderID string, lease time.Duration) (FencingToken, bool, error) {
	if err := ValidateLease(lease); err != nil {
		return 0, false, err
	}
	suffix, err := roleSuffix(kind)
	if err != nil {
		return 0, false, err
	}
	var (
		tok sql.NullInt64
		ok  int64
	)
	err = s.callProc(ctx,
		"CALL `sp_lock_acquire"+suffix+"`(?, ?, @tok, @ok)",
		[]any{holderID, leaseSeconds(lease)},
		"SELECT @tok, @ok", &tok, &ok)
	if err != nil {
		return 0, false, err
	}
	if ok != 1 {
		return 0, false, nil
	}
	return FencingToken(tok.Int64), true, nil
}

// Renew는 kind별 역할 wrapper sp_lock_renew_{agent,cutoff}를 호출한다(전이 2 — S2-1). 호출자가 여전히 holder이고
// (kind+id+token) lease가 살아 있는 동안에만 lease를 연장한다. 이것이 곧 불가역 단계
// 직전의 「보유 재확인(fencing)」 프리미티브다(CD-3): 내 fencing 토큰이 그 행에 그대로일
// 때만 참을, 만료·인계로 토큰이 어긋났으면 거짓을 반환한다 — 호출자는 거짓이면 그 단계를
// 시작하지 않는다(좀비 차단). 연결·권한 오류만 err로 올린다. 1초 미만 lease는
// ErrLeaseTooShort로 거절하고(S2-1 결함2 — Renew(...,0)로 살아있는 lease를 줄이는 것 금지),
// kind에 따라 역할별 wrapper로 디스패치한다(결함1).
func (s *SQLStore) Renew(ctx context.Context, kind HolderKind, holderID string, token FencingToken, lease time.Duration) (bool, error) {
	if err := ValidateLease(lease); err != nil {
		return false, err
	}
	suffix, err := roleSuffix(kind)
	if err != nil {
		return false, err
	}
	var ok int64
	err = s.callProc(ctx,
		"CALL `sp_lock_renew"+suffix+"`(?, ?, ?, @ok)",
		[]any{holderID, uint64(token), leaseSeconds(lease)},
		"SELECT @ok", &ok)
	if err != nil {
		return false, err
	}
	return ok == 1, nil
}

// --- 핸드셰이크 전이(ADR-024 §2.4 긴급 롤백 인계) — S3 -----------------------
// RecordPreempt·AckSafetyBoundary·OverrideAcquire·ResolveOpenDebt는 override
// 핸드셰이크(정지 후 인계)의 조각이며 이번 범위(#13 정상 경로 락) 밖이다. 인터페이스는
// 지금 확정하고 구현은 S3에서 각자의 핸드셰이크 테스트와 함께 채운다.

func (*SQLStore) RecordPreempt(context.Context, string, string, time.Time) (bool, error) {
	return false, ErrNotImplemented
}

func (*SQLStore) AckSafetyBoundary(context.Context, string, FencingToken) (bool, error) {
	return false, ErrNotImplemented
}

func (*SQLStore) OverrideAcquire(context.Context, string, time.Duration) (FencingToken, bool, error) {
	return 0, false, ErrNotImplemented
}

func (*SQLStore) ResolveOpenDebt(context.Context) (bool, error) {
	return false, ErrNotImplemented
}

// Release는 kind별 역할 wrapper sp_lock_release_{agent,cutoff}를 호출한다(전이 7 — S2-1). 호출자가 현재
// holder(kind+id+token)인 경우에만 해제하며; 토큰은 리셋되지 않고 open_debt도 지워지지
// 않는다. 거짓 반환은 이미 보유하지 않음(만료 회수됨·인계됨)을 뜻한다 — 해제 실패는
// 치명적이지 않다: lease 만료가 어차피 그 행을 회수한다(CD-3). 연결·권한 오류만 err로 올린다.
// kind에 따라 역할별 wrapper로 디스패치하므로, 상대 계정이 락 행 SELECT로 읽은 token으로
// 남의 락을 해제하려 해도 호출할 수 있는 프로시저가 없다(S2-1 결함1) — 미지 kind는
// ErrInvalidHolderKind.
func (s *SQLStore) Release(ctx context.Context, kind HolderKind, holderID string, token FencingToken) (bool, error) {
	suffix, err := roleSuffix(kind)
	if err != nil {
		return false, err
	}
	var ok int64
	err = s.callProc(ctx,
		"CALL `sp_lock_release"+suffix+"`(?, ?, @ok)",
		[]any{holderID, uint64(token)},
		"SELECT @ok", &ok)
	if err != nil {
		return false, err
	}
	return ok == 1, nil
}

// Read는 락 행의 스냅샷을 반환한다(SELECT — 두 계정이 락 테이블에 대해 부여받은 유일한
// 읽기). stale 판정의 관측 프리미티브다: LeaseExpiresAt가 과거이면 점유가 만료된 것이며
// 다음 Acquire가 그것을 회수한다. 락 행은 항상 존재하므로(단일 행 시드) 정상 경로에서
// sql.ErrNoRows는 나지 않는다.
func (s *SQLStore) Read(ctx context.Context) (LockState, error) {
	var (
		ls        LockState
		kind      string
		holderID  sql.NullString
		token     uint64
		lease     sql.NullTime
		preempt   bool
		safetyAck bool
		openDebt  bool
	)
	err := s.db.QueryRowContext(ctx,
		"SELECT `holder_kind`, `holder_id`, `fencing_token`, `lease_expires_at`, "+
			"`preempt_requested`, `safety_ack`, `open_debt` "+
			"FROM `deploy_window_lock` WHERE `lock_id` = 1").
		Scan(&kind, &holderID, &token, &lease, &preempt, &safetyAck, &openDebt)
	if err != nil {
		return LockState{}, err
	}
	ls.HolderKind = HolderKind(kind)
	ls.HolderID = holderID.String
	ls.FencingToken = FencingToken(token)
	ls.LeaseExpiresAt = lease.Time
	ls.PreemptRequested = preempt
	ls.SafetyAck = safetyAck
	ls.OpenDebt = openDebt
	return ls, nil
}

// Reserve는 append-only 원장에 예약 행 하나를 INSERT한다(DO-10 ⑶). grant는 이
// 테이블에 SELECT+INSERT만 주므로(03_grants — UPDATE/DELETE 없음) 재생 방어를 writer가
// 되돌릴 수 없다. jti가 비면 NULL로 넣는다 — UNIQUE 제약은 NULL을 충돌로 보지 않으므로
// (OIDC 이전 단계에서) 여러 요청이 jti 없이 공존할 수 있다.
func (s *SQLStore) Reserve(ctx context.Context, requestID, jti, bodyDigest string) error {
	var jtiArg any
	if jti != "" {
		jtiArg = jti
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO `deploy_request_ledger` (`request_id`, `jti`, `body_digest`) VALUES (?, ?, ?)",
		requestID, jtiArg, bodyDigest)
	if err == nil {
		return nil // 신규 예약
	}

	// 중복 키가 아니면 그대로 올린다(연결·권한 오류 등 — 조용히 삼키지 않는다).
	var myErr *mysql.MySQLError
	if !errors.As(err, &myErr) || myErr.Number != mysqlErrDupEntry {
		return err
	}

	// 중복 키 = requestId(PK) 또는 jti(UNIQUE) 충돌. 저장된 digest와 대조해 3분기한다.
	var storedDigest string
	qErr := s.db.QueryRowContext(ctx,
		"SELECT `body_digest` FROM `deploy_request_ledger` WHERE `request_id` = ?",
		requestID).Scan(&storedDigest)
	switch {
	case errors.Is(qErr, sql.ErrNoRows):
		// requestId는 신규인데 INSERT가 중복으로 실패했다 = jti 재사용(토큰 재전송).
		return ErrReplay
	case qErr != nil:
		return qErr
	case storedDigest == bodyDigest:
		// 동일 requestId + 동일 digest = 같은 요청의 재전송 → 재실행 금지.
		return ErrReplay
	default:
		// 동일 requestId + 다른 digest = 거절·기록해야 하는 충돌.
		return ErrDigestConflict
	}
}

// Current는 대상의 현재 mode와 mode version을 읽는다(SELECT — ADR-027 DO-17 ⑵).
// deploy_mode는 append-only이므로 "현재"는 대상별 mode_version이 가장 큰 행이다
// (토글은 덮어쓰기가 아니라 새 행 — DT-12 ⑵). 대상에 행이 하나도 없으면 ErrNoMode를
// 올린다 — store는 기본값을 지어내지 않고, fail-closed(operational) 판정은 호출자 몫이다.
func (s *SQLStore) Current(ctx context.Context, target string) (string, uint64, error) {
	var (
		mode    string
		version uint64
	)
	err := s.db.QueryRowContext(ctx,
		"SELECT `mode`, `mode_version` FROM `deploy_mode` WHERE `target` = ? ORDER BY `mode_version` DESC LIMIT 1",
		target).Scan(&mode, &version)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", 0, ErrNoMode
	case err != nil:
		// 연결·권한 오류 등은 그대로 올린다 — 조용히 삼켜 dev로 열지 않는다(fail-closed는
		// 호출자가 이 오류를 보고 operational로 닫는다).
		return "", 0, err
	default:
		return mode, version, nil
	}
}

// AppendMode는 새 mode 행 하나를 append한다(append-only 토글 원장 — DT-12 ⑵). version은
// 호출자가 정하지 않는다: sp_mode_append가 대상별 「현재 max + 1」을 원자적으로 계산해
// INSERT하므로, append된 행은 항상 최신(= Current)이 되어 단조 version이 강제된다
// (DO-17 ⑵). 임의 version을 넘길 자리가 없으니, 더 작은 version이 들어가 토글이 Current에
// 반영되지 않는 fail-open이 원천 차단된다. 동시 두 호출이 같은 max를 노려도 UNIQUE(target,
// mode_version)가 한쪽을 거부한다 — 단조성은 프로시저 계산과 DB 제약 두 계층에서 강제된다.
// actor는 인증된 subject에서 파생되며 절대 자기 보고가 아니다(DO-12 ⑶).
func (s *SQLStore) AppendMode(ctx context.Context, target, mode, actor string) error {
	_, err := s.db.ExecContext(ctx, "CALL `sp_mode_append`(?, ?, ?)", target, mode, actor)
	return err
}

// AppendEvent는 배포 이력 행 하나를 INSERT한다(append-only — DT-9 ⑵ · DT-12 ⑵). grant는
// 이 테이블에 SELECT+INSERT만 주므로(03_grants) 이력을 writer가 다시 쓸 수 없다. NULL 허용
// 칸(target·commit·digest·step·result·reject_reason·fencing_token)은 빈 값이면 NULL로 넣는다
// — 특히 target은 ENUM이라 빈 문자열이 들어가면 삽입이 실패하므로, 빈 값을 NULL로 접는 것이
// 조용한 실패가 아니라 스키마 계약(NULL 허용)에 맞춘 정합이다.
func (s *SQLStore) AppendEvent(ctx context.Context, ev HistoryEvent) error {
	var target, commit, digest, step, result, reason, detail, token any
	if ev.Target != "" {
		target = ev.Target
	}
	if ev.CommitSHA != "" {
		commit = ev.CommitSHA
	}
	if ev.ManifestDigest != "" {
		digest = ev.ManifestDigest
	}
	if ev.Step != "" {
		step = ev.Step
	}
	if ev.Result != "" {
		result = ev.Result
	}
	if ev.RejectReason != "" {
		reason = ev.RejectReason
	}
	switch {
	case ev.ReasonCode != "":
		// 코드가 있으면 detail을 구조화한다(스키마 ALTER 없이 코드별 질의 — codedDetailJSON).
		detail = codedDetailJSON(ev.ReasonCode, ev.Detail)
	case ev.Detail != "":
		detail = detailJSON(ev.Detail)
	}
	if ev.FencingToken != 0 {
		token = uint64(ev.FencingToken)
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO `deploy_history` "+
			"(`request_id`, `event_type`, `target`, `commit_sha`, `manifest_digest`, `step`, `result`, `reject_reason`, `detail`, `fencing_token`) "+
			"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		ev.RequestID, ev.EventType, target, commit, digest, step, result, reason, detail, token)
	return err
}

// ReadLatest는 requestId에 대한 가장 최근 이력 이벤트를 반환한다(SELECT — DO-16 상태 조회).
// deploy_history는 append-only이므로 "현재 상태"는 event_at·id가 가장 큰 행이다. 행이 없으면
// 빈 이벤트 + nil을 반환한다 — 아직 아무 이력이 없다는 것은 오류가 아니라 "예약만 되고
// 진전 없음"이며, 호출자는 그것을 재개 대상으로 본다(재전송 분류의 기본값 = 재개).
func (s *SQLStore) ReadLatest(ctx context.Context, requestID string) (HistoryEvent, error) {
	var (
		ev                                           HistoryEvent
		target, commit, digest, step, result, reason sql.NullString
		token                                        sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		"SELECT `request_id`, `event_type`, `target`, `commit_sha`, `manifest_digest`, `step`, `result`, `reject_reason`, `fencing_token` "+
			"FROM `deploy_history` WHERE `request_id` = ? ORDER BY `event_at` DESC, `id` DESC LIMIT 1",
		requestID).
		Scan(&ev.RequestID, &ev.EventType, &target, &commit, &digest, &step, &result, &reason, &token)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return HistoryEvent{}, nil
	case err != nil:
		return HistoryEvent{}, err
	}
	ev.Target = target.String
	ev.CommitSHA = commit.String
	ev.ManifestDigest = digest.String
	ev.Step = step.String
	ev.Result = result.String
	ev.RejectReason = reason.String
	ev.FencingToken = FencingToken(token.Int64)
	return ev, nil
}
