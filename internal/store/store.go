// Package store는 배포 스키마에 대한 유일한 관문이다(ADR-022 DT-9..DT-12).
// DB 권한 모델의 코드 측 절반이다: 배포 스키마는 락 행에 대한 raw DML을 허용하지
// 않고 나머지는 append-only이며, 이 패키지는 일반 exec/query 메서드를 전혀 노출하지
// 않음으로써 그것을 그대로 반영한다. 이 패키지를 통해 락을 변경하는 유일한 방법은
// 일곱 개의 명명된 전이 중 하나(각각 CALL sp_lock_*를 발행)이고, ledger·mode·history를
// 쓰는 유일한 방법은 Append/Reserve(각각 하나의 INSERT를 발행)뿐이다. 따라서 raw
// DML은 grant에서 금지된 것과 마찬가지로 코드에서도 도달 불가능하다(DT-12) — 동일한
// 규칙을 두 계층에서 강제한다.
//
// 이것은 스캐폴드다: 모든 메서드는 ErrNotImplemented를 반환하는 미구현 스텁이다.
// 실제 *sql.DB와 MySQL 드라이버로의 연결, 그리고 실제 MySQL에 대해 프로시저 계약을
// 증명하는 Testcontainers 통합 스위트가 다음 단계다(store_integration_test.go 참조).
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented는 스캐폴드 표면을 표시한다.
var ErrNotImplemented = errors.New("store: not implemented (scaffold)")

// ErrReplay는 requestId나 jti가 이미 예약된 경우 — 즉 재생 — Reserve가 반환한다.
// 재생은 ledger의 UNIQUE 제약에 의해 INSERT 시점에 거부된다(ADR-027 DO-10).
// 이는 writer의 선의에 의존하지 않는 방어다.
var ErrReplay = errors.New("store: request already reserved (replay)")

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
	// Acquire — sp_lock_acquire (전이 1; 두 호출자 모두). 락이 비어 있거나 lease가
	// 만료된 경우 성공하며; 새 토큰을 반환하고, 경합 시 ok=false를 반환한다.
	Acquire(ctx context.Context, kind HolderKind, holderID string, lease time.Duration) (token FencingToken, ok bool, err error)

	// Renew — sp_lock_renew (전이 2; 두 호출자 모두). 호출자가 여전히 holder이고
	// (kind+id+token) lease가 살아 있는 동안에만 lease를 연장한다.
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

	// Release — sp_lock_release (전이 7; 두 호출자 모두). 호출자가 현재 holder인
	// 경우에만 해제한다; 토큰은 리셋되지 않고 채무도 지워지지 않는다.
	Release(ctx context.Context, kind HolderKind, holderID string, token FencingToken) (ok bool, err error)

	// Read는 락 행의 스냅샷을 반환한다(SELECT).
	Read(ctx context.Context) (LockState, error)
}

// LedgerStore는 어떤 부작용이 있기 전에 requestId/jti를 예약한다(ADR-027 DO-10 ⑶).
// Reserve(INSERT)만 노출한다 — append-only이며, 삭제 메서드가 없으므로 재생 방어를
// writer가 되돌릴 수 없다.
type LedgerStore interface {
	// Reserve는 예약을 INSERT한다. requestId가 이미 존재하거나 jti가 재사용되면
	// ErrReplay를 반환한다. 동일 requestId/다른 digest 호출은 호출자가 거부 후
	// 기록해야 하는 충돌이다(DO-10 ⑷).
	Reserve(ctx context.Context, requestID, jti, bodyDigest string) error
}

// ModeStore는 대상별 mode를 읽고 append한다(ADR-027 DO-17 ⑵). 토글은 단조 증가하는
// 버전을 가진 INSERT이며 절대 덮어쓰기가 아니다; 최신 행이 현재 mode다. fail-closed
// 기본값은 operational이다(DO-17 ⑷) — 그 판정은 읽었을 때 행이 없을 경우 호출자의
// 몫이며, 이 store는 기본값을 지어내지 않는다.
type ModeStore interface {
	// Current는 대상의 최신 mode와 버전을 반환한다(SELECT).
	Current(ctx context.Context, target string) (mode string, version uint64, err error)
	// AppendMode는 새 mode 행을 INSERT한다. actor는 인증된 subject에서 파생되며,
	// 절대 자기 보고가 아니다(DO-12 ⑶).
	AppendMode(ctx context.Context, target, mode string, version uint64, actor string) error
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
	RejectReason   string // RL-8: 기록된 거부 사유
	FencingToken   FencingToken
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

// SQLStore는 네 개 store 모두의 (미구현) SQL 기반 구현이다. MySQL 드라이버가
// 추가되면 *sql.DB를 보유할 것이나; 지금은 아무것도 보유하지 않으며 모든 메서드는
// ErrNotImplemented를 반환한다.
type SQLStore struct {
	// TODO(다음 단계): db *sql.DB — DEPLOY_DB_DSN에 대해 열림(LAN 전용, 배포 스키마
	// 전용; ADR-022 DT-10). 드라이버는 이것이 구현될 때 추가된다.
}

// New는 미구현 SQLStore를 반환한다.
func New() *SQLStore { return &SQLStore{} }

// SQLStore가 모든 store 인터페이스를 만족한다는 컴파일 타임 단언.
var (
	_ LockStore    = (*SQLStore)(nil)
	_ LedgerStore  = (*SQLStore)(nil)
	_ ModeStore    = (*SQLStore)(nil)
	_ HistoryStore = (*SQLStore)(nil)
)

func (*SQLStore) Acquire(context.Context, HolderKind, string, time.Duration) (FencingToken, bool, error) {
	return 0, false, ErrNotImplemented
}

func (*SQLStore) Renew(context.Context, HolderKind, string, FencingToken, time.Duration) (bool, error) {
	return false, ErrNotImplemented
}

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

func (*SQLStore) Release(context.Context, HolderKind, string, FencingToken) (bool, error) {
	return false, ErrNotImplemented
}

func (*SQLStore) Read(context.Context) (LockState, error) {
	return LockState{}, ErrNotImplemented
}

func (*SQLStore) Reserve(context.Context, string, string, string) error {
	return ErrNotImplemented
}

func (*SQLStore) Current(context.Context, string) (string, uint64, error) {
	return "", 0, ErrNotImplemented
}

func (*SQLStore) AppendMode(context.Context, string, string, uint64, string) error {
	return ErrNotImplemented
}

func (*SQLStore) AppendEvent(context.Context, HistoryEvent) error {
	return ErrNotImplemented
}

func (*SQLStore) ReadLatest(context.Context, string) (HistoryEvent, error) {
	return HistoryEvent{}, ErrNotImplemented
}
