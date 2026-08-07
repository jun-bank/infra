// Package deploy는 오케스트레이션 골격이다: CD-4의 순서 있는 적용 시퀀스와 CI가
// 서명하는 배포 manifest를 소유한다(ADR-027 DO-18). 두 게이트(auth, ssh)와 지속
// 저장소(store) 위에 위치하며 그것들을 순서대로 엮는다.
//
// 계약 출처(정본):
//   - ADR-027 DO-4   (agent의 작업은 컨테이너 연산뿐: pull -> up/down -> status ->
//     이력; 빌드 도구 없음, 호스트에서 sudo 없음)
//   - ADR-027 DO-18  (CI는 태그만이 아니라 manifest 전체를 서명; pull/up은 digest로
//     고정; 롤백 단위는 manifest)
//   - ADR-024 §2.1   (블루-그린; 배포 산출물 = 이미지 + compose)
//
// 이것은 스캐폴드다: 시퀀스는 스텝 순서를 문서화한 인터페이스로 표현되며, 모든 스텝은
// TODO다.
package deploy

import "errors"

// ErrNotImplemented는 스캐폴드 표면을 표시한다.
var ErrNotImplemented = errors.New("deploy: not implemented (scaffold)")

// Target은 닫힌 배포 대상 집합이다(ADR-027 DO-20: 정확히 셋 — 진입 설정과 Oracle
// 엣지는 배포 대상이 아니다).
type Target string

const (
	TargetCore       Target = "core"       // .9
	TargetSettlement Target = "settlement" // .158
	TargetLedger     Target = "ledger"     // .164
)

// Manifest는 CI가 서명하는 대상이다(DO-18): 필수 6개 필드. 이미지는 태그가 아니라
// digest로 고정되고, compose revision은 불변 식별자이므로, 롤백은 이미지와 부팅
// 정의를 둘 다 이전 지점으로 되돌린다.
type Manifest struct {
	Target          Target
	CommitSHA       string
	ImageDigest     string // sha256:... — 고정됨(DO-18 ⑵), 절대 가변 태그가 아님
	ComposeRevision string // 부팅 정의의 불변 식별자(DO-18 ⑷)
	ConfigVersion   string // 애플리케이션 설정 스키마/버전(DO-18 ⑸)
	RequestID       string // DO-10; 시퀀스 전체를 통해 운반됨
}

// Orchestrator는 하나의 manifest에 대해 CD-4 적용 시퀀스를 실행한다. 순서가 곧
// 계약이다: 이미지 pull -> compose up -> 헬스 판정 -> switch -> compose down ->
// 이력. 롤백은 동일한 락과 동일한 이력이며, 호스트 로컬 이미지로부터 이전 manifest를
// 재생한다(DO-7).
type Orchestrator interface {
	// Apply는 검증되고 락을 보유한 요청에 대해 전체 시퀀스를 실행한다. 게이트 1(auth)이
	// 통과했고 배포 윈도우 락을 보유하고 있음을 전제한다(store); 그것들이 성립하기
	// 전에는 절대 SSH를 열지 않는다(DO-2).
	Apply(m Manifest) error

	// Rollback은 동일한 락과 이력 아래에서 이전 manifest를 재생한다(호스트 로컬
	// 이미지, 재빌드 없음, 레지스트리 fetch 없음)(DO-7, DO-18 ⑶).
	Rollback(m Manifest) error
}

// stubOrchestrator는 스캐폴드 구현이다.
type stubOrchestrator struct{}

// NewOrchestrator는 (미구현) orchestrator를 반환한다.
func NewOrchestrator() Orchestrator { return stubOrchestrator{} }

func (stubOrchestrator) Apply(Manifest) error {
	// TODO(CD-4 / DO-4 / DO-16): 순서 있는 시퀀스, 각 스텝은 query 가능한
	// 사후조건("기대한 digest의 컨테이너가 실행 중")을 가진다. 스텝 사이의 UNKNOWN은
	// 무턱대고 재시도하지 않고 status query로 해소한다.
	return ErrNotImplemented
}

func (stubOrchestrator) Rollback(Manifest) error {
	// TODO(DO-7 / DO-18 ⑶): 호스트 로컬 이미지로부터 이전 manifest로 전환.
	return ErrNotImplemented
}
