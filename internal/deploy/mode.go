package deploy

import "context"

// 배포 모드 판정 — DO-5(모드 조회)·DO-17(fail-closed·mode version 원자 검증).
//
// 모드는 게이트(HMAC·OIDC)를 통과한 뒤, 대상별로 판정한다. 판정은 오케스트레이션의
// 소유다(IA-4 ⑵) — 대상은 검증된 manifest에서 오고(HTTP 진입 층은 manifest를 파싱하지
// 않는다), 원자 검증은 락 획득과 같은 자리에서 서기 때문이다(DO-17 ⑵). 그래서 이 판정은
// httpentry(게이트 체인)가 아니라 여기(Apply 앞단)에 산다.
//
// 계약 출처(정본 — 재해석하지 않는다):
//   - ADR-027 DO-5   (모드 토글은 관제 소유 · 대상마다 dev/운영 · 토글은 기록된다)
//   - ADR-027 DO-17  (모드 정본=배포 스키마 · append-only · 단조 version · 요청 수락 시
//     version 기록 → 적용 직전 원자 검증 · 장애 시 운영 모드 fail-closed)
//   - ADR-024 §2.2   (dev는 환경이 아니라 모드 — dev=자동 방아쇠, 운영=사람 승인)

// Mode는 배포 대상의 두 모드다(ADR-024 §2.2). dev는 환경이 아니라 방아쇠 하나만
// 바꾸는 모드다 — 락·서명 검증·CD-4 순서·이력은 dev에서도 그대로다.
type Mode string

const (
	ModeDev         Mode = "dev"         // 자동 방아쇠 (main 머지가 곧 배포)
	ModeOperational Mode = "operational" // 사람 승인 필수
)

// ModeReader는 대상별 현재 mode와 단조 version을 읽는다(SELECT). 소비 지점 인터페이스로
// 두어 deploy가 store 구체 타입에 묶이지 않게 한다(IA-5 Go 관용구) — store.SQLStore가
// Current로 이를 만족한다. 오류(연결 실패·mode 부재)는 그대로 올라오며, 이 패키지가
// 그것을 fail-closed로 해석한다.
type ModeReader interface {
	Current(ctx context.Context, target string) (mode string, version uint64, err error)
}

// ModeDecision은 게이트 통과 후 대상 mode 판정 결과다. 요청 수락 시점의 판정이며,
// Version은 적용 직전 원자 검증(VerifyModeUnchanged)이 대조할 기준값으로 이력에 남는다.
type ModeDecision struct {
	Mode             Mode
	Version          uint64
	ApprovalRequired bool // 운영 모드면 참(사람 승인 필요) · dev면 거짓(자동 진행)
	// FailClosed는 저장 접근 불가·mode 부재·손상으로 operational로 닫혔음을 나타낸다.
	// 이 사실은 이력에 남는다 — "운영이라 승인 필요"와 "장애라 안전하게 닫음"이 사후에
	// 구별되어야 한다(DO-5 근거의 관측 성립 조건과 같은 축).
	FailClosed bool
}

// DecideMode는 대상의 현재 mode를 읽어 판정한다(DO-5). 정상 경로는 둘 —
//   - dev         → 자동 진행 (ApprovalRequired=false)
//   - operational → 사람 승인 필요 (ApprovalRequired=true)
//
// 그리고 저장 접근 실패·mode 부재(ErrNoMode)·미지의 mode 문자열(손상)은 전부
// operational(승인 필요)로 닫는다 — fail-closed(DO-17 ⑷). "모드를 모르면 dev"가 아니다:
// 승인 게이트가 장애로 열리면 승인 없이 배포가 나가므로, 모르면 승인 쪽으로 닫는다.
func DecideMode(ctx context.Context, r ModeReader, target string) ModeDecision {
	mode, version, err := r.Current(ctx, target)
	if err != nil {
		// 저장 접근 실패 또는 mode 부재 — 자동으로 열지 않는다.
		return ModeDecision{Mode: ModeOperational, ApprovalRequired: true, FailClosed: true}
	}
	switch Mode(mode) {
	case ModeDev:
		return ModeDecision{Mode: ModeDev, Version: version, ApprovalRequired: false}
	case ModeOperational:
		return ModeDecision{Mode: ModeOperational, Version: version, ApprovalRequired: true}
	default:
		// 닫힌 집합 밖의 값 = 손상 = fail-closed. DB ENUM이 이를 막지만, store를 우회한
		// 어떤 경로가 이상 값을 넣더라도 코드가 다시 한 번 operational로 닫는다.
		return ModeDecision{Mode: ModeOperational, ApprovalRequired: true, FailClosed: true}
	}
}

// ModeVerify는 적용 직전 mode version 원자 검증의 결과다.
type ModeVerify struct {
	OK             bool   // 수락 시 version이 그대로면 참 — 진행 허용
	CurrentVersion uint64 // 재조회한 현재 version (거절 기록용)
	FailClosed     bool   // 저장 접근 실패로 검증 불가라 거절했는지
}

// VerifyModeUnchanged는 적용 직전(CD-4 ① 락 획득과 같은 자리) 요청 수락 시 기록한
// acceptedVersion이 그대로인지 검증해 토글-요청 race를 닫는다(DO-17 ⑵). version이
// 바뀌었으면(진행 전 토글) OK=false로 거절한다. 저장 접근 실패도 거절(FailClosed) —
// 검증하지 못하는 채로 부작용을 열지 않는다(fail-closed).
//
// 재조회한 mode가 닫힌 집합(dev|operational) 밖이면 손상으로 보고 거절한다 —
// version만 대조하고 mode를 버리면, version이 안 바뀐 채 mode가 미지 값으로 손상됐을 때
// OK=true로 새어 승인 게이트가 장애로 열린다. DecideMode의 손상=fail-closed 계약과
// 일관되게, 검증 시에도 mode 유효성을 확인한다(DO-17 ⑷).
//
// ⚠️ 지금은 acceptedVersion과 재조회 version의 비교다. DO-17 ⑵·§2.2(저장 정본 이관)가
// 요구하는 "락 획득과 한 트랜잭션에서의 원자 검증"은 락 전이가 구현될 때 그 트랜잭션
// 안으로 이 비교가 들어가며, 그 전까지 비교와 락 획득 사이의 창은 [구현 검증]으로
// 남는다(ADR-027 §7 잔여-2 · ADR-022 CDT-3).
func VerifyModeUnchanged(ctx context.Context, r ModeReader, target string, acceptedVersion uint64) ModeVerify {
	mode, version, err := r.Current(ctx, target)
	if err != nil {
		return ModeVerify{OK: false, FailClosed: true}
	}
	switch Mode(mode) {
	case ModeDev, ModeOperational:
		// 닫힌 집합 안 — version 대조로 진행.
	default:
		// 닫힌 집합 밖의 값 = 손상 = fail-closed(DecideMode와 일관).
		return ModeVerify{OK: false, CurrentVersion: version, FailClosed: true}
	}
	return ModeVerify{OK: version == acceptedVersion, CurrentVersion: version}
}
