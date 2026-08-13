// Package compose는 서명된 manifest에 동봉된 compose 정의를 **실행 전에** 결박한다
// (infra#19 · ADR-030 CP-1~7). 두 관심사를 소유한다:
//
//   - 구조 검증(validate.go): 동봉 YAML이 닫힌 allowlist를 통과하는지 — 부작용 0.
//   - workspace(workspace.go): 검증을 통과한 바이트를 불변 candidate 파일로 기록하고,
//     배포가 성공한 뒤에만 target 단위 applied 인덱스로 승격한다.
//
// 계약 출처(정본 — 재해석하지 않는다):
//   - ADR-030 CP-1  (인증된 in-memory 바이트에서 sha256 선대조 · 대조 통과 바이트만 기록·사용)
//   - ADR-030 CP-2  (기록은 agent 전용 workspace — sudo 없음·고정 경로)
//   - ADR-030 CP-3  (appService는 manifest·compose·호스트 env 3자 일치)
//   - ADR-030 CP-4  (로컬 보관 = 수동 비상 복원 재료 · 자동 소비 경로 없음)
//   - ADR-030 CP-7  (fail-closed 구조 allowlist — 미지 키·미등재 변수/env/볼륨 거절)
//   - 설계 rev.2/2.1/2.2 = docs/plans/2026-08-13/compose-embed/design.md
//
// 이 패키지는 leaf다 — deploy·dispatch를 import하지 않는다(IA-5 닫힌 import).
package compose

import (
	"errors"
	"fmt"
)

// 거절 코드 — 이력·응답이 문자열 매칭에 기대지 않도록 기계 판독 코드를 함께 낸다.
// 코드가 갈리는 이유: 같은 "거절"이라도 운영 대응이 다르고(설정을 고칠지·CI를 고칠지·
// 침해를 의심할지), 무엇보다 **잘못된 이유로 거절되는 경로**(예: 병합 키가 미지 키로
// 뭉개져 통과 조건만 우연히 만족시키면 다음 리팩토링에서 조용히 열린다)를 테스트가
// 코드까지 단언해 막을 수 있게 하기 위해서다.
const (
	// --- 동봉 YAML 구조(CP-7) ---
	CodeSize          = "COMPOSE_SIZE"           // 디코드 후 크기 상한 초과
	CodeYAMLParse     = "COMPOSE_YAML_PARSE"     // YAML로 파싱되지 않음
	CodeMultiDoc      = "COMPOSE_MULTI_DOC"      // 문서가 2개 이상(--- 구분)
	CodeAnchor        = "COMPOSE_ANCHOR"         // 앵커 정의 또는 별칭 참조
	CodeMergeKey      = "COMPOSE_MERGE_KEY"      // 병합 키 `<<`
	CodeDupKey        = "COMPOSE_DUP_KEY"        // 같은 매핑에 중복 키
	CodeTag           = "COMPOSE_TAG"            // 허용 태그 밖(!!null·!!float·커스텀 태그 등)
	CodeNonStringKey  = "COMPOSE_NON_STRING_KEY" // 비문자열 키
	CodeDepth         = "COMPOSE_DEPTH"          // 중첩 깊이 상한 초과
	CodeNodeLimit     = "COMPOSE_NODE_LIMIT"     // 노드 수 상한 초과
	CodeTopLevel      = "COMPOSE_TOP_LEVEL"      // 최상위가 services 단일 키가 아님
	CodeServiceCount  = "COMPOSE_SERVICE_COUNT"  // 서비스가 정확히 1개가 아님
	CodeServiceName   = "COMPOSE_SERVICE_NAME"   // 서비스명이 appService와 불일치(CP-3)
	CodeUnknownKey    = "COMPOSE_UNKNOWN_KEY"    // 서비스의 미지 키
	CodeNodeKind      = "COMPOSE_NODE_KIND"      // 필드의 노드 종류·태그 불일치(대체 표기 포함)
	CodeImage         = "COMPOSE_IMAGE"          // image가 ${imageEnvVar} 정확일치가 아님
	CodePorts         = "COMPOSE_PORTS"          // ports 형식 위반
	CodeEnvironment   = "COMPOSE_ENVIRONMENT"    // environment 항목이 등재 밖·중복
	CodeRestart       = "COMPOSE_RESTART"        // restart 값이 닫힌 목록 밖
	CodeHealthcheck   = "COMPOSE_HEALTHCHECK"    // healthcheck 고정 패턴 위반
	CodeExtraHosts    = "COMPOSE_EXTRA_HOSTS"    // extra_hosts 정확일치 위반
	CodeVolume        = "COMPOSE_VOLUME"         // 볼륨 튜플이 등재 밖·심볼릭 링크 탈출
	CodeInterpolation = "COMPOSE_INTERPOLATION"  // 허용 2형식 밖의 `$` 등장

	// --- workspace(CP-2·CP-4) ---
	// CodeStorageIntegrity는 **검증 실패와 별도 분류**다(G-14): 바이트는 옳았는데 저장이
	// 어긋났다 = 요청자의 잘못이 아니라 이 호스트의 저장 계층 장애다.
	CodeStorageIntegrity = "STORAGE_INTEGRITY_ERROR"
	// CodeWorkspace는 workspace 배선 자체가 계약을 만족하지 않는 것이다(경로·권한·소유·.env).
	CodeWorkspace = "COMPOSE_WORKSPACE"
)

// Error는 기계 판독 코드를 가진 거절이다. 문면은 사람을 위한 것이고, 판정은 Code가 소유한다.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

// errf는 코드가 붙은 오류를 만든다.
func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// CodeOf는 오류에서 기계 판독 코드를 읽는다(코드 없는 오류는 빈 문자열).
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
