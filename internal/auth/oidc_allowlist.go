// 이 파일은 게이트 2의 "누가 무엇을 배포할 수 있는가"를 소유한다 — repo별 allowlist다.
//
// 게이트 2의 행렬(oidc.go)은 원래 저장소 한 곳(단일 OIDC_REPOSITORY*)을 기대값으로 대조했다.
// 배포 대상이 넷(core·settlement·ledger·gateway)이 되면서 저장소도 여럿이 되고, 그때
// "우리 파이프라인에서 왔다"만으로는 부족해진다: core의 워크플로가 발급받은 정상 토큰으로
// gateway를 배포하는 것을 아무것도 막지 못하기 때문이다. 그래서 판정이 두 겹이 된다 —
//
//	⑴ 이 저장소가 배포를 할 수 있는가 (allowlist 등재)
//	⑵ 그 저장소가 **이** 대상을 배포할 수 있는가 (항목의 허용 target 하나와 결박)
//
// ⑵의 대조는 진입 층(httpentry.withValidate)이 하며, 여기서는 ⑴을 판정하고 그 결과로
// "이 요청에 허용된 target"을 결정에 실어 보낸다.
//
// 설계 정본: docs/plans/2026-08-12/oidc-allowlist/design.md (rev.2 — 결박 위치는 진입 층,
// 단일 env 모드는 1항목 allowlist로 정규화). 불변식 A1·A4가 이 파일에 산다:
//
//	A1 매칭 키 = repository_id(수치) — 이름은 부가 대조이며 불일치 시 거절(개명 감지)
//	A4 파싱 실패·중복 키·두 정본 공존 = 기동 거부(부분 적재 금지 — 반쯤 읽힌 allowlist는
//	   반쯤 열린 문이다)
package auth

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jun-bank/infra/internal/deploy"
)

// allowlist 관련 환경 변수 이름. 두 정본(파일 · 단일 env 세트)이 공존하면 어느 쪽이
// 이겼는지 침묵으로 갈리므로 기동을 거부한다 — 이름을 한 곳에 모아 그 판정을 명시한다.
const (
	envAllowlistFile = "OIDC_ALLOWLIST_FILE"   // allowlist 파일 경로(설정되면 파일 모드)
	envRepository    = "OIDC_REPOSITORY"       // 단일 env 세트 — owner/repo
	envRepositoryID  = "OIDC_REPOSITORY_ID"    // 단일 env 세트 — 수치 ID
	envJobWorkflow   = "OIDC_JOB_WORKFLOW_REF" // 단일 env 세트 — 배포 워크플로 ref
	envAllowedTarget = "OIDC_ALLOWED_TARGET"   // 단일 env 세트 — 이 저장소가 배포할 수 있는 대상 하나
)

// singleModeEnvKeys는 단일 env 세트의 전 키다. 넷은 함께 있거나 함께 없어야 한다 —
// 일부만 남은 상태(이관 중단)는 "무엇이 기대값인지"가 반쯤만 정해진 것이라 거부한다.
var singleModeEnvKeys = []string{envRepository, envRepositoryID, envJobWorkflow, envAllowedTarget}

var (
	// ErrOIDCAllowlist는 allowlist 설정이 성립하지 않아 게이트를 열 수 없음을 나타낸다
	// (파일 부재·파싱 실패·중복 키·두 정본 공존·단일 세트 부분 잔존 — 전부 기동 거부).
	ErrOIDCAllowlist = errors.New("auth: OIDC allowlist 설정 오류 (게이트를 열지 않는다 — fail-closed)")
)

// OIDCAllowEntry는 allowlist 한 항목이다: 저장소 하나와 그 저장소가 배포할 수 있는
// 대상 하나. 세 신원 필드가 전부 일치해야 통과하며(A2 앞 절반), 통과의 산출물이 Target이다.
type OIDCAllowEntry struct {
	Repository     string        // repository — owner/repo 이름(부가 대조 · ASCII 대소문자 무시)
	RepositoryID   string        // repository_id — ★ 수치 ID. allowlist의 유일 키(A1)
	JobWorkflowRef string        // job_workflow_ref — 이 저장소의 배포 워크플로 하나
	Target         deploy.Target // 이 저장소가 배포할 수 있는 대상(닫힌 집합 — deploy가 정본)
}

// OIDCAllowlist는 검증을 마친 항목 집합이다. 만들어진 뒤에는 불변이며 — repository_id로만
// 조회된다(A1). 구성자를 거치지 않은 제로값은 항목이 없는 allowlist이고, 그것으로는 어떤
// 요청도 통과하지 못한다(무설정 = 게이트 안 열림).
//
// ★ 무상태(리뷰 2회차 U12 — 별도 테스트 비대상): 적재 후 이 map을 쓰는 코드는 lookup뿐이며
// 쓰기 경로가 없다(런타임 리로드 없음 · 요청 처리 중 변형 없음). 판정은 (claim, allowlist)의
// 순수 함수이므로 "요청이 다음 요청의 판정에 영향을 준다"는 상태 결함이 성립할 자리가 없다 —
// 동시 요청의 독립성은 구조로 서며, 그 구조가 깨지면 httpentry의 동시성 테스트가 잡는다.
type OIDCAllowlist struct {
	byID map[string]OIDCAllowEntry
}

// NewOIDCAllowlist는 항목들을 검증해 allowlist를 만든다. 하나라도 성립하지 않으면 부분
// 적재하지 않고 통째로 거부한다(A4) — 반쯤 읽힌 allowlist는 "누가 무엇을 배포할 수 있는가"의
// 절반만 아는 문지기이며, 그 상태로 문을 여는 것이 이 경계의 유일한 치명적 실패다.
//
// 유일성은 셋을 본다:
//   - repository_id 중복 — 유일 키가 둘이면 어느 항목이 이겼는지가 map 구성 순서로 갈린다.
//   - target 중복 — repo:target은 1:1이다(같은 대상을 두 저장소가 배포하면 결박이 의미를
//     잃는다). 완화가 필요하면 A1·A2를 함께 재설계한다(design D6).
//   - repository 이름 중복(ASCII fold 후) — 같은 저장소가 다른 수치 ID로 두 번 등재된 것은
//     이전·재생성 뒤 옛 줄을 지우지 않은 운영 실수의 징후다.
func NewOIDCAllowlist(entries []OIDCAllowEntry) (OIDCAllowlist, error) {
	if len(entries) == 0 {
		return OIDCAllowlist{}, fmt.Errorf("%w: 항목이 0개다 (등재된 저장소 없이 게이트를 열지 않는다)", ErrOIDCAllowlist)
	}

	byID := make(map[string]OIDCAllowEntry, len(entries))
	byTarget := make(map[deploy.Target]string, len(entries))
	byName := make(map[string]string, len(entries))

	for i, e := range entries {
		if err := validateAllowEntry(e); err != nil {
			return OIDCAllowlist{}, fmt.Errorf("%w: 항목 %d(%s): %v", ErrOIDCAllowlist, i+1, e.Repository, err)
		}
		if prev, dup := byID[e.RepositoryID]; dup {
			return OIDCAllowlist{}, fmt.Errorf("%w: repository_id 중복 %q (%s · %s) — 유일 키가 둘이면 판정이 순서에 갈린다", ErrOIDCAllowlist, e.RepositoryID, prev.Repository, e.Repository)
		}
		if prev, dup := byTarget[e.Target]; dup {
			return OIDCAllowlist{}, fmt.Errorf("%w: target %q을 두 저장소가 주장한다 (%s · %s) — repo:target은 1:1이다", ErrOIDCAllowlist, e.Target, prev, e.Repository)
		}
		name := asciiLower(e.Repository)
		if prev, dup := byName[name]; dup {
			return OIDCAllowlist{}, fmt.Errorf("%w: repository 이름 중복 %q (repository_id %s · %s) — 같은 저장소가 두 ID로 등재됐다(이전·재생성 뒤 옛 줄 잔존 의심)", ErrOIDCAllowlist, e.Repository, prev, e.RepositoryID)
		}
		byID[e.RepositoryID] = e
		byTarget[e.Target] = e.Repository
		byName[name] = e.RepositoryID
	}
	return OIDCAllowlist{byID: byID}, nil
}

// validateAllowEntry는 항목 하나의 각 칸이 판정에 쓸 수 있는 값인지 본다.
func validateAllowEntry(e OIDCAllowEntry) error {
	if e.Repository == "" {
		return errors.New("repository(owner/repo)가 비었다")
	}
	if err := validRepositoryID(e.RepositoryID); err != nil {
		return err
	}
	if e.JobWorkflowRef == "" {
		return errors.New("job_workflow_ref가 비었다 (배포 워크플로 하나로 고정해야 한다)")
	}
	if !e.Target.Valid() {
		return fmt.Errorf("target %q이 닫힌 집합 %v 밖이다", e.Target, deploy.ValidTargets())
	}
	return nil
}

// validRepositoryID는 수치 ID가 claim과 문자열로 대조 가능한 형태인지 본다: 10진수 양의
// 정수이며, 앞자리 0이 없고, **int64 범위 안**이다.
//
//   - 앞자리 0 거부: "0123"은 값으로는 123이지만 claim의 "123"과 문자열 대조에서 조용히
//     어긋난다 — 등재했는데 영영 통과하지 않는 항목이 된다(무음 불일치 대신 요란한 거부).
//   - int64 상한: GitHub의 저장소 ID는 부호 있는 64비트 정수 도메인이다. 그 범위를 넘는
//     값은 실재하는 ID일 수 없으므로 오타·조작으로 보고 거부한다 — 범위 밖 값을 그대로
//     키로 받아들이면 "설정에는 있으나 어떤 토큰과도 만나지 않는 항목"이 조용히 남는다.
func validRepositoryID(id string) error {
	if id == "" {
		return errors.New("repository_id가 비었다 (수치 ID가 allowlist의 유일 키다)")
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return fmt.Errorf("repository_id %q가 10진 수치가 아니다", id)
		}
	}
	if len(id) > 1 && id[0] == '0' {
		return fmt.Errorf("repository_id %q에 앞자리 0이 있다 (claim의 정규 표기와 문자열 대조에서 어긋난다)", id)
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return fmt.Errorf("repository_id %q가 int64 범위를 벗어난다 (저장소 ID의 도메인 밖 — 오타·조작): %v", id, err)
	}
	if n == 0 {
		return fmt.Errorf("repository_id %q가 0이다 (양의 정수여야 한다)", id)
	}
	return nil
}

// Len은 등재된 항목 수다(기동 로그·진단용).
func (a OIDCAllowlist) Len() int { return len(a.byID) }

// lookup은 claim의 repository_id로 항목을 찾는다 — 이름이 아니라 수치 ID가 키다(A1).
// 이름은 이전·삭제 후 재생성으로 재사용되지만 수치 ID는 재사용되지 않기 때문이다.
func (a OIDCAllowlist) lookup(repositoryID string) (OIDCAllowEntry, bool) {
	e, ok := a.byID[repositoryID]
	return e, ok
}

// --- 파일 파서 ----------------------------------------------------------------

// allowlistFieldCount는 한 줄의 파이프 구분 필드 수다(repository|repository_id|
// job_workflow_ref|target). 값에 파이프가 들어가지 않는 문자집합이라 구분자로 안전하다.
const allowlistFieldCount = 4

// parseOIDCAllowlist는 allowlist 파일 내용을 항목으로 자른다. 한 줄 = 한 항목이며,
// 빈 줄과 **줄 전체 주석**(첫 비공백 문자가 #)은 건너뛴다. 줄 끝 주석은 지원하지 않는다 —
// 값 안의 #를 주석으로 오려내는 것이 조용한 값 변조가 되므로, 그런 줄은 필드 수·target
// 검증에서 요란하게 걸린다(무음 절단보다 기동 거부가 낫다).
//
// 각 필드는 trim한다(정렬용 공백 허용). 필드 수 불일치·빈 필드·수치 아닌 ID·닫힌 집합 밖
// target은 그 줄 번호와 함께 오류다 — 어느 줄이 잘못됐는지 모르면 고칠 수 없다.
func parseOIDCAllowlist(content []byte) ([]OIDCAllowEntry, error) {
	var entries []OIDCAllowEntry
	for i, raw := range strings.Split(string(content), "\n") {
		lineNo := i + 1
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != allowlistFieldCount {
			return nil, fmt.Errorf("%w: %d번째 줄의 필드가 %d개다 (repository|repository_id|job_workflow_ref|target — %d개여야 한다)", ErrOIDCAllowlist, lineNo, len(fields), allowlistFieldCount)
		}
		e := OIDCAllowEntry{
			Repository:     strings.TrimSpace(fields[0]),
			RepositoryID:   strings.TrimSpace(fields[1]),
			JobWorkflowRef: strings.TrimSpace(fields[2]),
			Target:         deploy.Target(strings.TrimSpace(fields[3])),
		}
		if err := validateAllowEntry(e); err != nil {
			return nil, fmt.Errorf("%w: %d번째 줄: %v", ErrOIDCAllowlist, lineNo, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// loadOIDCAllowlist는 환경에서 allowlist를 읽는다(기동 시 1회 — 런타임 리로드는 없다.
// 갱신은 재기동이며, 그것이 부분 적재 위험을 구조적으로 없앤다).
//
// 정본은 하나여야 한다:
//   - OIDC_ALLOWLIST_FILE 설정 → 파일 모드. 단일 env 세트가 하나라도 남아 있으면 거부한다
//     (공존 시 어느 쪽이 이겼는지가 침묵으로 갈린다 — 이관은 파일 배치 + 단일 env 제거다).
//   - 미설정 → 단일 env 세트 넷이 전부 있어야 하며, **1항목 allowlist로 정규화**한다.
//     검증 코드 경로를 하나로 유지하기 위해서다(A2가 모드와 무관하게 성립한다).
//
// "설정됨" 판정은 공백을 제거한 뒤 비어 있지 않은 값만이다 — 빈 값 할당(KEY=)은 미설정과
// 같게 본다(.env에서 주석 대신 빈 값을 남기는 관행 때문).
func loadOIDCAllowlist() (OIDCAllowlist, error) {
	file := envValue(envAllowlistFile)

	var present, absent []string
	for _, k := range singleModeEnvKeys {
		if envValue(k) != "" {
			present = append(present, k)
			continue
		}
		absent = append(absent, k)
	}

	if file != "" {
		if len(present) > 0 {
			return OIDCAllowlist{}, fmt.Errorf("%w: %s와 단일 env 세트(%s)가 함께 설정됐다 — 정본은 하나여야 한다(이관: 파일 배치 후 단일 env 제거)", ErrOIDCAllowlist, envAllowlistFile, strings.Join(present, ", "))
		}
		return loadAllowlistFile(file)
	}

	if len(present) == 0 {
		return OIDCAllowlist{}, fmt.Errorf("%w: %s도 단일 env 세트(%s)도 없다 — 등재된 저장소가 없으면 게이트를 열지 않는다", ErrOIDCAllowlist, envAllowlistFile, strings.Join(singleModeEnvKeys, ", "))
	}
	if len(absent) > 0 {
		return OIDCAllowlist{}, fmt.Errorf("%w: 단일 env 세트가 일부만 설정됐다 — 설정됨(%s) · 없음(%s). 넷은 함께 있어야 한다(특히 %s가 없으면 결박할 대상이 없다)", ErrOIDCAllowlist, strings.Join(present, ", "), strings.Join(absent, ", "), envAllowedTarget)
	}

	// 단일 env 세트 → 1항목 allowlist로 정규화(rev.2 변경 ② — 무결박 모드를 남기지 않는다).
	entry := OIDCAllowEntry{
		Repository:     envValue(envRepository),
		RepositoryID:   envValue(envRepositoryID),
		JobWorkflowRef: envValue(envJobWorkflow),
		Target:         deploy.Target(envValue(envAllowedTarget)),
	}
	list, err := NewOIDCAllowlist([]OIDCAllowEntry{entry})
	if err != nil {
		return OIDCAllowlist{}, fmt.Errorf("단일 env 세트 정규화: %w", err)
	}
	return list, nil
}

// loadAllowlistFile은 allowlist 파일을 읽어 검증한다. 경로가 설정됐는데 읽지 못하는 것은
// (부재·권한·디렉토리) 기동 거부다 — 경로를 적어 두고 파일이 없는 상태는 "allowlist를
// 쓰려 했으나 비어 있다"이며, 그때 조용히 전면 거절 모드로 도는 것보다 요란하게 서지 않는
// 편이 낫다(원인이 배포 시점에 드러난다).
//
// ★ 퍼미션 케이스(리뷰 2회차 S6 — 별도 테스트 비대상): 0000 같은 읽기 불가 퍼미션은
// os.ReadFile의 오류로 이 가지에 그대로 들어오며, 부재·디렉토리 케이스가 같은 가지를
// 이미 덮는다. 테스트를 따로 두지 않는 것은 실행 환경 때문이다 — agent 컨테이너는 root로
// 돌아 mode 비트를 우회하므로, 그 환경에서 0000 파일은 "읽기 실패"가 아니라 그냥 읽힌다
// (테스트가 환경에 따라 갈리는 것보다 이 계약을 주석으로 못박는 편이 정직하다).
func loadAllowlistFile(path string) (OIDCAllowlist, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return OIDCAllowlist{}, fmt.Errorf("%w: %s=%q를 읽지 못했다: %v", ErrOIDCAllowlist, envAllowlistFile, path, err)
	}
	entries, err := parseOIDCAllowlist(content)
	if err != nil {
		return OIDCAllowlist{}, fmt.Errorf("%s=%q: %w", envAllowlistFile, path, err)
	}
	list, err := NewOIDCAllowlist(entries)
	if err != nil {
		return OIDCAllowlist{}, fmt.Errorf("%s=%q: %w", envAllowlistFile, path, err)
	}
	return list, nil
}

// envValue는 환경 변수를 공백 제거해 읽는다("설정됨" 판정의 단일 출처).
func envValue(key string) string { return strings.TrimSpace(os.Getenv(key)) }

// asciiLower는 ASCII 대문자만 소문자로 내린다. 저장소 이름 대조에 유니코드 fold를 쓰지
// 않는 것은 의도다 — 유니코드 simple fold는 서로 다른 문자를 같다고 보므로(예: 켈트어
// ſ↔s, 터키어 İ), 그것으로 이름을 대조하면 다른 저장소 이름이 같다고 판정될 수 있다.
// GitHub 저장소 이름은 ASCII 문자집합이므로 ASCII 한정 비교가 필요충분하다.
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// asciiEqualFold는 ASCII 대소문자만 무시하고 두 문자열을 대조한다(위 asciiLower와 같은
// 이유로 strings.EqualFold를 쓰지 않는다).
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return asciiLower(a) == asciiLower(b)
}
