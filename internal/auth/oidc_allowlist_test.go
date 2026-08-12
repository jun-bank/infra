// allowlist 로딩의 단위 테스트. 여기서 밟는 것은 대부분 **기동 거부** 가지다(A4) —
// 이 경계의 유일한 치명적 실패는 "설정이 어딘가 어긋났는데 그럭저럭 뜨는 것"이기
// 때문이다. 반쯤 읽힌 allowlist·정본 둘·결박 없는 단일 모드는 전부 반쯤 열린 문이다.
//
// 통과 경로도 함께 못박는다 — 거절 경로만 있으면 과잉 거부(정상 설정이 뜨지 않는 것)를
// 잡지 못한다.
package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jun-bank/infra/internal/deploy"
)

// oidcEnv는 게이트 2 정책이 읽는 환경 전체다. 각 테스트가 전 키를 명시적으로 채워
// 실행 환경의 잔여 값이 결과를 가르지 않게 한다(테스트가 자기 환경을 소유한다).
type oidcEnv struct {
	issuer         string
	audience       string
	ownerID        string
	refAllowlist   string
	allowlistFile  string
	repository     string
	repositoryID   string
	jobWorkflowRef string
	allowedTarget  string
}

// singleModeEnv는 단일 env 세트만으로 완전한 환경이다(이관 전 .9의 형태 + 신설
// OIDC_ALLOWED_TARGET).
func singleModeEnv() oidcEnv {
	return oidcEnv{
		issuer:         "https://token.actions.githubusercontent.com",
		audience:       "https://deploy.jun-bank.example",
		ownerID:        "654321",
		refAllowlist:   "refs/heads/main",
		repository:     "jun-bank/infra",
		repositoryID:   "123456",
		jobWorkflowRef: "jun-bank/infra/.github/workflows/deploy.yml@refs/heads/main",
		allowedTarget:  "core",
	}
}

func (e oidcEnv) apply(t *testing.T) {
	t.Helper()
	t.Setenv("OIDC_ISSUER", e.issuer)
	t.Setenv("OIDC_AUDIENCE", e.audience)
	t.Setenv("OIDC_OWNER_ID", e.ownerID)
	t.Setenv("OIDC_REF_ALLOWLIST", e.refAllowlist)
	t.Setenv(envAllowlistFile, e.allowlistFile)
	t.Setenv(envRepository, e.repository)
	t.Setenv(envRepositoryID, e.repositoryID)
	t.Setenv(envJobWorkflow, e.jobWorkflowRef)
	t.Setenv(envAllowedTarget, e.allowedTarget)
	t.Setenv("AGENT_CLOCK_SKEW", "")
}

// writeAllowlist는 임시 allowlist 파일을 만들고 경로를 준다.
func writeAllowlist(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oidc-allowlist.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("테스트 allowlist 파일 쓰기 실패: %v", err)
	}
	return path
}

// TestLoadOIDCPolicyBootRefusals는 기동을 거부해야 하는 설정 가지를 전부 밟는다(A4).
// 각 행은 "이 설정으로 뜨면 무엇이 반쯤 열리는가"에 대응한다.
func TestLoadOIDCPolicyBootRefusals(t *testing.T) {
	twoLines := "jun-bank/infra|123456|jun-bank/infra/.github/workflows/deploy.yml@refs/heads/main|core\n"

	for _, tc := range []struct {
		name string
		// mutate는 단일 env 세트 환경을 변형한다(nil이면 그대로).
		mutate func(*oidcEnv)
		// file이 true면 fileContent로 파일을 만들어 경로를 주입한다. 그때 단일 세트는
		// 기본적으로 비워 파일 검증 가지를 밟는다 — coexist가 true인 행만 남겨 둔다.
		file        bool
		fileContent string
		coexist     bool
		wantIn      string // 오류 메시지에 담겨야 할 조각(원인이 로그에서 바로 보여야 한다)
	}{
		// --- 전역 공통 칸(기존 계약 — 변경 없음) ---
		{name: "iss 미설정", mutate: func(e *oidcEnv) { e.issuer = "" }, wantIn: "필수 값"},
		{name: "aud 미설정", mutate: func(e *oidcEnv) { e.audience = "" }, wantIn: "필수 값"},
		{name: "owner_id 미설정", mutate: func(e *oidcEnv) { e.ownerID = "" }, wantIn: "필수 값"},
		{name: "ref 허용목록 미설정", mutate: func(e *oidcEnv) { e.refAllowlist = "" }, wantIn: "필수 값"},

		// --- 정본이 없다 / 둘이다 ---
		{name: "파일도 단일 세트도 없음", mutate: clearSingleMode, wantIn: "게이트를 열지 않는다"},
		{name: "파일과 단일 세트 공존", file: true, fileContent: twoLines, coexist: true, wantIn: "정본은 하나"},
		{name: "파일과 단일 세트 일부 공존(target만 잔존)", file: true, fileContent: twoLines, coexist: true,
			mutate: func(e *oidcEnv) { e.repository, e.repositoryID, e.jobWorkflowRef = "", "", "" }, wantIn: "정본은 하나"},

		// --- 단일 env 세트의 부분 잔존·값 오류 ---
		{name: "단일 세트 — ALLOWED_TARGET 없음", mutate: func(e *oidcEnv) { e.allowedTarget = "" }, wantIn: "일부만"},
		{name: "단일 세트 — REPOSITORY_ID 없음", mutate: func(e *oidcEnv) { e.repositoryID = "" }, wantIn: "일부만"},
		{name: "단일 세트 — JOB_WORKFLOW_REF 없음", mutate: func(e *oidcEnv) { e.jobWorkflowRef = "" }, wantIn: "일부만"},
		{name: "단일 세트 — 공백만 있는 값은 미설정 취급", mutate: func(e *oidcEnv) { e.allowedTarget = "   " }, wantIn: "일부만"},
		{name: "단일 세트 — target이 닫힌 집합 밖", mutate: func(e *oidcEnv) { e.allowedTarget = "core-v2" }, wantIn: "닫힌 집합"},
		{name: "단일 세트 — repository_id 비수치", mutate: func(e *oidcEnv) { e.repositoryID = "12a456" }, wantIn: "수치가 아니다"},
		{name: "단일 세트 — repository_id 0", mutate: func(e *oidcEnv) { e.repositoryID = "0" }, wantIn: "양의 정수"},
		{name: "단일 세트 — repository_id 음수", mutate: func(e *oidcEnv) { e.repositoryID = "-1" }, wantIn: "수치가 아니다"},

		// --- 파일 모드 ---
		{name: "파일 경로 설정됐으나 부재", wantIn: "읽지 못했다",
			mutate: func(e *oidcEnv) { clearSingleMode(e); e.allowlistFile = "/nonexistent/oidc-allowlist.txt" }},
		{name: "항목 0개(주석·빈 줄뿐)", file: true, fileContent: "# 아직 아무도 등재하지 않았다\n\n   \n", wantIn: "항목이 0개"},
		{name: "필드 부족(3칸)", file: true, fileContent: "jun-bank/infra|123456|core\n", wantIn: "필드가 3개"},
		{name: "필드 초과(5칸)", file: true, fileContent: "jun-bank/infra|123456|wf|core|extra\n", wantIn: "필드가 5개"},
		{name: "빈 필드(repository)", file: true, fileContent: "|123456|wf@refs/heads/main|core\n", wantIn: "repository(owner/repo)가 비었다"},
		{name: "빈 필드(job_workflow_ref)", file: true, fileContent: "jun-bank/infra|123456||core\n", wantIn: "job_workflow_ref가 비었다"},
		{name: "repository_id 비수치", file: true, fileContent: "jun-bank/infra|12_3456|wf@refs/heads/main|core\n", wantIn: "수치가 아니다"},
		{name: "repository_id 0", file: true, fileContent: "jun-bank/infra|0|wf@refs/heads/main|core\n", wantIn: "양의 정수"},
		{name: "repository_id 앞자리 0", file: true, fileContent: "jun-bank/infra|0123456|wf@refs/heads/main|core\n", wantIn: "앞자리 0"},
		{name: "target 닫힌 집합 밖", file: true, fileContent: "jun-bank/infra|123456|wf@refs/heads/main|oracle-edge\n", wantIn: "닫힌 집합"},
		{name: "repository_id 중복", file: true, wantIn: "repository_id 중복",
			fileContent: "jun-bank/infra|123456|wf-a@refs/heads/main|core\njun-bank/gateway|123456|wf-b@refs/heads/main|gateway\n"},
		{name: "target 중복(두 저장소가 같은 대상)", file: true, wantIn: "1:1",
			fileContent: "jun-bank/infra|123456|wf-a@refs/heads/main|core\njun-bank/gateway|777777|wf-b@refs/heads/main|core\n"},
		{name: "같은 이름·다른 ID(옛 줄 잔존)", file: true, wantIn: "이름 중복",
			fileContent: "jun-bank/infra|123456|wf-a@refs/heads/main|core\nJun-Bank/Infra|777777|wf-b@refs/heads/main|gateway\n"},
		{name: "줄 끝 주석은 지원하지 않는다(요란한 거부)", file: true, wantIn: "닫힌 집합",
			fileContent: "jun-bank/infra|123456|wf@refs/heads/main|core # 배포 저장소\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := singleModeEnv()
			if tc.file {
				env.allowlistFile = writeAllowlist(t, tc.fileContent)
				if !tc.coexist {
					clearSingleMode(&env)
				}
			}
			if tc.mutate != nil {
				tc.mutate(&env)
			}
			env.apply(t)

			_, err := LoadOIDCPolicy()
			if err == nil {
				t.Fatalf("%s: 기동이 거부되지 않았다 (fail-closed 기대 — 이 설정으로 뜨면 문이 반쯤 열린다)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("오류 메시지 = %q, %q를 담아야 한다 (원인이 기동 로그에서 바로 보여야 한다)", err, tc.wantIn)
			}
		})
	}
}

// clearSingleMode는 단일 env 세트를 전부 비운다(파일 모드 케이스의 전제).
func clearSingleMode(e *oidcEnv) {
	e.repository, e.repositoryID, e.jobWorkflowRef, e.allowedTarget = "", "", "", ""
}

// TestLoadOIDCPolicyDirectoryPathRefused는 경로가 파일이 아니라 디렉토리일 때도 기동을
// 거부하는지 확인한다(읽기 실패의 다른 얼굴 — 존재하지만 읽을 수 없다).
func TestLoadOIDCPolicyDirectoryPathRefused(t *testing.T) {
	env := singleModeEnv()
	clearSingleMode(&env)
	env.allowlistFile = t.TempDir() // 디렉토리
	env.apply(t)

	if _, err := LoadOIDCPolicy(); err == nil {
		t.Fatal("디렉토리 경로로 기동이 성공했다 (fail-closed 기대)")
	}
}

// TestLoadOIDCPolicySingleModeNormalized는 단일 env 세트가 1항목 allowlist로 정규화되는지
// 확인한다(rev.2 변경 ② — 무결박 모드를 남기지 않는다). 검증 코드 경로가 하나여야 A2가
// 모드와 무관하게 성립한다.
func TestLoadOIDCPolicySingleModeNormalized(t *testing.T) {
	singleModeEnv().apply(t)

	p, err := LoadOIDCPolicy()
	if err != nil {
		t.Fatalf("완전한 단일 env 세트로 기동이 거부됐다: %v", err)
	}
	if p.Allowlist.Len() != 1 {
		t.Fatalf("정규화된 항목 수 = %d, 기대 = 1", p.Allowlist.Len())
	}
	e, ok := p.Allowlist.lookup("123456")
	if !ok {
		t.Fatal("단일 세트의 repository_id로 조회되지 않는다")
	}
	if e.Target != deploy.TargetCore || e.Repository != "jun-bank/infra" {
		t.Errorf("정규화된 항목이 어긋났다: %+v", e)
	}
	// 저장소 세 칸이 allowlist로 옮겨졌어도 전역 공통 칸은 그대로다(A5).
	if p.OwnerID != "654321" || len(p.RefAllowlist) != 1 || p.Skew != DefaultClockSkew {
		t.Errorf("전역 공통 칸이 어긋났다: ownerID=%q refs=%v skew=%s", p.OwnerID, p.RefAllowlist, p.Skew)
	}
}

// TestLoadOIDCPolicyFileMode는 파일 모드의 정상 적재를 확인한다: 주석·빈 줄·정렬 공백·
// CRLF 줄끝을 견디고, 항목마다 자기 target을 싣는다.
func TestLoadOIDCPolicyFileMode(t *testing.T) {
	content := "# repository|repository_id|job_workflow_ref|target\r\n" +
		"\r\n" +
		"  jun-bank/infra | 123456 | jun-bank/infra/.github/workflows/deploy.yml@refs/heads/main | core \r\n" +
		"# gateway는 2026-08-12 등재(infra#28)\n" +
		"jun-bank/gateway|777777|jun-bank/gateway/.github/workflows/deploy.yml@refs/heads/main|gateway\n"

	env := singleModeEnv()
	clearSingleMode(&env)
	env.allowlistFile = writeAllowlist(t, content)
	env.apply(t)

	p, err := LoadOIDCPolicy()
	if err != nil {
		t.Fatalf("정상 allowlist 파일로 기동이 거부됐다: %v", err)
	}
	if p.Allowlist.Len() != 2 {
		t.Fatalf("적재된 항목 수 = %d, 기대 = 2", p.Allowlist.Len())
	}
	for _, want := range []OIDCAllowEntry{
		{Repository: "jun-bank/infra", RepositoryID: "123456", JobWorkflowRef: "jun-bank/infra/.github/workflows/deploy.yml@refs/heads/main", Target: deploy.TargetCore},
		{Repository: "jun-bank/gateway", RepositoryID: "777777", JobWorkflowRef: "jun-bank/gateway/.github/workflows/deploy.yml@refs/heads/main", Target: deploy.TargetGateway},
	} {
		got, ok := p.Allowlist.lookup(want.RepositoryID)
		if !ok {
			t.Errorf("repository_id %s가 적재되지 않았다", want.RepositoryID)
			continue
		}
		if got != want {
			t.Errorf("항목이 어긋났다(공백 trim 확인):\n 실제 = %+v\n 기대 = %+v", got, want)
		}
	}
}

// TestAsciiEqualFoldNotUnicode는 이름 대조가 ASCII 한정임을 못박는다. 유니코드 simple
// fold(strings.EqualFold)는 서로 다른 문자를 같다고 보므로(ſ↔s 등) 저장소 이름 대조에
// 쓰면 다른 이름이 같은 저장소로 판정될 수 있다.
func TestAsciiEqualFoldNotUnicode(t *testing.T) {
	if !asciiEqualFold("jun-bank/INFRA", "Jun-Bank/infra") {
		t.Error("ASCII 대소문자 차이가 다른 이름으로 판정됐다 (과잉 거절)")
	}
	// 대조군: strings.EqualFold는 아래 둘을 같다고 본다(유니코드 simple fold — ſ↔s).
	// 우리 비교는 그러면 안 된다 — 저장소 이름의 문자가 다르면 다른 저장소다.
	const asciiName = "jun-bank/infras"
	const unicodeName = "jun-bank/infraſ" // ſ = U+017F LATIN SMALL LETTER LONG S
	if !strings.EqualFold(asciiName, unicodeName) {
		t.Skip("이 Go 버전의 EqualFold가 ſ를 fold하지 않는다 — 대조군 전제가 성립하지 않는다")
	}
	if asciiEqualFold(asciiName, unicodeName) {
		t.Error("유니코드 fold로 다른 이름이 같다고 판정됐다 (ASCII 한정이어야 한다)")
	}
}
