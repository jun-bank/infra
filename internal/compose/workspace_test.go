package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newWorkspace는 계약(0700·소유·심볼릭 링크 없음)을 만족하는 workspace를 만든다.
func newWorkspace(t *testing.T) *Workspace {
	t.Helper()
	// t.TempDir()의 상위(예: macOS /var → /private/var)에 심볼릭 링크가 있을 수 있으므로
	// 해소된 경로로 연다 — 검사 대상은 우리가 만든 디렉터리다.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "ws")
	if mkErr := os.Mkdir(root, 0o700); mkErr != nil {
		t.Fatal(mkErr)
	}
	w, err := Open(root)
	if err != nil {
		t.Fatalf("workspace 열기 실패: %v", err)
	}
	return w
}

func revOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// Open은 배타성 계약을 강제한다 — 이 전제가 없으면 candidate 불변성이 "우리만 쓴다"에
// 기대지 못한다.
func TestOpenEnforcesExclusivity(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("상대 경로 거절", func(t *testing.T) {
		if _, err := Open("relative/ws"); CodeOf(err) != CodeWorkspace {
			t.Fatalf("코드=%q, %q 기대: %v", CodeOf(err), CodeWorkspace, err)
		}
	})
	t.Run("비정규형 거절", func(t *testing.T) {
		if _, err := Open(base + "/./ws"); CodeOf(err) != CodeWorkspace {
			t.Fatalf("코드=%q, %q 기대: %v", CodeOf(err), CodeWorkspace, err)
		}
	})
	t.Run("모드 0755 거절", func(t *testing.T) {
		loose := filepath.Join(base, "loose")
		if err := os.Mkdir(loose, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(loose); CodeOf(err) != CodeWorkspace {
			t.Fatalf("0755 workspace가 통과했다(다른 사용자가 candidate를 바꿀 수 있다): %v", err)
		}
	})
	t.Run("심볼릭 링크 거절", func(t *testing.T) {
		real := filepath.Join(base, "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(real, link); err != nil {
			t.Skipf("심볼릭 링크 불가: %v", err)
		}
		if _, err := Open(link); CodeOf(err) != CodeWorkspace {
			t.Fatalf("심볼릭 링크 workspace가 통과했다: %v", err)
		}
	})
	t.Run("파일 거절", func(t *testing.T) {
		f := filepath.Join(base, "file")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(f); CodeOf(err) != CodeWorkspace {
			t.Fatalf("파일이 workspace로 통과했다: %v", err)
		}
	})
}

// candidate는 내용이 곧 이름이고(full 64hex) O_EXCL로 만들어진다 — 같은 이름의 파일을
// 덮어쓰지 않으며 내용이 다르면 저장 무결성 장애다.
func TestWriteCandidateImmutable(t *testing.T) {
	w := newWorkspace(t)
	content := []byte("services:\n  app:\n    image: x\n")
	rev := revOf(content)

	cand, err := w.WriteCandidate("core", "green", rev, content)
	if err != nil {
		t.Fatalf("candidate 기록 실패: %v", err)
	}
	if filepath.Base(cand.Path) != "compose.sha256-"+rev+".yml" {
		t.Fatalf("파일명=%q — 내용의 full 해시여야 한다", filepath.Base(cand.Path))
	}
	if cand.ProjectDirectory != filepath.Dir(cand.Path) {
		t.Fatalf("--project-directory=%q, candidate 디렉터리 기대", cand.ProjectDirectory)
	}
	if cand.Reused {
		t.Fatal("첫 기록인데 Reused=true")
	}
	// G-15: candidate 0644 · workspace 디렉터리 0700.
	fi, err := os.Stat(cand.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != candidatePerm {
		t.Fatalf("candidate 모드=%o, %o 기대", fi.Mode().Perm(), candidatePerm)
	}
	di, err := os.Stat(cand.ProjectDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != dirPerm {
		t.Fatalf("workspace 디렉터리 모드=%o, %o 기대", di.Mode().Perm(), dirPerm)
	}

	// 같은 내용 재배포 — 재사용이고 파일은 그대로다.
	again, err := w.WriteCandidate("core", "green", rev, content)
	if err != nil {
		t.Fatalf("동일 내용 재기록 실패: %v", err)
	}
	if !again.Reused {
		t.Fatal("같은 해시 파일이 있는데 Reused=false — O_EXCL 경로를 타지 않았다")
	}

	// 저장이 어긋난 상황: 같은 이름인데 내용이 다르다 = 저장 무결성 장애(검증 실패와 별도 분류).
	if err := os.WriteFile(cand.Path, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = w.WriteCandidate("core", "green", rev, content)
	if CodeOf(err) != CodeStorageIntegrity {
		t.Fatalf("코드=%q, %q 기대(바이트는 옳았고 저장이 어긋났다): %v", CodeOf(err), CodeStorageIntegrity, err)
	}
	// 그리고 덮어쓰지 않았다 — 불변 계약(내용이 다른 기존 파일을 조용히 교체하지 않는다).
	got, rerr := os.ReadFile(cand.Path)
	if rerr != nil || string(got) != "tampered\n" {
		t.Fatalf("기존 파일이 덮어써졌다: %q err=%v", got, rerr)
	}
}

// 실행 기준 디렉터리의 .env는 서명 밖 값을 보간에 끌어들인다 — 기록 전에 막는다.
func TestWriteCandidateRejectsDotEnv(t *testing.T) {
	w := newWorkspace(t)
	dir := filepath.Join(w.Root(), "core", "green")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DEPLOY_IMAGE_REF=evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := []byte("services: {}\n")
	before := snapshot(t, w.Root())
	_, err := w.WriteCandidate("core", "green", revOf(content), content)
	if CodeOf(err) != CodeWorkspace {
		t.Fatalf("코드=%q, %q 기대: %v", CodeOf(err), CodeWorkspace, err)
	}
	// 부작용 0 — .env 거절은 **기록 전**이므로 트리가 바뀌지 않아야 한다.
	if after := snapshot(t, w.Root()); after != before {
		t.Fatalf(".env 거절이 파일을 남겼다:\n전=%s\n후=%s", before, after)
	}
}

// rec는 검증을 통과하는 온전한 record를 만든다(복원 재료로서 의미가 서는 최소 형태).
func rec(rev, slot, digestSeed, request string) AppliedRecord {
	return AppliedRecord{
		Revision:    rev,
		Slot:        slot,
		ImageDigest: "sha256:" + strings.Repeat(digestSeed, 64),
		CommitSHA:   "c1",
		RequestID:   request,
		TS:          "2026-08-13T00:00:00Z",
		Injected:    map[string]string{"DEPLOY_HOST_PORT": "18080"},
		Status:      StatusApplied,
	}
}

// 승격은 배포 성공 뒤에만이고, applied[1]은 항상 "마지막 정상본"이다.
func TestPromoteKeepsLastGoodRevision(t *testing.T) {
	w := newWorkspace(t)
	revA, revB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := w.Promote("core", rec(revA, "green", "1", "req-1")); err != nil {
		t.Fatalf("첫 승격 실패: %v", err)
	}
	if err := w.Promote("core", rec(revB, "blue", "2", "req-2")); err != nil {
		t.Fatalf("두 번째 승격 실패: %v", err)
	}
	list, err := w.Applied("core")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Revision != revB || list[1].Revision != revA {
		t.Fatalf("applied 목록이 최신순이 아니다: %+v", list)
	}
}

// E-1: 승격의 no-op 판정은 revision이 **아니라 record 전체 상태**로 갈린다.
//
// compose 정의는 릴리스마다 바뀌지 않는다 — 같은 compose에 새 이미지를 올리는 것이 정상
// 배포의 대다수다. revision만 비교하면 그 전부가 "같은 것"으로 접혀 승격이 통째로 삼켜지고,
// applied[0]의 imageDigest가 옛 릴리스에 머문 채 복원 재료가 거짓이 된다.
func TestPromoteRecordIdentity(t *testing.T) {
	revA := strings.Repeat("a", 64)

	t.Run("같은 compose + 새 이미지 = 새 record", func(t *testing.T) {
		w := newWorkspace(t)
		if err := w.Promote("core", rec(revA, "green", "1", "req-1")); err != nil {
			t.Fatal(err)
		}
		newImage := rec(revA, "green", "2", "req-2") // revision 동일 · digest만 다르다
		if err := w.Promote("core", newImage); err != nil {
			t.Fatal(err)
		}
		list, err := w.Applied("core")
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 {
			t.Fatalf("새 이미지 승격이 삼켜졌다(record %d개) — applied[0]이 옛 릴리스에 머문다: %+v", len(list), list)
		}
		if list[0].ImageDigest != newImage.ImageDigest {
			t.Fatalf("applied[0].imageDigest=%q, 방금 배포한 %q 기대", list[0].ImageDigest, newImage.ImageDigest)
		}
		if list[1].ImageDigest == newImage.ImageDigest {
			t.Fatal("직전 정상본이 새 것으로 덮였다")
		}
	})

	t.Run("완전 동일 replay = 무변경", func(t *testing.T) {
		w := newWorkspace(t)
		same := rec(revA, "green", "1", "req-1")
		if err := w.Promote("core", same); err != nil {
			t.Fatal(err)
		}
		if err := w.Promote("core", rec(strings.Repeat("b", 64), "blue", "2", "req-0")); err != nil {
			t.Fatal(err)
		}
		// 맨 앞을 다시 same으로 만들고, 같은 요청을 한 번 더 민다.
		if err := w.Promote("core", same); err != nil {
			t.Fatal(err)
		}
		before, _ := w.Applied("core")
		if err := w.Promote("core", same); err != nil {
			t.Fatal(err)
		}
		after, _ := w.Applied("core")
		if len(after) != len(before) {
			t.Fatalf("완전 동일 replay가 목록을 늘렸다: %d → %d", len(before), len(after))
		}
		if after[0].TS != before[0].TS || after[0].RequestID != before[0].RequestID {
			t.Fatalf("완전 동일 replay가 [0]을 건드렸다: %+v → %+v", before[0], after[0])
		}
	})

	t.Run("상태 동일 + 새 requestId = [0] 제자리 갱신·[1] 불변", func(t *testing.T) {
		w := newWorkspace(t)
		old := rec(strings.Repeat("c", 64), "blue", "3", "req-0")
		if err := w.Promote("core", old); err != nil {
			t.Fatal(err)
		}
		first := rec(revA, "green", "1", "req-1")
		if err := w.Promote("core", first); err != nil {
			t.Fatal(err)
		}
		again := first
		again.RequestID = "req-2"
		again.TS = "2026-08-13T01:00:00Z"
		if err := w.Promote("core", again); err != nil {
			t.Fatal(err)
		}
		list, err := w.Applied("core")
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 {
			t.Fatalf("제자리 갱신이 아니라 목록이 늘었다: %+v", list)
		}
		if list[0].RequestID != "req-2" || list[0].TS != again.TS {
			t.Fatalf("[0]의 추적 메타가 갱신되지 않았다: %+v", list[0])
		}
		if list[1].Revision != old.Revision || list[1].RequestID != "req-0" {
			t.Fatalf("직전 정상본이 밀려났다: %+v", list[1])
		}
	})
}

// W-06: 승격의 원자성. rename **직전**에 끊어도 원본은 온전해야 하고, 재기동 후 그대로
// 파싱돼야 한다 — 그렇지 않으면 "반쪽 승격 창이 없다"가 성립하지 않는다.
func TestPromoteAtomicityOnCrashBeforeRename(t *testing.T) {
	w := newWorkspace(t)
	good := rec(strings.Repeat("a", 64), "green", "1", "req-1")
	if err := w.Promote("core", good); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(w.Root(), "core", "applied.json"))
	if err != nil {
		t.Fatal(err)
	}

	boom := errors.New("rename 직전 중단(시험 주입)")
	w.beforeRename = func() error { return boom }
	if perr := w.Promote("core", rec(strings.Repeat("b", 64), "blue", "2", "req-2")); !errors.Is(perr, boom) {
		t.Fatalf("주입한 중단이 전파되지 않았다: %v", perr)
	}
	w.beforeRename = nil

	// ⑴ 원본이 그대로다(바이트 단위).
	after, err := os.ReadFile(filepath.Join(w.Root(), "core", "applied.json"))
	if err != nil {
		t.Fatalf("중단 후 원본이 사라졌다: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("중단이 원본을 바꿨다:\n전=%s\n후=%s", before, after)
	}
	// ⑵ 재기동(재파싱)이 여전히 유효하다 — 손상으로 읽히지 않는다.
	list, lerr := w.Applied("core")
	if lerr != nil {
		t.Fatalf("중단 후 인덱스가 손상으로 읽힌다: %v", lerr)
	}
	if len(list) != 1 || list[0].Revision != good.Revision {
		t.Fatalf("중단 후 내용이 바뀌었다: %+v", list)
	}
	// ⑶ temp 잔재가 남더라도 인덱스 파일이 아니다(정리는 defer가 하지만, 남아도 무해함을 못박는다).
	ents, _ := os.ReadDir(filepath.Join(w.Root(), "core"))
	for _, e := range ents {
		if e.Name() != "applied.json" && !strings.HasPrefix(e.Name(), ".applied-") {
			t.Fatalf("예상 밖 파일이 남았다: %q", e.Name())
		}
	}
}

// E-3/W-09: 파일 **부재만이** 첫 배포다. 파일이 있는데 의미가 서지 않으면 전부 손상이며,
// 손상은 승격·GC를 중단시킨다 — 빈 목록으로 접으면 다음 승격이 "직전 정상본 없음"을
// 사실로 만들어 복원할 곳을 조용히 지운다.
func TestAppliedIndexSemanticValidation(t *testing.T) {
	validRec := `{"revision":"` + strings.Repeat("a", 64) + `","slot":"green","imageDigest":"sha256:` + strings.Repeat("1", 64) + `","commitSha":"c1","requestId":"r1","ts":"t","injected":{},"status":"applied"}`

	cases := []struct {
		name    string
		content string
	}{
		{"깨진 JSON", "{not json"},
		{"빈 객체", "{}"},
		{"빈 배열", `{"applied":[]}`},
		{"applied null", `{"applied":null}`},
		{"중복 키", `{"applied":[],"applied":[` + validRec + `]}`},
		{"record 중복 키", `{"applied":[{"revision":"x","revision":"y"}]}`},
		{"미지 최상위 필드", `{"applied":[` + validRec + `],"extra":1}`},
		{"미지 record 필드", `{"applied":[{"revision":"` + strings.Repeat("a", 64) + `","slot":"green","imageDigest":"sha256:` + strings.Repeat("1", 64) + `","status":"applied","rogue":1}]}`},
		{"후행 데이터", `{"applied":[` + validRec + `]}{"applied":[]}`},
		{"revision 형식 위반", `{"applied":[{"revision":"abc","slot":"green","imageDigest":"sha256:` + strings.Repeat("1", 64) + `","status":"applied"}]}`},
		{"revision 대문자", `{"applied":[{"revision":"` + strings.Repeat("A", 64) + `","slot":"green","imageDigest":"sha256:` + strings.Repeat("1", 64) + `","status":"applied"}]}`},
		{"slot 닫힌 집합 밖", `{"applied":[{"revision":"` + strings.Repeat("a", 64) + `","slot":"purple","imageDigest":"sha256:` + strings.Repeat("1", 64) + `","status":"applied"}]}`},
		{"slot 빈 값", `{"applied":[{"revision":"` + strings.Repeat("a", 64) + `","slot":"","imageDigest":"sha256:` + strings.Repeat("1", 64) + `","status":"applied"}]}`},
		{"digest 형식 위반", `{"applied":[{"revision":"` + strings.Repeat("a", 64) + `","slot":"green","imageDigest":"latest","status":"applied"}]}`},
		{"status 다른 값", `{"applied":[{"revision":"` + strings.Repeat("a", 64) + `","slot":"green","imageDigest":"sha256:` + strings.Repeat("1", 64) + `","status":"pending"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorkspace(t)
			dir := filepath.Join(w.Root(), "core")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "applied.json"), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Applied("core"); !errors.Is(err, ErrAppliedCorrupt) {
				t.Fatalf("손상으로 읽히지 않았다: %v", err)
			}
			// 손상이면 승격·GC 둘 다 중단이다(삭제 0).
			if err := w.Promote("core", rec(strings.Repeat("b", 64), "blue", "2", "r2")); !errors.Is(err, ErrAppliedCorrupt) {
				t.Fatalf("손상인데 승격이 진행됐다: %v", err)
			}
			if err := w.GC("core", nil); !errors.Is(err, ErrAppliedCorrupt) {
				t.Fatalf("손상인데 GC가 진행됐다: %v", err)
			}
		})
	}

	t.Run("파일 부재 = 첫 승격", func(t *testing.T) {
		w := newWorkspace(t)
		list, err := w.Applied("core")
		if err != nil || len(list) != 0 {
			t.Fatalf("부재가 첫 배포로 읽히지 않았다: list=%+v err=%v", list, err)
		}
		if err := w.Promote("core", rec(strings.Repeat("a", 64), "green", "1", "r1")); err != nil {
			t.Fatalf("첫 승격이 막혔다: %v", err)
		}
	})
}

// W-07: applied·candidate는 target별로 격리된다 — 한 대상의 이력이 다른 대상의 복원 재료나
// GC pin 판정에 섞이면 "이 대상의 직전 정상본"이 거짓이 된다.
func TestTargetScopeIsolation(t *testing.T) {
	w := newWorkspace(t)
	if err := w.Promote("core", rec(strings.Repeat("a", 64), "green", "1", "r1")); err != nil {
		t.Fatal(err)
	}
	gwList, err := w.Applied("gateway")
	if err != nil || len(gwList) != 0 {
		t.Fatalf("다른 대상의 이력이 새어 들어왔다: %+v err=%v", gwList, err)
	}

	content := []byte("services: {}\n")
	rev := revOf(content)
	if _, err := w.WriteCandidate("core", "green", rev, content); err != nil {
		t.Fatal(err)
	}
	if _, serr := os.Stat(w.CandidatePath("gateway", "green", rev)); !os.IsNotExist(serr) {
		t.Fatalf("candidate가 대상 경계를 넘었다: %v", serr)
	}
	// gateway 쪽 GC는 core의 세대 파일을 건드리지 않는다.
	if err := w.GC("gateway", nil); err != nil {
		t.Fatal(err)
	}
	if _, serr := os.Stat(w.CandidatePath("core", "green", rev)); serr != nil {
		t.Fatalf("다른 대상의 GC가 core 세대를 지웠다: %v", serr)
	}
}

// G-09: applied 손상은 승격·GC를 중단시킨다(fail-safe no-op) — 빈 목록으로 접으면
// "이전 정상본 없음"이 사실이 되어 복원 재료가 조용히 사라진다.
func TestCorruptAppliedStopsPromoteAndGC(t *testing.T) {
	w := newWorkspace(t)
	dir := filepath.Join(w.Root(), "core")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "applied.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := w.Promote("core", rec(strings.Repeat("c", 64), "green", "1", "r1"))
	if !errors.Is(err, ErrAppliedCorrupt) {
		t.Fatalf("손상 인덱스인데 승격이 진행됐다: %v", err)
	}
	if err := w.GC("core", nil); !errors.Is(err, ErrAppliedCorrupt) {
		t.Fatalf("손상 인덱스인데 GC가 진행됐다: %v", err)
	}
}

// GC의 pin 규칙 — applied[0]·[1]과 실행 중 슬롯 revision은 잔여 상한과 무관하게 남는다.
// 이것이 없으면 실패 candidate가 연속으로 들어올 때 정상본이 밀려 지워진다.
func TestGCPinsLastGoodAndRunning(t *testing.T) {
	w := newWorkspace(t)
	write := func(n int) string {
		content := []byte(strings.Repeat("x", n) + "\n")
		rev := revOf(content)
		if _, err := w.WriteCandidate("core", "green", rev, content); err != nil {
			t.Fatalf("candidate 기록 실패: %v", err)
		}
		return rev
	}
	// 8세대를 쌓고, 그 중 가장 오래된 둘을 정상본으로, 하나를 실행 중으로 pin한다.
	var revs []string
	for i := 1; i <= 8; i++ {
		revs = append(revs, write(i))
		// mtime 순서를 확정한다(같은 나노초에 몰려 정렬이 흔들리지 않게).
		p := w.CandidatePath("core", "green", revs[len(revs)-1])
		touch(t, p, i)
	}
	if err := w.Promote("core", rec(revs[1], "green", "1", "r1")); err != nil {
		t.Fatal(err)
	}
	if err := w.Promote("core", rec(revs[0], "green", "2", "r2")); err != nil {
		t.Fatal(err)
	}
	running := revs[2]
	if err := w.GC("core", []string{running}); err != nil {
		t.Fatalf("GC 실패: %v", err)
	}
	for _, rev := range []string{revs[0], revs[1], running} {
		if _, err := os.Stat(w.CandidatePath("core", "green", rev)); err != nil {
			t.Fatalf("pin된 세대가 지워졌다(rev=%s): %v", rev[:8], err)
		}
	}
	// pin 3개 + 잔여 상한 4 = 최대 4개가 남는다(pin은 상한 안에 든다 — 상한을 넘겨 늘리지 않는다).
	left := countGenerations(t, filepath.Join(w.Root(), "core", "green"))
	if left > maxGenerations {
		t.Fatalf("GC 후 세대 %d개 — 상한 %d 초과", left, maxGenerations)
	}
}

// 승격은 배포 성공 뒤에만 — candidate 기록만으로는 applied가 바뀌지 않는다.
func TestWriteCandidateDoesNotPromote(t *testing.T) {
	w := newWorkspace(t)
	content := []byte("services: {}\n")
	if _, err := w.WriteCandidate("core", "green", revOf(content), content); err != nil {
		t.Fatal(err)
	}
	list, err := w.Applied("core")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("기록만 했는데 승격됐다: %+v", list)
	}
}

// touch는 세대 파일의 mtime을 결정적으로 벌린다 — GC 정렬(오래된 것부터 제거)이 같은
// 나노초에 몰린 파일들 사이에서 흔들리지 않게 한다(seq가 클수록 최신).
func touch(t *testing.T, path string, seq int) {
	t.Helper()
	mod := time.Unix(1_700_000_000+int64(seq)*60, 0)
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func countGenerations(t *testing.T, dir string) int {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), candidatePrefix) {
			n++
		}
	}
	return n
}

// W-09(pin 실패 = 삭제 0): pin 대상을 확정하지 못하면 GC는 **아무것도 지우지 않는다**.
// "모르면 지우지 않는다"가 성립하지 않으면, 인덱스가 깨진 순간 복원 재료가 함께 사라진다.
func TestGCStopsWithoutDeletingWhenPinUnknown(t *testing.T) {
	w := newWorkspace(t)
	var paths []string
	for i := 1; i <= 6; i++ {
		content := []byte(strings.Repeat("y", i) + "\n")
		cand, err := w.WriteCandidate("core", "green", revOf(content), content)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, cand.Path)
	}
	dir := filepath.Join(w.Root(), "core")
	if err := os.WriteFile(filepath.Join(dir, "applied.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := w.GC("core", nil); !errors.Is(err, ErrAppliedCorrupt) {
		t.Fatalf("손상 인덱스인데 GC가 진행됐다: %v", err)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("pin 확정 실패인데 세대가 지워졌다: %q: %v", p, err)
		}
	}
}
