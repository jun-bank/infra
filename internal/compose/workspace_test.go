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

// 승격은 배포 성공 뒤에만이고, applied[1]은 항상 "마지막 정상본"이다.
func TestPromoteKeepsLastGoodRevision(t *testing.T) {
	w := newWorkspace(t)
	rec := func(rev, slot string) AppliedRecord {
		return AppliedRecord{Revision: rev, Slot: slot, ImageDigest: "sha256:d" + rev[:3], Status: "applied"}
	}
	if err := w.Promote("core", rec(strings.Repeat("a", 64), "green")); err != nil {
		t.Fatalf("첫 승격 실패: %v", err)
	}
	if err := w.Promote("core", rec(strings.Repeat("b", 64), "blue")); err != nil {
		t.Fatalf("두 번째 승격 실패: %v", err)
	}
	list, err := w.Applied("core")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Revision != strings.Repeat("b", 64) || list[1].Revision != strings.Repeat("a", 64) {
		t.Fatalf("applied 목록이 최신순이 아니다: %+v", list)
	}

	// G-08: 같은 revision 재배포는 무변경이어야 한다 — 밀어넣으면 [1](직전 정상본)이 밀려
	// 나가 되돌릴 곳이 사라진다.
	if err := w.Promote("core", rec(strings.Repeat("b", 64), "blue")); err != nil {
		t.Fatal(err)
	}
	list, err = w.Applied("core")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[1].Revision != strings.Repeat("a", 64) {
		t.Fatalf("동일 revision 재승격이 직전 정상본을 밀어냈다: %+v", list)
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
	err := w.Promote("core", AppliedRecord{Revision: strings.Repeat("c", 64)})
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
	if err := w.Promote("core", AppliedRecord{Revision: revs[1]}); err != nil {
		t.Fatal(err)
	}
	if err := w.Promote("core", AppliedRecord{Revision: revs[0]}); err != nil {
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
