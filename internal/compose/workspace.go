package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// workspace — 검증을 통과한 바이트가 사는 곳(CP-2·CP-4 · 설계 rev.2.1 C1).
//
//	<root>/<target>/<slot>/compose.sha256-<64hex>.yml   불변 candidate — up이 -f로 읽는 파일
//	<root>/<target>/applied.json                        target 단위 단일 인덱스(성공 승격만)
//
// 두 가지가 설계의 핵심이고 재해석하지 않는다:
//
//   - **candidate는 불변이다.** 파일명이 내용의 full sha256이고 O_EXCL로 만든다 — 같은
//     이름의 기존 파일을 덮어쓰지 않으며, 내용이 같을 때만 재사용한다. "검증한 바이트"와
//     "실행되는 바이트" 사이에 덮어쓰기 창이 없다.
//   - **승격은 배포 성공 뒤에만.** applied.json은 실패한 candidate를 절대 담지 않으므로
//     applied[1]이 항상 "마지막 정상본"이다 — 수동 비상 복원의 재료가 이것이다(#23 ⓐ
//     불변: 자동 소비 경로는 없다. 사람이 이 목록과 로컬 잔존 이미지로 복원한다).
//
// ⚠️ TOCTOU 정직 서술(rev.2 F14): 기록 후 재해시는 저장 오류·자기 버그를 잡을 뿐이다.
// 실방어는 workspace 배타성(0700·소유 검사·상위 심볼릭 링크 금지)과 candidate 불변 경로다.

// 파일 모드 — G-15 선언값. workspace 디렉터리는 0700(배타성), candidate 파일은 0644
// (동봉 compose는 pass-through 목록만 담고 값을 담지 않으므로 시크릿이 아니다).
const (
	dirPerm       os.FileMode = 0o700
	candidatePerm os.FileMode = 0o644
	appliedPerm   os.FileMode = 0o644
)

// maxGenerations는 세대 파일 잔여 상한이다(rev.2.1 C1 선언값 — pin된 것은 이 상한과
// 무관하게 남는다).
const maxGenerations = 4

// maxAppliedRecords는 applied 인덱스에 남기는 이력 길이다(선언값 — [0]·[1]만 계약이고
// 나머지는 사람이 읽는 흔적이다).
const maxAppliedRecords = 16

// SlotSingle은 슬롯이 없는 단일 경로 배포의 슬롯 이름이다(디렉터리 이름으로 쓴다).
const SlotSingle = "single"

// candidatePrefix·candidateSuffix는 세대 파일명 규약이다: compose.sha256-<64hex>.yml.
const (
	candidatePrefix = "compose.sha256-"
	candidateSuffix = ".yml"
)

// ErrAppliedCorrupt는 applied 인덱스를 읽을 수 없음을 뜻한다(G-09) — 승격·GC를 **중단**하며
// (fail-safe no-op) 배포 결과 자체를 뒤집지는 않는다.
var ErrAppliedCorrupt = errors.New("compose: applied 인덱스 손상")

// Workspace는 검증된 workspace 루트다. Open이 배타성 계약을 확인한 뒤에만 만들어진다.
type Workspace struct {
	root string
	// uid는 Open 시점의 소유자 검사에 쓴 uid다(진단용).
	uid int
}

// Root는 workspace 루트 절대경로다(compose 실행의 --project-directory 산정에 쓰인다).
func (w *Workspace) Root() string { return w.root }

// Open은 workspace 루트를 열고 배타성 계약을 확인한다(IV-53): 절대경로·Clean·심볼릭 링크
// 없음·디렉터리·모드 0700·현재 uid 소유. 하나라도 어긋나면 기동을 막는다 — 이 전제가
// 무너지면 candidate 불변성이 "우리만 쓴다"에 기대지 못하고 재해시도 자기 위안이 된다.
func Open(root string) (*Workspace, error) {
	if root == "" {
		return nil, errf(CodeWorkspace, "workspace 경로가 비어 있다")
	}
	if !filepath.IsAbs(root) {
		return nil, errf(CodeWorkspace, "workspace 경로는 절대경로여야 한다: %q", root)
	}
	if filepath.Clean(root) != root {
		return nil, errf(CodeWorkspace, "workspace 경로가 정규형이 아니다: %q(기대 %q)", root, filepath.Clean(root))
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errf(CodeWorkspace, "workspace 경로 해소 실패: %q: %v", root, err)
	}
	if resolved != root {
		return nil, errf(CodeWorkspace, "workspace 경로에 심볼릭 링크가 있다: %q → %q(상위 심볼릭 링크 금지 — 배타성 전제)", root, resolved)
	}
	fi, err := os.Stat(root)
	if err != nil {
		return nil, errf(CodeWorkspace, "workspace 경로 stat 실패: %q: %v", root, err)
	}
	if !fi.IsDir() {
		return nil, errf(CodeWorkspace, "workspace 경로가 디렉터리가 아니다: %q", root)
	}
	if perm := fi.Mode().Perm(); perm != dirPerm {
		return nil, errf(CodeWorkspace, "workspace 디렉터리 모드가 %o가 아니다: %q는 %o(배타성 — 다른 사용자가 candidate를 바꿀 수 있으면 결박이 무의미하다)", dirPerm, root, perm)
	}
	uid := os.Getuid()
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if int(st.Uid) != uid {
			return nil, errf(CodeWorkspace, "workspace 디렉터리 소유자가 이 프로세스(uid=%d)가 아니다: %q는 uid=%d", uid, root, st.Uid)
		}
	}
	return &Workspace{root: root, uid: uid}, nil
}

// dir는 한 배포 단위(target·slot)의 디렉터리다 — 이 자리가 compose의 --project-directory다.
func (w *Workspace) dir(target, slot string) string {
	return filepath.Join(w.root, target, slot)
}

// CandidatePath는 revision hex에 대응하는 세대 파일 경로다(내용이 곧 이름 — full 64hex).
func (w *Workspace) CandidatePath(target, slot, revHex string) string {
	return filepath.Join(w.dir(target, slot), candidatePrefix+revHex+candidateSuffix)
}

// Candidate는 기록된 candidate의 실행 좌표다.
type Candidate struct {
	// Path는 up이 `-f`로 읽을 파일이다.
	Path string
	// ProjectDirectory는 compose의 `--project-directory`다(candidate가 있는 디렉터리 —
	// compose가 상대 경로·.env를 해석하는 기준을 workspace 안으로 고정한다).
	ProjectDirectory string
	// Reused는 같은 내용의 세대 파일이 이미 있어 재사용했음을 뜻한다(동일 revision 재배포).
	Reused bool
}

// WriteCandidate는 **검증을 통과한 바이트만** 불변 candidate로 기록한다(CP-1 마지막 단계).
// 순서와 각 단계의 이유:
//
//	⑴ 디렉터리 생성(0700) — 배타성.
//	⑵ `.env` 부재 확인 — compose는 --project-directory의 .env를 자동으로 읽는다. 그 파일이
//	   있으면 서명 밖 값이 실효 설정에 섞인다(B1' 위반). **기록 전**에 본다.
//	⑶ O_EXCL 생성 — 같은 이름(=같은 해시)의 파일이 있으면 덮어쓰지 않는다. 내용이 같으면
//	   재사용하고, 다르면 저장 무결성 장애다(해시 충돌이 아니라 저장 계층이 어긋난 것).
//	⑷ fsync(파일) → close → fsync(디렉터리) — 이름이 durable해야 재기동 후에도 같은 것을 읽는다.
//	⑸ 재해시 — 기록된 파일을 다시 읽어 revision과 대조한다. 불일치는 **검증 실패와 다른
//	   분류**(저장 무결성 장애)다: 요청은 옳았고 이 호스트가 잘못했다.
func (w *Workspace) WriteCandidate(target, slot, revHex string, content []byte) (Candidate, error) {
	if err := validRevHex(revHex); err != nil {
		return Candidate{}, err
	}
	dir := w.dir(target, slot)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return Candidate{}, errf(CodeWorkspace, "workspace 디렉터리 생성 실패: %q: %v", dir, err)
	}
	// MkdirAll은 umask를 거치므로 모드를 명시적으로 확정한다(0700 — 배타성).
	if err := os.Chmod(dir, dirPerm); err != nil {
		return Candidate{}, errf(CodeWorkspace, "workspace 디렉터리 모드 설정 실패: %q: %v", dir, err)
	}
	if err := w.CheckNoDotEnv(target, slot); err != nil {
		return Candidate{}, err
	}

	path := w.CandidatePath(target, slot, revHex)
	cand := Candidate{Path: path, ProjectDirectory: dir}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, candidatePerm)
	switch {
	case err == nil:
		if werr := writeAndSync(f, content); werr != nil {
			f.Close()
			return Candidate{}, werr
		}
		if cerr := f.Close(); cerr != nil {
			return Candidate{}, errf(CodeStorageIntegrity, "candidate 닫기 실패: %q: %v", path, cerr)
		}
		// 모드도 umask 영향을 받으므로 확정한다(G-15).
		if cerr := os.Chmod(path, candidatePerm); cerr != nil {
			return Candidate{}, errf(CodeStorageIntegrity, "candidate 모드 설정 실패: %q: %v", path, cerr)
		}
		if serr := syncDir(dir); serr != nil {
			return Candidate{}, serr
		}
	case errors.Is(err, os.ErrExist):
		// 같은 해시의 세대 파일이 이미 있다 — 덮어쓰지 않는다(불변). 내용이 같은지만 본다.
		cand.Reused = true
	default:
		return Candidate{}, errf(CodeStorageIntegrity, "candidate 생성 실패: %q: %v", path, err)
	}

	// ⑸ 재해시 — 재사용 경로에도 똑같이 적용된다(기존 파일이 정말 그 내용인지 증명한다).
	got, err := os.ReadFile(path) //nolint:gosec // 경로는 workspace 안에서 해시로 결정된다
	if err != nil {
		return Candidate{}, errf(CodeStorageIntegrity, "candidate 재읽기 실패: %q: %v", path, err)
	}
	if sum := sha256.Sum256(got); hex.EncodeToString(sum[:]) != revHex {
		return Candidate{}, errf(CodeStorageIntegrity, "기록된 candidate가 검증 바이트와 다르다: %q(기대 sha256=%s 실제=%x) — 저장 무결성 장애", path, revHex, sum)
	}
	return cand, nil
}

// CheckNoDotEnv는 실행 기준 디렉터리에 `.env`가 없음을 확인한다. **기록 전과 실행 직전**
// 두 번 부른다 — 그 사이에 생기면 서명 밖 값이 보간에 섞이기 때문이다(창을 좁히는 것이지
// 없애는 것은 아니다: 없애는 것은 workspace 배타성이다).
func (w *Workspace) CheckNoDotEnv(target, slot string) error {
	p := filepath.Join(w.dir(target, slot), ".env")
	if _, err := os.Lstat(p); err == nil {
		return errf(CodeWorkspace, "workspace 실행 디렉터리에 .env가 있다: %q — compose가 자동으로 읽어 서명 밖 값이 실효 설정에 섞인다(fail-closed)", p)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errf(CodeWorkspace, "workspace .env 확인 실패: %q: %v", p, err)
	}
	return nil
}

// writeAndSync는 내용을 쓰고 fsync한다(내용이 durable해야 재해시가 의미를 갖는다).
func writeAndSync(f *os.File, content []byte) error {
	if _, err := f.Write(content); err != nil {
		return errf(CodeStorageIntegrity, "candidate 기록 실패: %v", err)
	}
	if err := f.Sync(); err != nil {
		return errf(CodeStorageIntegrity, "candidate fsync 실패: %v", err)
	}
	return nil
}

// syncDir는 디렉터리 엔트리를 fsync한다 — 파일 내용만 fsync하면 이름이 durable하지 않다.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // workspace 내부 경로
	if err != nil {
		return errf(CodeStorageIntegrity, "workspace 디렉터리 열기 실패(fsync): %q: %v", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return errf(CodeStorageIntegrity, "workspace 디렉터리 fsync 실패: %q: %v", dir, err)
	}
	return nil
}

// AppliedRecord는 "성공적으로 적용된 한 배포"다. 수동 비상 복원이 이 한 행에서 출발한다 —
// 그래서 세대 파일 revision뿐 아니라 imageDigest와 **주입 변수 전체**를 함께 남긴다(그것이
// 없으면 같은 compose를 같은 값으로 다시 띄우지 못한다).
type AppliedRecord struct {
	Revision    string            `json:"revision"`
	Slot        string            `json:"slot"`
	ImageDigest string            `json:"imageDigest"`
	CommitSHA   string            `json:"commitSha"`
	RequestID   string            `json:"requestId"`
	TS          string            `json:"ts"`
	Injected    map[string]string `json:"injected"`
	Status      string            `json:"status"`
}

// appliedIndex는 target 단위 단일 인덱스 파일의 형태다(최신순).
type appliedIndex struct {
	Applied []AppliedRecord `json:"applied"`
}

// appliedPath는 target 단위 인덱스 파일 경로다(슬롯 단위가 아니다 — "직전 가동"은 슬롯을
// 가로질러 정의돼야 수동 복원이 성립한다).
func (w *Workspace) appliedPath(target string) string {
	return filepath.Join(w.root, target, "applied.json")
}

// Applied는 target의 적용 이력을 최신순으로 읽는다. 파일 부재는 빈 목록(첫 배포)이고,
// 깨진 JSON은 ErrAppliedCorrupt다 — 빈 목록으로 접으면 다음 승격이 "이전 정상본 없음"을
// 사실로 만들어 복원 재료를 조용히 지운다.
func (w *Workspace) Applied(target string) ([]AppliedRecord, error) {
	b, err := os.ReadFile(w.appliedPath(target)) //nolint:gosec // workspace 내부 경로
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: 읽기 실패 %q: %v", ErrAppliedCorrupt, w.appliedPath(target), err)
	}
	var idx appliedIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("%w: JSON 파싱 실패 %q: %v", ErrAppliedCorrupt, w.appliedPath(target), err)
	}
	return idx.Applied, nil
}

// Promote는 **배포가 성공한 뒤에만** 호출된다(B4' — 실패 candidate는 승격되지 않는다).
// 목록 맨 앞에 한 항을 넣고 단일 파일을 원자 교체한다 — 반쪽 승격 창이 없다.
//
// 같은 revision을 다시 배포한 경우(applied[0]과 revision이 같다)는 **무변경**이다(G-08):
// 재전송·재배포가 목록을 같은 값으로 밀어 [1](직전 정상본)을 밀어내면, 복원 재료가
// "같은 것 두 개"가 되어 되돌릴 곳이 사라진다.
func (w *Workspace) Promote(target string, rec AppliedRecord) error {
	cur, err := w.Applied(target)
	if err != nil {
		return err
	}
	if len(cur) > 0 && cur[0].Revision == rec.Revision {
		return nil
	}
	next := append([]AppliedRecord{rec}, cur...)
	if len(next) > maxAppliedRecords {
		next = next[:maxAppliedRecords]
	}
	b, err := json.MarshalIndent(appliedIndex{Applied: next}, "", "  ")
	if err != nil {
		return errf(CodeStorageIntegrity, "applied 인덱스 직렬화 실패: %v", err)
	}
	b = append(b, '\n')

	dir := filepath.Join(w.root, target)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return errf(CodeWorkspace, "target 디렉터리 생성 실패: %q: %v", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".applied-*.tmp")
	if err != nil {
		return errf(CodeStorageIntegrity, "applied 임시 파일 생성 실패: %q: %v", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 성공 시 no-op
	if werr := writeAndSync(tmp, b); werr != nil {
		tmp.Close()
		return werr
	}
	if cerr := tmp.Close(); cerr != nil {
		return errf(CodeStorageIntegrity, "applied 임시 파일 닫기 실패: %v", cerr)
	}
	if cerr := os.Chmod(tmpName, appliedPerm); cerr != nil {
		return errf(CodeStorageIntegrity, "applied 모드 설정 실패: %v", cerr)
	}
	if rerr := os.Rename(tmpName, w.appliedPath(target)); rerr != nil {
		return errf(CodeStorageIntegrity, "applied 원자 교체 실패: %v", rerr)
	}
	return syncDir(dir)
}

// GC는 세대 파일을 정리한다. pin 규칙이 요점이다(rev.2.1 C1):
//
//	applied[0]·applied[1]의 revision + 호출자가 준 pinned(실행 중 슬롯의 revision)은 **무조건 남긴다**.
//
// 이 pin이 없으면 실패 candidate가 연속으로 들어올 때 정상본이 잔여 상한에 밀려 지워진다 —
// 즉 "복원 재료 보존"이라는 목적 자체가 실패 배포에 의해 무너진다.
//
// applied 인덱스를 읽지 못하면(손상) 무엇을 pin해야 하는지 모른다 = **삭제 0으로 중단**한다
// (G-09/G-10 — 모르면 지우지 않는다).
func (w *Workspace) GC(target string, pinned []string) error {
	applied, err := w.Applied(target)
	if err != nil {
		return err
	}
	pin := map[string]bool{}
	for i, rec := range applied {
		if i >= 2 {
			break
		}
		pin[rec.Revision] = true
	}
	for _, r := range pinned {
		if r != "" {
			pin[r] = true
		}
	}

	type gen struct {
		path string
		rev  string
		mod  time.Time
	}
	var pinnedGens, others []gen
	targetDir := filepath.Join(w.root, target)
	slots, err := os.ReadDir(targetDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errf(CodeWorkspace, "target 디렉터리 조회 실패: %q: %v", targetDir, err)
	}
	for _, slotEnt := range slots {
		if !slotEnt.IsDir() {
			continue
		}
		slotDir := filepath.Join(targetDir, slotEnt.Name())
		files, ferr := os.ReadDir(slotDir)
		if ferr != nil {
			return errf(CodeWorkspace, "슬롯 디렉터리 조회 실패: %q: %v", slotDir, ferr)
		}
		for _, fe := range files {
			name := fe.Name()
			if fe.IsDir() || !strings.HasPrefix(name, candidatePrefix) || !strings.HasSuffix(name, candidateSuffix) {
				continue
			}
			rev := strings.TrimSuffix(strings.TrimPrefix(name, candidatePrefix), candidateSuffix)
			info, ierr := fe.Info()
			if ierr != nil {
				return errf(CodeWorkspace, "세대 파일 정보 조회 실패: %q: %v", filepath.Join(slotDir, name), ierr)
			}
			g := gen{path: filepath.Join(slotDir, name), rev: rev, mod: info.ModTime()}
			if pin[rev] {
				pinnedGens = append(pinnedGens, g)
			} else {
				others = append(others, g)
			}
		}
	}
	// 최신 것부터 남긴다 — 오래된 것이 먼저 지워진다.
	sort.Slice(others, func(i, j int) bool { return others[i].mod.After(others[j].mod) })
	keep := maxGenerations - len(pinnedGens)
	for i, g := range others {
		if i < keep {
			continue
		}
		if rerr := os.Remove(g.path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return errf(CodeWorkspace, "세대 파일 삭제 실패: %q: %v", g.path, rerr)
		}
	}
	return nil
}

// validRevHex는 revision이 소문자 64자 hex인지 본다(파일명이 되므로 경로 주입 방지이기도 하다).
func validRevHex(revHex string) error {
	if len(revHex) != 64 {
		return errf(CodeStorageIntegrity, "revision hex 길이가 64가 아니다: %d", len(revHex))
	}
	for _, c := range revHex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errf(CodeStorageIntegrity, "revision hex에 허용되지 않는 문자가 있다: %q", revHex)
		}
	}
	return nil
}
