package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// applied.json은 0600이다 — candidate와 달리 **주입 변수의 실값**(등재 config 키의
	// 호스트 값)을 담기 때문이다. 시크릿은 애초에 여기 오면 안 되지만(CF-6), 값이 담기는
	// 파일을 값이 담기지 않는 파일과 같은 모드로 두지 않는다.
	appliedPerm os.FileMode = 0o600
	// 스냅샷은 실행 전용 임시 파일이라 candidate보다 좁게 연다(값을 담지 않지만, 수명이
	// 짧고 아무도 읽을 필요가 없는 파일을 굳이 넓게 열 이유가 없다).
	snapshotPerm os.FileMode = 0o600
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
	// beforeRename은 applied 원자 교체 직전에 불리는 시험용 훅이다(테스트 전용 — 프로덕션 nil).
	beforeRename func() error
}

// StatusApplied는 정상 승격된 record의 상태값이다(닫힌 값 — 다른 값은 손상으로 읽는다).
const StatusApplied = "applied"

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

// snapshotDir는 실행 중 잠깐만 사는 파일들이 모이는 자리다(세대·인덱스와 분리). 이 격리가
// 필요한 이유: 세대 파일은 "내용이 곧 이름"이고 applied 인덱스는 "성공한 것만"인데, 스냅샷은
// 둘 다 아니다 — 같은 디렉터리에 섞으면 GC와 복원 재료 판정이 임시 파일을 세게 된다.
const snapshotDir = "tmp"

// WriteSnapshot은 **이미 검증된 바이트 버퍼**를 실행 전용 임시 파일로 고정한다.
//
// 무엇을 막는가: 검증(재해시)과 사용(compose 실행) 사이의 창이다. 세대 파일 경로를 그대로
// 실행기에 넘기면, 검증한 순간과 `docker compose`가 그 파일을 여는 순간 사이에 내용이 바뀔
// 수 있다 — 그 사이에는 idle 기동·헬스·라우트 전환·드레인이 통째로 들어간다(초 단위가 아니라
// 분 단위 창이다). 재검증 시점을 뒤로 미루는 것으로는 창이 좁아질 뿐 없어지지 않는다.
// 검증한 **바이트 자체**를 별도 파일로 굳혀 실행기에 결박하면, 원본이 그 뒤 어떻게 바뀌든
// 실행되는 내용은 검증된 것 그대로다.
//
// name은 호출자가 만드는 파일시스템 안전 문자열이다(경로 구분자·`..` 금지 — 여기서 검사한다).
// 같은 이름이 이미 있으면 내용이 같을 때만 재사용한다(중단된 시도의 잔재로 재전송이 막히지
// 않게 하되, 다른 내용이면 거절 — candidate와 같은 규칙).
func (w *Workspace) WriteSnapshot(target, name string, content []byte) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", errf(CodeWorkspace, "스냅샷 이름이 안전하지 않다: %q", name)
	}
	dir := filepath.Join(w.root, target, snapshotDir)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return "", errf(CodeStorageIntegrity, "스냅샷 디렉터리 생성 실패: %q: %v", dir, err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		return "", errf(CodeStorageIntegrity, "스냅샷 디렉터리 모드 설정 실패: %q: %v", dir, err)
	}
	path := filepath.Join(dir, name)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, snapshotPerm)
	switch {
	case err == nil:
		if werr := writeAndSync(f, content); werr != nil {
			f.Close()
			return "", werr
		}
		if cerr := f.Close(); cerr != nil {
			return "", errf(CodeStorageIntegrity, "스냅샷 닫기 실패: %q: %v", path, cerr)
		}
		if cerr := os.Chmod(path, snapshotPerm); cerr != nil {
			return "", errf(CodeStorageIntegrity, "스냅샷 모드 설정 실패: %q: %v", path, cerr)
		}
		if serr := syncDir(dir); serr != nil {
			return "", serr
		}
	case errors.Is(err, os.ErrExist):
		// 중단된 앞선 시도의 잔재 — 내용이 같을 때만 재사용한다.
	default:
		return "", errf(CodeStorageIntegrity, "스냅샷 생성 실패: %q: %v", path, err)
	}

	got, rerr := os.ReadFile(path) //nolint:gosec // workspace 안의 우리가 만든 경로
	if rerr != nil {
		return "", errf(CodeStorageIntegrity, "스냅샷 재읽기 실패: %q: %v", path, rerr)
	}
	if !bytes.Equal(got, content) {
		return "", errf(CodeStorageIntegrity, "기록된 스냅샷이 검증 바이트와 다르다: %q — 저장 무결성 장애", path)
	}
	return path, nil
}

// RemoveSnapshot은 실행이 끝난 스냅샷을 지운다(성공·실패 무관). 실패해도 오류를 올리지
// 않는 이유: 이 파일은 tmp에 격리돼 있어 잔존해도 세대 회전·applied 인덱스·GC 어디에도
// 들지 않고, 다음 실행은 같은 내용이면 재사용하고 다르면 거절한다 — 정리 실패가 배포
// 결과를 뒤집을 근거가 없다.
func (w *Workspace) RemoveSnapshot(path string) {
	if path == "" {
		return
	}
	_ = os.Remove(path)
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

// appliedSlots는 record의 slot이 가질 수 있는 닫힌 값이다.
var appliedSlots = map[string]bool{"blue": true, "green": true, SlotSingle: true}

// Applied는 target의 적용 이력을 최신순으로 읽는다. **파일 부재만이 "첫 배포"**이고,
// 파일이 있는데 의미가 서지 않으면(파싱 불가·중복 키·미지 필드·빈 목록·record 필드 위반)
// 전부 ErrAppliedCorrupt다.
//
// 이 구분이 엄격한 이유: 이 목록은 수동 비상 복원의 유일한 재료다. 손상을 "빈 목록"으로
// 접으면 다음 승격이 그 자리에 새 record 하나만 남기고, 그 순간 **직전 정상본이 존재한
// 적 없다는 것이 사실이 된다** — 복원할 곳이 조용히 사라진다. 그래서 빈 배열·`{}`도
// 부재가 아니라 손상으로 읽는다: 정상 경로는 빈 목록을 기록하지 않으므로, 빈 목록이
// 파일로 존재한다는 것 자체가 무언가 잘못됐다는 신호다.
func (w *Workspace) Applied(target string) ([]AppliedRecord, error) {
	path := w.appliedPath(target)
	b, err := os.ReadFile(path) //nolint:gosec // workspace 내부 경로
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: 읽기 실패 %q: %v", ErrAppliedCorrupt, path, err)
	}
	if derr := rejectDuplicateJSONKeys(b); derr != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrAppliedCorrupt, path, derr)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var idx appliedIndex
	if derr := dec.Decode(&idx); derr != nil {
		return nil, fmt.Errorf("%w: JSON 파싱 실패 %q: %v", ErrAppliedCorrupt, path, derr)
	}
	if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
		return nil, fmt.Errorf("%w: 첫 JSON 값 뒤에 데이터가 남아 있다 %q", ErrAppliedCorrupt, path)
	}
	if len(idx.Applied) == 0 {
		return nil, fmt.Errorf("%w: applied 목록이 비어 있다 %q — 정상 경로는 빈 목록을 기록하지 않는다(부재가 아니라 손상)", ErrAppliedCorrupt, path)
	}
	for i, rec := range idx.Applied {
		if verr := rec.valid(); verr != nil {
			return nil, fmt.Errorf("%w: applied[%d] %q: %v", ErrAppliedCorrupt, i, path, verr)
		}
	}
	return idx.Applied, nil
}

// valid는 한 record가 복원 재료로서 의미가 서는지 본다. 형식만 맞고 값이 비어 있는 record는
// "무엇을 어느 슬롯에 어떤 이미지로 띄웠는가"에 답하지 못하므로 복원에 쓸 수 없다.
func (r AppliedRecord) valid() error {
	if err := validRevHex(r.Revision); err != nil {
		return fmt.Errorf("revision: %v", err)
	}
	if !appliedSlots[r.Slot] {
		return fmt.Errorf("slot이 닫힌 집합 밖이다: %q", r.Slot)
	}
	hex, ok := strings.CutPrefix(r.ImageDigest, "sha256:")
	if !ok || validRevHex(hex) != nil {
		return fmt.Errorf("imageDigest가 sha256:<64소문자hex>가 아니다: %q", r.ImageDigest)
	}
	if r.Status != StatusApplied {
		return fmt.Errorf("status가 %q가 아니다: %q", StatusApplied, r.Status)
	}
	return nil
}

// rejectDuplicateJSONKeys는 중복 키를 토큰 수준에서 거절한다(중첩 포함). encoding/json의
// 구조체 디코드는 중복 키에서 뒤엣것을 조용히 채택하므로, 손상된(또는 조작된) 인덱스가
// "읽히기는 하는" 상태로 통과한다.
func rejectDuplicateJSONKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return scanJSONValue(dec)
}

func scanJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("JSON 토큰 읽기 실패: %v", err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, kerr := dec.Token()
			if kerr != nil {
				return fmt.Errorf("JSON 키 읽기 실패: %v", kerr)
			}
			key, kok := kt.(string)
			if !kok {
				return fmt.Errorf("JSON 객체 키가 문자열이 아니다")
			}
			if seen[key] {
				return fmt.Errorf("중복 키: %q", key)
			}
			seen[key] = true
			if verr := scanJSONValue(dec); verr != nil {
				return verr
			}
		}
	case '[':
		for dec.More() {
			if verr := scanJSONValue(dec); verr != nil {
				return verr
			}
		}
	}
	if _, cerr := dec.Token(); cerr != nil {
		return fmt.Errorf("JSON 닫는 구분자 읽기 실패: %v", cerr)
	}
	return nil
}

// sameState는 두 record의 **복원 상태**가 같은지 본다 — 다시 띄우는 데 필요한 값 전부다.
// 추적 메타(requestId·ts)는 여기 들지 않는다: 그것들이 달라도 "무엇을 띄웠는가"는 같다.
func (r AppliedRecord) sameState(o AppliedRecord) bool {
	return r.Revision == o.Revision &&
		r.ImageDigest == o.ImageDigest &&
		r.Slot == o.Slot &&
		r.CommitSHA == o.CommitSHA &&
		sameInjected(r.Injected, o.Injected)
}

func sameInjected(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// Promote는 **배포가 성공한 뒤에만** 호출된다(B4' — 실패 candidate는 승격되지 않는다).
// 단일 파일을 원자 교체하므로 반쪽 승격 창이 없다. 갈래는 셋이며, 판정 기준은 revision이
// **아니라 record 전체의 상태**다:
//
//   - 완전 동일(상태 + requestId까지 같다) = 같은 요청의 재실행 = **무변경**.
//   - 상태만 동일(새 requestId) = 같은 것을 다시 띄웠다 = applied[0] **제자리 갱신**.
//     [1](직전 정상본)은 건드리지 않는다 — 밀어넣으면 복원 재료가 "같은 것 두 개"가 되어
//     되돌릴 곳이 사라진다.
//   - 그 밖 = 새 record를 앞에 넣는다.
//
// ⚠️ revision만 비교하면 안 되는 이유(리뷰 E-1): compose 정의는 릴리스마다 바뀌지 않는다.
// 같은 compose에 **새 이미지**를 올리는 것이 정상 배포의 대다수인데, revision 비교는 그
// 전부를 "같은 것"으로 보고 승격을 통째로 삼킨다 — applied[0]의 imageDigest가 옛 릴리스에
// 머물고, 그 목록을 보고 복원하면 방금 배포한 것이 아니라 예전 이미지가 뜬다.
func (w *Workspace) Promote(target string, rec AppliedRecord) error {
	cur, err := w.Applied(target)
	if err != nil {
		return err
	}
	var next []AppliedRecord
	switch {
	case len(cur) > 0 && cur[0].sameState(rec) && cur[0].RequestID == rec.RequestID:
		return nil
	case len(cur) > 0 && cur[0].sameState(rec):
		next = append([]AppliedRecord{rec}, cur[1:]...)
	default:
		next = append([]AppliedRecord{rec}, cur...)
	}
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
	// 원자성 시험용 훅 — 테스트가 rename **직전**에 프로세스 중단을 흉내 낸다. 프로덕션에서는
	// 항상 nil이다. 이 지점이 원자성의 유일한 경계이므로(그 전은 temp 파일뿐, 그 후는 완료)
	// 여기서 끊었을 때 원본이 온전한지가 곧 "반쪽 승격 창이 없다"의 증명이다.
	if w.beforeRename != nil {
		if herr := w.beforeRename(); herr != nil {
			return herr
		}
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
		// 스냅샷 디렉터리는 세대 회전 밖이다 — 실행 중 잠깐 사는 파일이라 pin·잔여 상한의
		// 대상이 아니고, 여기 섞이면 GC가 임시 파일을 세대로 세게 된다.
		if slotEnt.Name() == snapshotDir {
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
// 코드가 CodeRevision인 이유(리뷰 E-11): 이 값은 **요청(manifest)에서 온다**. 저장 무결성
// 장애로 분류하면 요청 형식 위반이 500으로 나가 CI가 자기 산출물 대신 이 호스트의 디스크를
// 의심하게 된다 — 형식 위반은 422다.
func validRevHex(revHex string) error {
	if len(revHex) != 64 {
		return errf(CodeRevision, "revision hex 길이가 64가 아니다: %d", len(revHex))
	}
	for _, c := range revHex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errf(CodeRevision, "revision hex에 허용되지 않는 문자가 있다: %q", revHex)
		}
	}
	return nil
}
