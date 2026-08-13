package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jun-bank/infra/internal/compose"
	"github.com/jun-bank/infra/internal/store"
)

// 동봉 결박의 실행 지점 계약(infra#19). 여기서 지키는 불변식:
//
//	B1'' 실효 설정 = 서명 바이트 + 닫힌 주입값
//	B4'  preflight 실패 = 부작용 0 · 실패 candidate는 승격되지 않는다
//	B5'  동봉이 기본 · legacy는 명시 opt-in + 요청별 가시화
//
// "부작용 0"은 **디렉터리 스냅샷 전/후 비교**로 본다. "없던 파일이 없다"를 단언하는 골든은
// 원래도 없었으므로 항상 통과한다(fail-open 골든) — 트리 전체가 그대로임을 봐야 의미가 있다.

// --- 픽스처 ------------------------------------------------------------------

const embeddedCompose = `services:
  app:
    image: ${DEPLOY_IMAGE_REF}
    ports:
      - "${DEPLOY_HOST_PORT}:8080"
    environment:
      - CORE_BLUE_URI
    restart: "unless-stopped"
`

func revHexOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// embeddedManifest는 동봉 계약을 온전히 만족하는 manifest다.
func embeddedManifest(content string) Manifest {
	m := manifest(validDigest)
	m.ComposeContent = base64.StdEncoding.EncodeToString([]byte(content))
	m.ComposeRevision = "sha256:" + revHexOf(content)
	m.AppService = "app"
	return m
}

// embedRig는 동봉 배선 + 실행기 페이크를 함께 든 시험대다.
type embedRig struct {
	t        *testing.T
	ws       *compose.Workspace
	root     string
	exec     *fakeExec
	health   fakeHealth
	binds    int
	lastBind ComposeBinding
	lastSlot string
	bindErr  error
	runtime  *ComposeRuntime
}

func newEmbedRig(t *testing.T) *embedRig {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "ws")
	if mkErr := os.Mkdir(root, 0o700); mkErr != nil {
		t.Fatal(mkErr)
	}
	ws, err := compose.Open(root)
	if err != nil {
		t.Fatalf("workspace 열기 실패: %v", err)
	}
	r := &embedRig{t: t, ws: ws, root: root, exec: &fakeExec{}}
	r.runtime = &ComposeRuntime{
		Workspace:  ws,
		AppService: "app",
		HostPort:   map[string]string{"blue": "18081", "green": "18082", compose.SlotSingle: "18080"},
		Policy: func(Target) compose.Policy {
			return compose.Policy{
				ImageEnvVar:  "DEPLOY_IMAGE_REF",
				EnvAllow:     []string{"CORE_BLUE_URI"},
				EvalSymlinks: func(s string) (string, error) { return s, nil },
			}
		},
		ConfigValue: func(key string) (string, bool) {
			if key == "CORE_BLUE_URI" {
				return "http://127.0.0.1:18081", true
			}
			return "", false
		},
		Bind: func(slot string, b ComposeBinding) (HostExecutor, HealthChecker, error) {
			r.binds++
			r.lastSlot, r.lastBind = slot, b
			if r.bindErr != nil {
				return nil, nil, r.bindErr
			}
			return r.exec, r.health, nil
		},
	}
	return r
}

// dispatcher는 단일 경로(전환 없음) 실행 지점이다 — 동봉 결박 자체를 보는 데 충분하고,
// 블루-그린 축은 기존 bgRig가 따로 덮는다.
func (r *embedRig) dispatcher() LocalDispatcher {
	return LocalDispatcher{
		Exec: r.exec, Health: r.health,
		Repos: repos(), PhaseBudget: time.Minute, Compose: r.runtime,
	}
}

func (r *embedRig) run(m Manifest) (RemoteState, error) {
	return r.dispatcher().Dispatch(context.Background(), m, store.FencingToken(1))
}

// snapshotTree는 트리를 (경로·모드·크기) 문자열로 접는다 — 생성·삭제·변경이 전부 드러난다.
func snapshotTree(t *testing.T, dir string) string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		out = append(out, rel+"|"+info.Mode().String())
		return nil
	})
	if err != nil {
		t.Fatalf("스냅샷 실패: %v", err)
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

// --- 정상 경로 ---------------------------------------------------------------

// 동봉 경로 정상 배포: candidate가 기록되고, 실행기가 그 경로에 결박되며, 성공 후에만 승격된다.
func TestEmbeddedDeployBindsCandidateAndPromotes(t *testing.T) {
	r := newEmbedRig(t)
	m := embeddedManifest(embeddedCompose)

	st, err := r.run(m)
	if st != StateCompleted || err != nil {
		t.Fatalf("정상 동봉 배포: state=%v err=%v", st, err)
	}
	if r.binds != 1 {
		t.Fatalf("결박 호출 %d회, 1회 기대", r.binds)
	}

	rev := revHexOf(embeddedCompose)
	wantPath := r.ws.CandidatePath("core", compose.SlotSingle, rev)
	if r.lastBind.ComposeFile != wantPath {
		t.Fatalf("결박된 compose 파일=%q, %q 기대", r.lastBind.ComposeFile, wantPath)
	}
	if r.lastBind.ProjectDirectory != filepath.Dir(wantPath) {
		t.Fatalf("--project-directory=%q", r.lastBind.ProjectDirectory)
	}
	// candidate 내용은 서명 바이트 그대로여야 한다(정규화·재직렬화 금지).
	got, rerr := os.ReadFile(wantPath)
	if rerr != nil || string(got) != embeddedCompose {
		t.Fatalf("기록된 candidate가 서명 바이트와 다르다: err=%v", rerr)
	}

	// B1'' — 주입 집합은 닫혀 있다: 등재 config 키 + 호스트 포트뿐(이미지는 up이 주입).
	want := []string{"CORE_BLUE_URI=http://127.0.0.1:18081", "DEPLOY_HOST_PORT=18080"}
	if strings.Join(r.lastBind.Injected, "|") != strings.Join(want, "|") {
		t.Fatalf("주입 집합=%v, %v 기대", r.lastBind.Injected, want)
	}

	applied, aerr := r.ws.Applied("core")
	if aerr != nil {
		t.Fatal(aerr)
	}
	if len(applied) != 1 || applied[0].Revision != rev || applied[0].Slot != compose.SlotSingle {
		t.Fatalf("승격 결과=%+v", applied)
	}
	if applied[0].ImageDigest != validDigest || applied[0].Injected["DEPLOY_HOST_PORT"] != "18080" {
		t.Fatalf("복원 재료가 불완전하다: %+v", applied[0])
	}
}

// --- B4' 부작용 0 -------------------------------------------------------------

// preflight 실패는 workspace 트리를 **전혀** 바꾸지 않는다.
func TestPreflightFailuresLeaveNoTrace(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*Manifest)
		isErr func(error) bool
	}{
		{"해시 불일치(위조)", func(m *Manifest) {
			m.ComposeRevision = "sha256:" + strings.Repeat("0", 64)
		}, func(e error) bool { return errors.Is(e, ErrManifestComposeHash) }},
		{"구조 위반(미지 키)", func(m *Manifest) {
			*m = embeddedManifest("services:\n  app:\n    image: ${DEPLOY_IMAGE_REF}\n    privileged: true\n")
		}, func(e error) bool { return errors.Is(e, ErrComposePreflight) }},
		{"CP-3 3자 불일치", func(m *Manifest) {
			*m = embeddedManifest("services:\n  other:\n    image: ${DEPLOY_IMAGE_REF}\n")
			m.AppService = "other"
		}, func(e error) bool { return errors.Is(e, ErrComposePreflight) }},
		{"등재 밖 environment 키", func(m *Manifest) {
			*m = embeddedManifest("services:\n  app:\n    image: ${DEPLOY_IMAGE_REF}\n    environment:\n      - \"AWS_SECRET_ACCESS_KEY\"\n")
		}, func(e error) bool { return errors.Is(e, ErrComposePreflight) }},
		{"등재 볼륨 밖", func(m *Manifest) {
			*m = embeddedManifest("services:\n  app:\n    image: ${DEPLOY_IMAGE_REF}\n    volumes:\n      - \"/var/run/docker.sock:/var/run/docker.sock:rw\"\n")
		}, func(e error) bool { return errors.Is(e, ErrComposePreflight) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newEmbedRig(t)
			before := snapshotTree(t, r.root)

			m := embeddedManifest(embeddedCompose)
			tc.mut(&m)
			st, err := r.run(m)

			if st != StateUnexecuted || err == nil {
				t.Fatalf("state=%v err=%v, UNEXECUTED·err 기대", st, err)
			}
			if !tc.isErr(err) {
				t.Fatalf("오류 분류가 다르다: %v", err)
			}
			if after := snapshotTree(t, r.root); after != before {
				t.Fatalf("preflight 실패가 파일시스템을 바꿨다(부작용 0 위반):\n전=%s\n후=%s", before, after)
			}
			if r.exec.pulls != 0 || r.exec.ups != 0 || r.binds != 0 {
				t.Fatalf("preflight 실패인데 실행이 일어났다: pull=%d up=%d bind=%d", r.exec.pulls, r.exec.ups, r.binds)
			}
		})
	}
}

// 실패한 배포는 승격되지 않는다 — applied[0]이 실패본이 되면 "마지막 정상본"이 거짓이 된다.
func TestFailedDeployDoesNotPromote(t *testing.T) {
	r := newEmbedRig(t)
	r.health = fakeHealth{err: errors.New("헬스 미달")}
	m := embeddedManifest(embeddedCompose)

	st, err := r.run(m)
	if st != StateUnexecuted || err == nil {
		t.Fatalf("헬스 실패: state=%v err=%v", st, err)
	}
	applied, aerr := r.ws.Applied("core")
	if aerr != nil {
		t.Fatal(aerr)
	}
	if len(applied) != 0 {
		t.Fatalf("실패 배포가 승격됐다: %+v", applied)
	}
	// candidate 잔류는 무해하다(B4' 재기술) — 지워지는 것이 아니라 GC 대상으로 남는다.
	if _, serr := os.Stat(r.ws.CandidatePath("core", compose.SlotSingle, revHexOf(embeddedCompose))); serr != nil {
		t.Fatalf("candidate가 남아 있어야 한다(GC 대상): %v", serr)
	}
}

// --- CP-1 불변 candidate ------------------------------------------------------

// 같은 이름(=같은 해시)의 파일이 **다른 내용**으로 존재하면 덮어쓰지 않고 저장 무결성
// 장애로 닫는다. 요청은 옳았고 이 호스트가 잘못한 것이므로 별도 분류다(G-14).
func TestCandidateCollisionIsStorageIntegrity(t *testing.T) {
	r := newEmbedRig(t)
	rev := revHexOf(embeddedCompose)
	dir := filepath.Join(r.root, "core", compose.SlotSingle)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := r.ws.CandidatePath("core", compose.SlotSingle, rev)
	if err := os.WriteFile(path, []byte("services: {} # 다른 내용\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := r.run(embeddedManifest(embeddedCompose))
	if st != StateUnexecuted || !errors.Is(err, ErrComposeStorage) {
		t.Fatalf("state=%v err=%v, UNEXECUTED·저장 무결성 장애 기대", st, err)
	}
	// 기존 파일을 덮어쓰지 않았다(불변 계약).
	got, rerr := os.ReadFile(path)
	if rerr != nil || !strings.Contains(string(got), "다른 내용") {
		t.Fatalf("기존 candidate가 덮어써졌다: %q", got)
	}
	if r.exec.ups != 0 {
		t.Fatal("저장 무결성 장애인데 up이 실행됐다")
	}
}

// 실행 기준 디렉터리의 .env는 서명 밖 값을 보간에 끌어들인다 — 기록 전에 막고, up도 하지 않는다.
func TestDotEnvInWorkspaceBlocksDeploy(t *testing.T) {
	r := newEmbedRig(t)
	dir := filepath.Join(r.root, "core", compose.SlotSingle)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DEPLOY_IMAGE_REF=evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := r.run(embeddedManifest(embeddedCompose))
	if st != StateUnexecuted || !errors.Is(err, ErrComposePreflight) {
		t.Fatalf("state=%v err=%v", st, err)
	}
	if r.exec.ups != 0 {
		t.Fatal(".env가 있는데 up이 실행됐다")
	}
}

// --- R7 REQUIRE 게이트 --------------------------------------------------------

// 기본은 동봉 필수다 — 무동봉 manifest는 부작용 0으로 거절된다(다운그레이드 차단).
func TestLegacyManifestRejectedByDefault(t *testing.T) {
	r := newEmbedRig(t)
	before := snapshotTree(t, r.root)

	st, err := r.run(manifest(validDigest)) // 동봉 필드 없음
	if st != StateUnexecuted || !errors.Is(err, ErrManifestComposeRequired) {
		t.Fatalf("state=%v err=%v, UNEXECUTED·동봉 필수 기대", st, err)
	}
	if after := snapshotTree(t, r.root); after != before {
		t.Fatal("무동봉 거절이 파일을 남겼다")
	}
	if r.exec.pulls != 0 {
		t.Fatal("무동봉 거절인데 pull이 실행됐다")
	}
}

// opt-in을 켜면 기존 호스트 compose 경로로 흐른다(과도기) — 그때 결박은 일어나지 않는다.
func TestLegacyManifestAcceptedWithOptIn(t *testing.T) {
	r := newEmbedRig(t)
	r.runtime.AllowLegacy = true

	st, err := r.run(manifest(validDigest))
	if st != StateCompleted || err != nil {
		t.Fatalf("legacy opt-in: state=%v err=%v", st, err)
	}
	if r.binds != 0 {
		t.Fatal("legacy 경로인데 candidate 결박이 일어났다")
	}
	applied, _ := r.ws.Applied("core")
	if len(applied) != 0 {
		t.Fatalf("legacy 배포가 applied에 기록됐다(동봉 정의가 아니다): %+v", applied)
	}
}

// 동봉 manifest가 왔는데 배선이 없으면 요란하게 거절한다(조용히 legacy로 흐르지 않는다).
func TestEmbeddedWithoutWiringIsRejected(t *testing.T) {
	d := LocalDispatcher{
		Exec: &fakeExec{}, Health: fakeHealth{}, Repos: repos(), PhaseBudget: time.Minute,
		Compose: &ComposeRuntime{AllowLegacy: true}, // legacy 전용 호스트
	}
	st, err := d.Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(1))
	if st != StateUnexecuted || !errors.Is(err, ErrComposeWiring) {
		t.Fatalf("state=%v err=%v, UNEXECUTED·배선 부재 기대", st, err)
	}
}

// --- 주입값 fail-closed -------------------------------------------------------

// 등재 키의 값이 호스트에 없으면 배포를 시작하지 않는다(CP-5) — 빈 값으로 뜨는 조용한
// 오설정 기동을 막는다. 슬롯 호스트 포트도 같은 축이다.
func TestMissingInjectionValuesFailClosed(t *testing.T) {
	t.Run("등재 config 키 값 부재", func(t *testing.T) {
		r := newEmbedRig(t)
		r.runtime.ConfigValue = func(string) (string, bool) { return "", false }
		before := snapshotTree(t, r.root)
		st, err := r.run(embeddedManifest(embeddedCompose))
		if st != StateUnexecuted || !errors.Is(err, ErrComposePreflight) {
			t.Fatalf("state=%v err=%v", st, err)
		}
		if snapshotTree(t, r.root) != before {
			t.Fatal("주입값 부재 거절이 파일을 남겼다(부작용 0 위반)")
		}
	})
	t.Run("슬롯 호스트 포트 미배선", func(t *testing.T) {
		r := newEmbedRig(t)
		r.runtime.HostPort = map[string]string{}
		st, err := r.run(embeddedManifest(embeddedCompose))
		if st != StateUnexecuted || !errors.Is(err, ErrComposePreflight) {
			t.Fatalf("state=%v err=%v", st, err)
		}
		if r.exec.ups != 0 {
			t.Fatal("포트 미배선인데 up이 실행됐다")
		}
	})
}

// --- G-08 동일 revision 재배포 -------------------------------------------------

// 같은 revision을 다시 배포해도 applied는 바뀌지 않는다 — 밀어넣으면 [1](직전 정상본)이
// 밀려나 되돌릴 곳이 사라진다. candidate도 재사용되고 덮어써지지 않는다.
func TestSameRevisionRedeployKeepsAppliedStable(t *testing.T) {
	r := newEmbedRig(t)
	m := embeddedManifest(embeddedCompose)
	if st, err := r.run(m); st != StateCompleted || err != nil {
		t.Fatalf("1차: state=%v err=%v", st, err)
	}
	first, _ := r.ws.Applied("core")
	if st, err := r.run(m); st != StateCompleted || err != nil {
		t.Fatalf("2차: state=%v err=%v", st, err)
	}
	second, _ := r.ws.Applied("core")
	if len(second) != len(first) || len(second) != 1 {
		t.Fatalf("동일 revision 재배포가 applied를 늘렸다: %d → %d", len(first), len(second))
	}
}

// --- 오케스트레이션 사상 ------------------------------------------------------

// 이력에는 요청마다 **어느 compose 경로로 배포됐는지**가 남아야 한다(G-11 · B5').
// 이 표기가 없으면 "legacy 표기 급증"이라는 이관 순서 위반의 관측 신호가 성립하지 않는다.
func TestHistoryRecordsComposePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
		want string
	}{
		{"동봉", embeddedBody(), ComposePathEmbedded},
		{"과도기", bodyOf(""), ComposePathLegacy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, h := baseDeps()
			d.Dispatcher = fakeDispatcher{state: StateCompleted}
			res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: tc.body})
			if res.Outcome != OutcomeCompleted {
				t.Fatalf("outcome=%v detail=%q", res.Outcome, res.Detail)
			}
			if !strings.Contains(h.last().Detail, "composePath="+tc.want) {
				t.Fatalf("이력 detail에 경로 표기가 없다: %q", h.last().Detail)
			}
		})
	}
}

// 동봉 결박의 거절은 실행 계층 실패(502)와 범주가 다르다 — 뭉치면 관제가 원인을 잘못 짚는다.
func TestComposeRejectionOutcomeMapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want Outcome
	}{
		{"무동봉(REQUIRE)", ErrManifestComposeRequired, OutcomeManifestInvalid},
		{"구조·CP-3 위반", ErrComposePreflight, OutcomeManifestInvalid},
		{"해시 불일치", ErrManifestComposeHash, OutcomeManifestInvalid},
		{"base64 계약 위반", ErrManifestComposeEncoding, OutcomeManifestInvalid},
		{"저장 무결성 장애", ErrComposeStorage, OutcomeStorageIntegrity},
		{"실행 계층 실패", errors.New("compose up 실패"), OutcomeExecutionFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, l, _ := baseDeps()
			d.Dispatcher = fakeDispatcher{state: StateUnexecuted, err: tc.err}
			res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: embeddedBody()})
			if res.Outcome != tc.want {
				t.Fatalf("outcome=%v, %v 기대(detail=%q)", res.Outcome, tc.want, res.Detail)
			}
			// 전부 부작용 0이거나 candidate 잔류뿐이므로 락은 해제된다.
			if l.released != 1 {
				t.Fatalf("락 해제 %d회, 1회 기대", l.released)
			}
		})
	}
}

// 엄격 파서는 락 보유 중에 선다 — 미지 필드가 실린 body는 dispatch에 닿기 전에 422로 닫힌다.
func TestStrictParseRejectsBeforeDispatch(t *testing.T) {
	d, _, h := baseDeps()
	rec := &recDispatcher{state: StateCompleted}
	d.Dispatcher = rec
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{
		RequestID: "req-1",
		Body:      bodyOf(`"extraField":"x"`),
	})
	if res.Outcome != OutcomeManifestInvalid {
		t.Fatalf("outcome=%v, MANIFEST_INVALID 기대", res.Outcome)
	}
	if rec.calls != 0 {
		t.Fatalf("엄격 검증 실패인데 dispatch가 %d회 호출됐다", rec.calls)
	}
	if h.last().EventType != "REJECTED" {
		t.Fatalf("거절이 이력에 남지 않았다: %+v", h.last())
	}
}
