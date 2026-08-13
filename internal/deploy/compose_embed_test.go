package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
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

// --- E-8 preflight 순서 -------------------------------------------------------

// 두 위반이 겹친 입력에서 **어느 방어선이 잡는가**는 진단의 출발점을 정한다. 순서가
// 흔들리면 같은 입력이 어느 날 다른 코드로 거절되고, 그때 사람은 엉뚱한 곳을 고치러 간다.
func TestPreflightOrder(t *testing.T) {
	// I-09: 해시 불일치 + YAML 구조 위반이 동시에 걸린 입력 → **해시**가 먼저다.
	// 해시가 어긋났다는 것은 "이 바이트는 서명된 것이 아니다"라, 그 내용을 구조로 평가하는
	// 것 자체가 의미 없다.
	t.Run("I-09 해시+구조 이중 위반 = 해시", func(t *testing.T) {
		r := newEmbedRig(t)
		m := embeddedManifest("services:\n  app:\n    image: ${DEPLOY_IMAGE_REF}\n    privileged: true\n")
		m.ComposeRevision = "sha256:" + strings.Repeat("0", 64) // 해시도 어긋나게
		_, err := r.run(m)
		if !errors.Is(err, ErrManifestComposeHash) {
			t.Fatalf("해시가 먼저 잡아야 한다: %v", err)
		}
	})

	// I-10: 구조 위반 + CP-3 호스트 불일치 → **구조**가 먼저다. 구조 위반은 "이 compose는
	// 애초에 실행될 수 없다"이고 CP-3 불일치는 "이 호스트가 배포할 대상이 아니다"라,
	// 전자를 먼저 알려야 CI를 고치러 간다.
	t.Run("I-10 구조+CP-3 이중 위반 = 구조", func(t *testing.T) {
		r := newEmbedRig(t)
		// 서비스명이 host env("app")와 다르고, 그 안에 미지 키까지 있다.
		m := embeddedManifest("services:\n  other:\n    image: ${DEPLOY_IMAGE_REF}\n    privileged: true\n")
		m.AppService = "other"
		_, err := r.run(m)
		if !errors.Is(err, ErrComposePreflight) {
			t.Fatalf("preflight 분류가 아니다: %v", err)
		}
		if !strings.Contains(err.Error(), compose.CodeUnknownKey) {
			t.Fatalf("구조 위반 코드가 아니라 다른 방어선이 잡았다: %v", err)
		}
	})

	// 구조가 온전하고 CP-3만 어긋나면 그때 CP-3가 잡는다(순서가 CP-3를 삼키지 않는다).
	t.Run("구조 정상 + CP-3만 불일치 = CP-3", func(t *testing.T) {
		r := newEmbedRig(t)
		m := embeddedManifest("services:\n  other:\n    image: ${DEPLOY_IMAGE_REF}\n")
		m.AppService = "other"
		_, err := r.run(m)
		if !errors.Is(err, ErrComposePreflight) || !strings.Contains(err.Error(), "DEPLOY_APP_SERVICE") {
			t.Fatalf("CP-3 대조가 잡아야 한다: %v", err)
		}
	})
}

// --- E-6 블루-그린 + 동봉 ------------------------------------------------------

// bgEmbedRig는 동봉 배선을 얹은 블루-그린 시험대다.
type bgEmbedRig struct {
	*embedRig
	blue, green   *fakeExec
	blueH, greenH fakeHealth
	gw            *fakeGateway
	bound         map[string]*fakeExec
	// midDeploy는 idle 헬스 판정 직전에 불린다(기동 뒤·전환 앞) — 검증과 사용 사이의 창을
	// 실제 시퀀스 안에서 흔들어 보기 위한 주입점이다.
	midDeploy func()
	// onActiveDown은 구 active를 내리는 순간 불린다(실행 시점의 파일 상태 포착).
	onActiveDown func()
}

// activeBound는 구 active 슬롯에 결박된 실행기와 그 `-f` 경로를 찾는다.
func (r *bgEmbedRig) activeBound(t *testing.T, slot string) (*fakeExec, string) {
	t.Helper()
	for k, ex := range r.bound {
		if strings.HasPrefix(k, slot+"|") {
			return ex, strings.TrimPrefix(k, slot+"|")
		}
	}
	t.Fatalf("슬롯 %q에 결박된 실행기가 없다(결박된 것: %v)", slot, boundKeys(r.bound))
	return nil, ""
}

func newBGEmbedRig(t *testing.T, active Slot) *bgEmbedRig {
	base := newEmbedRig(t)
	r := &bgEmbedRig{
		embedRig: base,
		blue:     &fakeExec{name: "blue"},
		green:    &fakeExec{name: "green"},
		blueH:    fakeHealth{name: "blue"},
		greenH:   fakeHealth{name: "green"},
		gw:       &fakeGateway{active: string(active)},
		bound:    map[string]*fakeExec{},
	}
	// 결박은 슬롯마다 **새 실행기**를 낸다 — 실제 배선(WithCompose 파생)과 같은 모양이라야
	// "누가 어떤 파일로 무엇을 했는가"를 슬롯별로 가려낼 수 있다.
	base.runtime.Bind = func(slot string, b ComposeBinding) (HostExecutor, HealthChecker, error) {
		base.binds++
		base.lastSlot, base.lastBind = slot, b
		if base.bindErr != nil {
			return nil, nil, base.bindErr
		}
		ex := &fakeExec{name: slot + ":bound"}
		r.bound[slot+"|"+b.ComposeFile] = ex
		health := fakeHealth{name: slot}
		if slot == string(SlotBlue) {
			health.err = r.blueH.err
		} else if slot == string(SlotGreen) {
			health.err = r.greenH.err
		}
		// idle 슬롯의 헬스는 시퀀스 중간이고, active 슬롯의 down은 시퀀스 끝이다 —
		// 그 둘 사이가 정확히 검증과 사용 사이의 창이다.
		if slot != string(r.gw.active) {
			health.hook = r.midDeploy
		} else {
			ex.onDown = r.onActiveDown
		}
		return ex, health, nil
	}
	return r
}

// seedActive는 구 active 슬롯이 **동봉 경로로 떠 있는** 정상 상태를 만든다(이관이 끝난
// 뒤의 모습). 이것을 만들지 않으면 구 active의 실행 정의를 확정할 수 없어 배포가 거절되는데,
// 그 거절이야말로 E-7a가 세운 계약이므로 시나리오마다 명시적으로 깔아 준다.
func (r *bgEmbedRig) seedActive(t *testing.T, slot, hostPort string) string {
	t.Helper()
	body := embeddedCompose + "# " + slot + " 세대\n"
	rev := revHexOf(body)
	if _, err := r.ws.WriteCandidate("core", slot, rev, []byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := r.ws.Promote("core", compose.AppliedRecord{
		Revision: rev, Slot: slot, ImageDigest: validDigest, CommitSHA: "c0",
		RequestID: "req-0", TS: "t", Injected: map[string]string{"DEPLOY_HOST_PORT": hostPort},
		Status: compose.StatusApplied,
	}); err != nil {
		t.Fatal(err)
	}
	return rev
}

func (r *bgEmbedRig) dispatcher() LocalDispatcher {
	return LocalDispatcher{
		Repos:       repos(),
		PhaseBudget: time.Minute,
		Gateway:     r.gw,
		SlotExec:    map[Slot]HostExecutor{SlotBlue: r.blue, SlotGreen: r.green},
		SlotHealth:  map[Slot]HealthChecker{SlotBlue: r.blueH, SlotGreen: r.greenH},
		DrainWait:   testDrainWait,
		Compose:     r.runtime,
	}
}

// E-6 ⑴: 블루-그린 정상 완주 — idle 슬롯에 결박된 candidate로 올라가고, 승격 record의
// slot이 그 idle이다(슬롯이 뒤바뀌면 복원이 엉뚱한 쪽을 되살린다).
func TestBlueGreenEmbeddedCompletes(t *testing.T) {
	r := newBGEmbedRig(t, SlotBlue) // active=blue → idle=green
	r.seedActive(t, "blue", "18081")
	st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
	if st != StateCompleted || err != nil {
		t.Fatalf("state=%v err=%v, COMPLETED 기대", st, err)
	}

	rev := revHexOf(embeddedCompose)
	wantPath := r.ws.CandidatePath("core", "green", rev)
	if r.lastSlot != "green" || r.lastBind.ComposeFile != wantPath {
		t.Fatalf("idle 슬롯 결박이 어긋났다: slot=%q file=%q", r.lastSlot, r.lastBind.ComposeFile)
	}
	// 주입값은 그 슬롯의 호스트 포트를 쓴다(슬롯마다 다르다).
	if !containsStr(r.lastBind.Injected, "DEPLOY_HOST_PORT=18082") {
		t.Fatalf("green 슬롯의 호스트 포트가 주입되지 않았다: %v", r.lastBind.Injected)
	}

	applied, aerr := r.ws.Applied("core")
	if aerr != nil {
		t.Fatal(aerr)
	}
	if applied[0].Slot != "green" {
		t.Fatalf("승격 record의 slot이 idle이 아니다: %+v", applied[0])
	}
	if len(applied) != 2 || applied[1].Slot != "blue" {
		t.Fatalf("직전 정상본(구 active)이 밀려났다: %+v", applied)
	}
}

// E-6 ⑵: 전환 **전** 실패(헬스 미달) — 승격이 없고 candidate만 잔류한다. 라우트도 옮기지 않는다.
func TestBlueGreenEmbeddedFailsBeforeCutover(t *testing.T) {
	r := newBGEmbedRig(t, SlotBlue)
	r.seedActive(t, "blue", "18081")
	r.greenH = fakeHealth{name: "green", err: errors.New("헬스 미달")}

	st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
	if st != StateUnexecuted || err == nil {
		t.Fatalf("state=%v err=%v, UNEXECUTED 기대", st, err)
	}
	if r.gw.switches != 0 {
		t.Fatalf("전환 전 실패인데 라우트가 옮겨졌다(%d회)", r.gw.switches)
	}
	applied, aerr := r.ws.Applied("core")
	if aerr != nil {
		t.Fatal(aerr)
	}
	for _, rec := range applied {
		if rec.Slot == "green" {
			t.Fatalf("전환 전 실패가 승격됐다: %+v", rec)
		}
	}
	if _, serr := os.Stat(r.ws.CandidatePath("core", "green", revHexOf(embeddedCompose))); serr != nil {
		t.Fatalf("candidate는 잔류해야 한다(무해·GC 대상): %v", serr)
	}
}

// --- E-7 구 active 슬롯의 down 결박 --------------------------------------------

// 구 active 슬롯을 내릴 때 `-f`는 **그 슬롯이 실제로 떠 있는 정의**를 가리켜야 한다.
// 기존 SlotExec로 내리면 호스트의 옛 compose 파일 기준으로 프로젝트를 로드하게 되고,
// 동봉 필수 호스트에는 그 파일이 아예 없을 수도 있다.
func TestActiveSlotDownBoundToAppliedRecord(t *testing.T) {
	r := newBGEmbedRig(t, SlotBlue)

	// blue가 예전에 다른 정의로 떠 있었다고 기록한다(그 세대 파일도 함께).
	oldCompose := embeddedCompose + "# 이전 세대\n"
	oldRev := revHexOf(oldCompose)
	if _, err := r.ws.WriteCandidate("core", "blue", oldRev, []byte(oldCompose)); err != nil {
		t.Fatal(err)
	}
	if err := r.ws.Promote("core", compose.AppliedRecord{
		Revision: oldRev, Slot: "blue", ImageDigest: validDigest, CommitSHA: "c0",
		RequestID: "req-0", TS: "t", Injected: map[string]string{"DEPLOY_HOST_PORT": "18081"},
		Status: compose.StatusApplied,
	}); err != nil {
		t.Fatal(err)
	}

	st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
	if st != StateCompleted || err != nil {
		t.Fatalf("state=%v err=%v", st, err)
	}

	// blue(구 active)를 내린 실행기는 그 record의 정의에 결박됐어야 한다. `-f`가 가리키는
	// 것은 세대 파일 자체가 아니라 **검증된 바이트의 스냅샷**이다(TOCTOU 창 차단 — 아래
	// TestActiveSlotDownUsesImmutableSnapshot 참조).
	downExec, boundPath := r.activeBound(t, "blue")
	if downExec.downs != 1 {
		t.Fatalf("결박된 실행기가 down하지 않았다(%d회)", downExec.downs)
	}
	if r.blue.downs != 0 {
		t.Fatalf("호스트 옛 compose 파일 실행기가 down했다(%d회) — 결박이 우회됐다", r.blue.downs)
	}
	if boundPath == r.ws.CandidatePath("core", "blue", oldRev) {
		t.Fatal("세대 파일 경로를 그대로 결박했다 — 검증과 사용 사이의 창이 열려 있다")
	}
	if !strings.Contains(boundPath, filepath.Join("core", "tmp")) {
		t.Fatalf("스냅샷이 tmp 격리 밖이다: %q", boundPath)
	}
}

// applied가 손상되면 **legacy 파일로 폴백하지 않는다** — 그때는 "record가 없다"가 아니라
// "알 수 없다"이고, 알 수 없는 채로 옛 파일을 들고 down하는 것이 막으려는 동작이다.
func TestActiveSlotDownRefusesLegacyFallbackOnCorruptApplied(t *testing.T) {
	r := newBGEmbedRig(t, SlotBlue)
	dir := filepath.Join(r.root, "core")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "applied.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
	if st != StateUnexecuted || !errors.Is(err, ErrComposeStorage) {
		t.Fatalf("state=%v err=%v, UNEXECUTED·저장 무결성 기대", st, err)
	}
	if r.blue.downs != 0 || r.green.ups != 0 {
		t.Fatalf("손상인데 실행이 일어났다: blue.down=%d green.up=%d", r.blue.downs, r.green.ups)
	}
}

// E-7a: record 부재 시의 호스트 compose 폴백은 **legacy opt-in에서만** 열린다.
//
// 그 경로가 필요한 상황은 하나뿐이다 — 이관 중 첫 동봉 배포에서 구 컨테이너가 아직 legacy로
// 떠 있는 때. opt-in으로 막지 않으면 동봉 배포가 서명되지 않은 호스트 파일로 down하는
// fail-open이 상시로 열려 있게 되고, 그것이 이 결박이 막으려는 바로 그 동작이다.
func TestActiveSlotFallbackRequiresLegacyOptIn(t *testing.T) {
	t.Run("opt-in 없으면 거부", func(t *testing.T) {
		r := newBGEmbedRig(t, SlotBlue)
		st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
		if st != StateUnexecuted || !errors.Is(err, ErrComposeStorage) {
			t.Fatalf("state=%v err=%v, UNEXECUTED·저장 무결성 기대(서명 안 된 파일로 down 금지)", st, err)
		}
		if r.blue.downs != 0 || r.green.ups != 0 {
			t.Fatalf("거부인데 실행이 일어났다: blue.down=%d green.up=%d", r.blue.downs, r.green.ups)
		}
	})
	t.Run("opt-in이면 과도기 폴백", func(t *testing.T) {
		r := newBGEmbedRig(t, SlotBlue)
		r.runtime.AllowLegacy = true
		st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
		if st != StateCompleted || err != nil {
			t.Fatalf("state=%v err=%v", st, err)
		}
		if r.blue.downs != 1 {
			t.Fatalf("과도기 폴백이 동작하지 않았다(down %d회)", r.blue.downs)
		}
		// 동봉 검증 자체는 여전히 온전하다(opt-in은 폴백 창만 연다).
		applied, _ := r.ws.Applied("core")
		if len(applied) != 1 || applied[0].Slot != "green" {
			t.Fatalf("폴백 경로에서 승격이 어긋났다: %+v", applied)
		}
	})
}

// E-7b: 세대 파일은 **파일명이 곧 내용 해시**라는 계약 위에 서 있고, 그 계약은 파일을 실제로
// 읽어 재대조할 때만 증명된다. 존재 확인만 하면 변조·절단된 파일을 이름만 믿고 "그 슬롯이
// 돌리는 정의"로 쓰게 된다.
func TestActiveSlotGenerationFileIsRehashed(t *testing.T) {
	setup := func(t *testing.T) (*bgEmbedRig, string, string) {
		t.Helper()
		r := newBGEmbedRig(t, SlotBlue)
		oldCompose := embeddedCompose + "# 이전 세대\n"
		oldRev := revHexOf(oldCompose)
		if _, err := r.ws.WriteCandidate("core", "blue", oldRev, []byte(oldCompose)); err != nil {
			t.Fatal(err)
		}
		if err := r.ws.Promote("core", compose.AppliedRecord{
			Revision: oldRev, Slot: "blue", ImageDigest: validDigest, CommitSHA: "c0",
			RequestID: "req-0", TS: "t", Injected: map[string]string{"DEPLOY_HOST_PORT": "18081"},
			Status: compose.StatusApplied,
		}); err != nil {
			t.Fatal(err)
		}
		return r, oldRev, r.ws.CandidatePath("core", "blue", oldRev)
	}

	t.Run("정상 세대 파일은 통과", func(t *testing.T) {
		r, oldRev, _ := setup(t)
		st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
		if st != StateCompleted || err != nil {
			t.Fatalf("state=%v err=%v", st, err)
		}
		if downExec, _ := r.activeBound(t, "blue"); downExec.downs != 1 {
			t.Fatalf("정상 세대 파일인데 결박 down이 일어나지 않았다(rev=%s)", oldRev[:8])
		}
	})

	t.Run("1바이트 변조 = 거부", func(t *testing.T) {
		r, _, path := setup(t)
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatal(rerr)
		}
		tampered := append([]byte(nil), body...)
		tampered[len(tampered)-2] ^= 0x01 // 1비트만 뒤집는다(길이도 그대로)
		if werr := os.WriteFile(path, tampered, 0o644); werr != nil {
			t.Fatal(werr)
		}

		st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
		if st != StateUnexecuted || !errors.Is(err, ErrComposeStorage) {
			t.Fatalf("state=%v err=%v, UNEXECUTED·저장 무결성 기대", st, err)
		}
		if r.blue.downs != 0 {
			t.Fatalf("변조된 정의인데 legacy 배선으로 폴백해 down했다(%d회) — 폴백 금지 계약 위반", r.blue.downs)
		}
		if r.green.ups != 0 {
			t.Fatalf("변조 거부인데 배포가 진행됐다(up %d회)", r.green.ups)
		}
	})

	t.Run("절단 = 거부", func(t *testing.T) {
		r, _, path := setup(t)
		if werr := os.WriteFile(path, []byte("services:"), 0o644); werr != nil {
			t.Fatal(werr)
		}
		st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
		if st != StateUnexecuted || !errors.Is(err, ErrComposeStorage) {
			t.Fatalf("state=%v err=%v, UNEXECUTED·저장 무결성 기대", st, err)
		}
	})
}

// --- E-2 승격 실패의 가시화 ----------------------------------------------------

// 승격 실패는 배포 결과를 뒤집지 않되 **이력에 드러난다**. 오류로 실으면 (COMPLETED, err)가
// 되어 모순 조합 정규화가 정상 배포를 UNKNOWN으로 접고, 로그로만 남기면 나중에 "이 배포의
// 복원 재료가 왜 없는가"를 되짚을 근거가 없다.
func TestPromotionFailureIsVisibleWithoutFlippingOutcome(t *testing.T) {
	r := newEmbedRig(t)
	// applied.json을 손상시켜 승격만 실패하게 만든다(배포 자체는 성공한다).
	dir := filepath.Join(r.root, "core")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "applied.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}

	d, _, h := baseDeps()
	d.Dispatcher = r.dispatcher()
	res := NewCoordinator(d).Orchestrate(context.Background(), Request{RequestID: "req-1", Body: embeddedBody()})

	if res.Outcome != OutcomeCompleted {
		t.Fatalf("승격 실패가 배포 결과를 뒤집었다: outcome=%v detail=%q", res.Outcome, res.Detail)
	}
	if !strings.Contains(h.last().Detail, "composePromotion="+ComposePromotionFailed) {
		t.Fatalf("승격 실패가 이력에 남지 않았다: %q", h.last().Detail)
	}
}

// --- E-10 blind 보강 -----------------------------------------------------------

// I-04: legacy opt-in이 켜져 있어도 **동봉 manifest는 전 검증을 그대로 받는다**. opt-in이
// "검증 완화"로 새면, 과도기 플래그 하나가 결박 전체를 끄는 스위치가 된다.
func TestOptInDoesNotWeakenEmbeddedValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Manifest)
		want error
	}{
		{"해시 위조", func(m *Manifest) { m.ComposeRevision = "sha256:" + strings.Repeat("0", 64) }, ErrManifestComposeHash},
		{"구조 위반", func(m *Manifest) {
			*m = embeddedManifest("services:\n  app:\n    image: ${DEPLOY_IMAGE_REF}\n    privileged: true\n")
		}, ErrComposePreflight},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newEmbedRig(t)
			r.runtime.AllowLegacy = true // 과도기 켜짐
			m := embeddedManifest(embeddedCompose)
			tc.mut(&m)
			st, err := r.run(m)
			if st != StateUnexecuted || !errors.Is(err, tc.want) {
				t.Fatalf("opt-in이 동봉 검증을 완화했다: state=%v err=%v", st, err)
			}
		})
	}
}

// I-02: legacy 수락은 **WARN 로그**로 드러난다(조용한 폴백 금지 · G-11의 로그 축).
func TestLegacyAcceptanceLogsWarning(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	r := newEmbedRig(t)
	r.runtime.AllowLegacy = true
	if st, err := r.run(manifest(validDigest)); st != StateCompleted || err != nil {
		t.Fatalf("state=%v err=%v", st, err)
	}
	out := buf.String()
	if !strings.Contains(out, ComposePathLegacy) {
		t.Fatalf("legacy 수락 WARN에 경로 코드가 없다: %q", out)
	}
	if !strings.Contains(out, "경고") {
		t.Fatalf("WARN 문면이 아니다: %q", out)
	}

	// 동봉 경로는 이 경고를 내지 않는다(경고가 상시 울리면 신호가 죽는다).
	buf.Reset()
	if st, err := r.run(embeddedManifest(embeddedCompose)); st != StateCompleted || err != nil {
		t.Fatalf("state=%v err=%v", st, err)
	}
	if strings.Contains(buf.String(), ComposePathLegacy) {
		t.Fatalf("동봉 배포가 legacy 경고를 냈다: %q", buf.String())
	}
}

// I-07: candidate 파일에는 **등재 config 키의 값이 들어 있지 않다**. 값은 호스트 .env가
// 소유하고 compose에는 키만 실린다(CP-5) — 값이 파일로 내려가면 서명 대상에 설정이 섞이고,
// 0644 파일에 그것이 남는다.
func TestCandidateNeverContainsInjectedValues(t *testing.T) {
	r := newEmbedRig(t)
	if st, err := r.run(embeddedManifest(embeddedCompose)); st != StateCompleted || err != nil {
		t.Fatalf("state=%v err=%v", st, err)
	}
	body, err := os.ReadFile(r.ws.CandidatePath("core", compose.SlotSingle, revHexOf(embeddedCompose)))
	if err != nil {
		t.Fatal(err)
	}
	for _, secretish := range []string{"http://127.0.0.1:18081", "18080"} {
		if strings.Contains(string(body), secretish) {
			t.Fatalf("candidate에 주입값이 들어 있다(%q) — 값의 소유는 호스트 .env다: %s", secretish, body)
		}
	}
	// 키 자체는 있어야 한다(pass-through 목록).
	if !strings.Contains(string(body), "CORE_BLUE_URI") {
		t.Fatalf("pass-through 키가 사라졌다: %s", body)
	}
}

// W-10(유예 근거): "배포 창 락이 동봉 경로 전체를 포괄하는가"는 여기서 따로 시험하지 않는다.
// 결박은 dispatch **안**에서 일어나고, dispatch가 락 보유 구간 안에 통째로 들어간다는 것은
// coordinator 테스트(락 획득 → fencing 재확인 → dispatch → 해제 순서)와 main의 lease 하한식
// 검증이 이미 고정하고 있다 — 같은 불변식을 이 층에서 다시 세우면 정본이 둘이 된다.

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func boundKeys(m map[string]*fakeExec) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// E-7b(TOCTOU): 세대 파일을 재해시하는 것만으로는 부족하다 — 검증은 bindActive 시점이고
// 실제 사용은 idle 기동·헬스·라우트 전환·드레인을 지난 뒤의 down이다. 그 사이(분 단위 창)에
// 원본이 바뀌면 검증되지 않은 내용으로 내리게 된다. 검증한 **바이트 자체**를 스냅샷으로
// 굳혀 결박하면, 원본이 그 뒤 어떻게 바뀌든 실행되는 것은 검증된 내용 그대로다.
func TestActiveSlotDownUsesImmutableSnapshot(t *testing.T) {
	r := newBGEmbedRig(t, SlotBlue)
	oldCompose := embeddedCompose + "# blue 세대\n"
	oldRev := revHexOf(oldCompose)
	if _, err := r.ws.WriteCandidate("core", "blue", oldRev, []byte(oldCompose)); err != nil {
		t.Fatal(err)
	}
	if err := r.ws.Promote("core", compose.AppliedRecord{
		Revision: oldRev, Slot: "blue", ImageDigest: validDigest, CommitSHA: "c0",
		RequestID: "req-0", TS: "t", Injected: map[string]string{"DEPLOY_HOST_PORT": "18081"},
		Status: compose.StatusApplied,
	}); err != nil {
		t.Fatal(err)
	}
	genPath := r.ws.CandidatePath("core", "blue", oldRev)

	// ⑴ 시퀀스 중간(기동 뒤·전환 앞)에 원본 세대 파일을 통째로 갈아치운다.
	const evil = "services:\n  app:\n    image: \"evil/image:latest\"\n"
	r.midDeploy = func() {
		if err := os.WriteFile(genPath, []byte(evil), 0o644); err != nil {
			t.Errorf("변조 실패: %v", err)
		}
	}
	// ⑵ down이 실제로 실행되는 순간, 결박된 파일의 내용을 그대로 포착한다.
	var seenAtDown string
	var seenPath string
	r.onActiveDown = func() {
		_, p := r.activeBound(t, "blue")
		seenPath = p
		body, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("down 시점에 결박 파일을 읽을 수 없다: %v", err)
			return
		}
		seenAtDown = string(body)
	}

	st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
	if st != StateCompleted || err != nil {
		t.Fatalf("state=%v err=%v", st, err)
	}

	if seenAtDown == "" {
		t.Fatal("down 훅이 불리지 않았다 — 시험이 실제 실행 시점을 보지 못했다")
	}
	if seenAtDown == evil {
		t.Fatalf("down이 변조된 내용으로 실행됐다(TOCTOU 창) — 결박 파일=%q", seenPath)
	}
	if seenAtDown != oldCompose {
		t.Fatalf("down이 검증된 바이트로 실행되지 않았다:\n기대=%q\n실제=%q", oldCompose, seenAtDown)
	}
	// 원본은 실제로 변조돼 있다 — 시험이 무음으로 통과한 것이 아님을 못박는다.
	if got, _ := os.ReadFile(genPath); string(got) != evil {
		t.Fatalf("변조 주입이 일어나지 않았다(시험 자체가 무효): %q", got)
	}

	// ⑶ 사용 후 스냅샷은 지워진다(tmp 격리 + 정리).
	if _, serr := os.Stat(seenPath); !os.IsNotExist(serr) {
		t.Fatalf("사용 후 스냅샷이 남았다: %q (err=%v)", seenPath, serr)
	}
}

// 스냅샷을 만들 수 없으면 배포를 시작하지 않는다 — 검증한 바이트를 결박하지 못한 채
// down하는 것이 이 결박이 막으려는 동작이다.
func TestActiveSlotSnapshotFailureIsFailClosed(t *testing.T) {
	r := newBGEmbedRig(t, SlotBlue)
	r.seedActive(t, "blue", "18081")

	// tmp 자리를 **파일**로 막아 디렉터리 생성을 실패시킨다.
	if err := os.WriteFile(filepath.Join(r.root, "core", "tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := r.dispatcher().Dispatch(context.Background(), embeddedManifest(embeddedCompose), store.FencingToken(7))
	if st != StateUnexecuted || !errors.Is(err, ErrComposeStorage) {
		t.Fatalf("state=%v err=%v, UNEXECUTED·저장 무결성 기대", st, err)
	}
	if r.blue.downs != 0 || r.green.ups != 0 {
		t.Fatalf("스냅샷 실패인데 실행이 일어났다: blue.down=%d green.up=%d", r.blue.downs, r.green.ups)
	}
}

// 스냅샷은 세대 회전·applied 인덱스 밖이다 — 잔존하더라도 GC가 세대로 세거나 복원 재료
// 판정에 끼어들지 않아야 한다.
func TestSnapshotIsolatedFromGenerationsAndIndex(t *testing.T) {
	w := newEmbedRig(t).ws
	path, err := w.WriteSnapshot("core", "down-blue-abc.yml", []byte("services: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Promote("core", compose.AppliedRecord{
		Revision: strings.Repeat("a", 64), Slot: "green", ImageDigest: validDigest,
		CommitSHA: "c1", RequestID: "r1", TS: "t", Status: compose.StatusApplied,
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.GC("core", nil); err != nil {
		t.Fatalf("스냅샷이 GC를 깨뜨렸다: %v", err)
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Fatalf("GC가 tmp 스냅샷을 건드렸다: %v", serr)
	}
	list, lerr := w.Applied("core")
	if lerr != nil || len(list) != 1 {
		t.Fatalf("스냅샷이 applied 인덱스에 섞였다: %+v err=%v", list, lerr)
	}
}
