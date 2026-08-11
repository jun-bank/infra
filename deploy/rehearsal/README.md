# 로컬 배포 리허설 (#15 S2-3 실행 층)

이 디렉토리는 `internal/dispatch` 실행 층이 밟는 단계 — **이미지 pull(digest 고정) →
compose up(green) → CD-1 헬스 → compose down** — 을 무해한 이미지로 이 개발 머신에서 한
번 완주해 보기 위한 것이다. 자동화된 테스트가 아니라 **사람이 손으로 돌리는 리허설**이다
(단위 테스트는 실제 docker 없이 명령 조립·상태 매핑을 검증한다 — `go test ./internal/...`).

정본: ADR-027 DO-18·DO-23, `operations/cicd.md` CD-1·CD-4.

## 전제

- 이 머신은 `docker` 그룹 소속이라 sudo 프리픽스 없이 직접 실행한다(실호스트는
  `DEPLOY_SUDO_PREFIX="sudo -S"` + `DEPLOY_SUDO_PASSWORD`).
- `docker compose` v2 사용.
- 리허설 대상 이미지 = `traefik/whoami`(임의 GET에 200을 돌려주는 무해 이미지).

## 절차

아래는 Executor가 조립하는 argv와 **정확히 같은 형태**의 명령이다(sudo 프리픽스 없음).

### 0. digest 확정 (DO-18 ⑵ — 태그가 아니라 digest로 고정)

태그로 띄우지 않는다. 실제 digest를 확정해 `<repo>@sha256:...` 로 고정한다:

```sh
docker pull traefik/whoami:latest
# RepoDigest를 읽는다 (registry가 준 내용 주소)
docker inspect --format '{{index .RepoDigests 0}}' traefik/whoami:latest
# 예: traefik/whoami@sha256:<64 hex>
export REHEARSAL_IMAGE='traefik/whoami@sha256:<위에서 나온 digest>'
export REHEARSAL_GREEN_PORT=18080
export COMPOSE=deploy/rehearsal/compose.yml
export PROJECT=whoami-green
```

### 1. pull (digest 고정)

```sh
docker pull "$REHEARSAL_IMAGE"
```

pull이 실패하면(digest 불일치·not found·연결 실패) 실행 층은 **UNEXECUTED**(부작용 0)를
낸다. compose를 건드리지 않는다(CD-4 ②).

### 2. up (green · --no-build · digest 참조는 env 치환으로 주입)

```sh
REHEARSAL_IMAGE="$REHEARSAL_IMAGE" \
  docker compose -f "$COMPOSE" -p "$PROJECT" up -d --no-build
```

compose 파일이 `image: ${REHEARSAL_IMAGE}` 로 이 참조를 읽어, digest 고정 이미지가 실제로
뜬다. `--no-build` — 호스트에 빌드 도구가 없다(DO-4/P1).

### 3. CD-1 헬스 (HTTP 준비성 프로브 + 재시작 횟수 안정)

green 준비성 URL에 GET → **2xx가 연속 N회**(간격 T, 상한 D) + **컨테이너 재시작 횟수가
증가하지 않음** 일 때만 healthy다. compose 내장 healthcheck를 CD-1로 읽지 않는다.

```sh
# 준비성 프로브 (whoami는 임의 GET에 200)
curl -fsS "http://127.0.0.1:${REHEARSAL_GREEN_PORT}/" >/dev/null && echo "2xx"

# 그린 위장 방어 — 재시작 횟수를 읽는다(대기 시작 시 baseline, 대기 중 불변이어야 통과)
docker inspect -f '{{.RestartCount}}' "${PROJECT}-app-1"
```

agent가 자동으로 하는 판정: baseline 재시작 횟수를 한 번 읽고, 대기 중 어느 프로브에서든
값이 증가하면 즉시 실패(재시작 정책이 판정을 감추지 못하게 — CD-1). 헬스 실패면 실행 층은
green을 `down`해 **미전환**(net-0)으로 되돌린다(롤백 아님 — CD-4 ④).

환경 변수로 튜닝(agent 기준): `DEPLOY_HEALTH_SUCCESS_THRESHOLD`(N)·`DEPLOY_HEALTH_INTERVAL`
(T)·`DEPLOY_HEALTH_TIMEOUT`·`DEPLOY_HEALTH_DEADLINE`(D). 기본값 N=3·T=2s·timeout=3s·D=60s
(모두 [구현 검증] CDV-1 — 리허설 실측으로 정한다). 재시작 검사 대상 컨테이너는 설정으로
지정하지 않고 compose 프로젝트(`-p $PROJECT`)에서 파생한다 — 방어선은 항상 켜진다(CD-1).

### 4. down (green 프로젝트만 · 이미지는 남긴다 — RL-5)

```sh
docker compose -f "$COMPOSE" -p "$PROJECT" down
```

`-p "$PROJECT"` 로 green 프로젝트만 종료한다(공유·무범위 down 금지 — 나중에 blue가 있을
때 blue를 죽이지 않게). `--rmi` 를 붙이지 않는다 — 이미지를 지우면 RL-5의 호스트 로컬
되돌림이 성립하지 않는다.

## 상태 매핑 확인 (DO-16)

| 리허설 상황 | 기대 RemoteState |
|---|---|
| pull 실패(잘못된 digest 주입) | UNEXECUTED |
| up 성공 + 헬스 통과 | COMPLETED |
| 헬스 실패(잘못된 준비성 URL) → down 성공 | UNEXECUTED (미전환) |
| 헬스 실패 → down도 실패(모의) | UNKNOWN (green 잔존 가능) |

## 소요 시간 기록

리허설 1회(pull + up + 헬스 통과)의 소요를 잰다 — ADR-027 `[구현 검증]`(SSH/실행 1회
소요)과 CD-3 lease 하한(CDV-4)의 입력이다.

```sh
time ( docker pull "$REHEARSAL_IMAGE" && \
  REHEARSAL_IMAGE="$REHEARSAL_IMAGE" docker compose -f "$COMPOSE" -p "$PROJECT" up -d --no-build )
```
