# infra 개발 여정 — 배포 인프라를 만들며 한 고민들

이 폴더는 infra repo의 개발 과정을 PR 단위로 기록한 문서 모음이다. 각 문서는 그 PR이 풀려던 문제에서 출발해, 검토한 선택지와 채택 이유, 그리고 그 선택이 코드로 어떻게 나타났는지를 순서대로 담는다. 설계 원본(ADR)이 "무엇을 하기로 했나"의 정본이라면, 여기는 "왜 그렇게 됐고 만들면서 무엇이 바뀌었나"를 읽는 곳이다.

## 이 저장소의 역할

infra는 jun-bank의 배포 파이프라인 중 **수신·검증·실행** 축을 담당한다. 각 서비스 repo(core·gateway)의 CI가 이미지를 빌드하고 서명된 배포 요청(manifest)을 발행하면, 오라클 엣지를 거쳐 집 서버(.9)의 배포 agent가 그 요청을 받는다. agent는 두 겹의 관문(HMAC 서명, OIDC 신원 검증)을 통과한 요청만 실행하며, 실행은 배포 창 락 안에서 블루-그린 전환 또는 재기동 교체로 이뤄진다. 배포할 이미지는 digest로, 실행할 compose 정의는 서명에 동봉된 내용으로 고정되어 있어 호스트에 놓인 파일이 몰래 실행되는 경로가 없다.

이 구조의 설계 정본은 ADR-027(배포 오케스트레이션)·ADR-030(배포물 전달)·ADR-031(블루-그린 전환)이고, 운영 규칙은 `docs/operations/cicd.md`(docs repo)가 소유한다. 이 폴더의 문서는 그 결정들이 코드가 되는 과정의 기록이다.

## 여정 지도 — 마일스톤 세 개

**S0 — 기반.** 프로젝트 레이아웃과 배포 이력·락을 담는 DB 스키마를 먼저 세웠다. 코드보다 "배포 기록을 어디에 어떤 계약으로 남기나"가 먼저였다.

**S1 — 수신 관문.** 요청을 받되 아무것도 실행하지 않는 단계다. HTTP 골격, 게이트 1(HMAC 서명·requestId 멱등), 게이트 2(OIDC claim 행렬), 그리고 모드 조회의 fail-closed까지 — "실행하지 않는 상태에서 거절부터 올바르게"를 만들었다.

**S2 — 실행.** 배포 창 락, HTTP와 오케스트레이션의 배선, 이미지 pull과 compose up, JWKS 실검증을 거쳐 블루-그린 전환에 도달했다. 이후 리뷰와 실사고(false-UNKNOWN)가 남긴 갭을 후속 이슈로 하나씩 닫았다 — 실행 실패의 관측 분리, 사후조건 identity 결박, repo별 allowlist, 그리고 마지막으로 compose 동봉 실행 결박까지.

## 문서 목록 (PR 순서)

아래 목록이 곧 읽기 순서다 — 각 PR은 연결된 이슈와 한 쌍이고, 앞 PR이 남긴 갭이 다음 이슈가 되는 구조로 이어진다.

| PR | 이슈 | 문서 | 한 줄 |
|---|---|---|---|
| #2 | #1 | [pr-02-layout-schema.md](pr-02-layout-schema.md) | 레이아웃과 배포 스키마 DDL — 기록의 계약부터 |
| #7 | #3 | [pr-07-http-skeleton.md](pr-07-http-skeleton.md) | HTTP 골격 — 아직 아무것도 실행하지 않는 서버 |
| #8 | #4 | [pr-08-hmac-gate1.md](pr-08-hmac-gate1.md) | 게이트 1 — HMAC 서명과 requestId 멱등 |
| #10 | #5 | [pr-10-oidc-gate2.md](pr-10-oidc-gate2.md) | 게이트 2 — OIDC claim 검증 행렬 |
| #12 | #6 | [pr-12-mode-failclosed.md](pr-12-mode-failclosed.md) | 모드 조회 — 모르면 실행하지 않는다 |
| #16 | #13 | [pr-16-window-lock.md](pr-16-window-lock.md) | 배포 창 락 — 획득·fencing 재확인·해제 |
| #18 | #14 | [pr-18-http-orchestration.md](pr-18-http-orchestration.md) | HTTP→오케스트레이션 배선 |
| #22 | #15 | [pr-22-local-dispatch.md](pr-22-local-dispatch.md) | 로컬 dispatch — pull·up·헬스 |
| #24 | #11 | [pr-24-jwks.md](pr-24-jwks.md) | JWKS 실 공개키 페치 |
| #25 | (#9) | [pr-25-false-unknown.md](pr-25-false-unknown.md) | false-UNKNOWN 사건 — env 주입 누락 |
| #27 | #26 | [pr-27-blue-green.md](pr-27-blue-green.md) | 블루-그린 전환 실행 |
| #29 | #28 | [pr-29-oidc-allowlist.md](pr-29-oidc-allowlist.md) | repo별 allowlist·repo↔target 결박 |
| #30 | #20·#21 | [pr-30-outcome-identity.md](pr-30-outcome-identity.md) | Outcome 분리·identity 결박 |
| #31 | #19 | [pr-31-compose-embed.md](pr-31-compose-embed.md) | compose 동봉 실행 결박 — S2의 마지막 조각 |
| #34·#37·#38·#36 | S3 | [pr-34-38-satellite-transport.md](pr-34-38-satellite-transport.md) | 위성으로 배포를 넓히다 — 재슬라이스 3조각(전송·fencing·재개)+실배선·CDT-1 종결 |

S3(위성 배포)는 코드 전 재슬라이스로 3조각(#34 전송·#37 fencing·#38 자동 재개)으로 나뉘고 #36 실배선으로 정산(.158)·원장(.164)이 실동작한다 — 배포 대상 넷 완성. PR 단위가 아니라 여정 종합 1편으로 읽는다.

전체 아키텍처 해설과 설계 패턴 문서는 docs repo의 `study/tech/infra-journey/`에 있다 — 이 폴더가 PR 단위의 세로 읽기라면 그쪽은 구조의 가로 읽기다.
