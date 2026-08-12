-- deploy/schema/04_alter_target_gateway.sql
--
-- 배포 대상 enum 확장 — 셋(core·settlement·ledger) → 넷(+ gateway).
-- 정본: ADR-027 DO-20 v0.5(2026-08-12 재판정 — ADR-031 BG-1이 내부 게이트웨이(SCG)를
-- 라우팅 정본으로 세우면서 상시 실행 서비스가 하나 늘었고, 그 갱신 경로가 배포 대상 밖이면
-- 사람 손 배포(RL-7 위반) 아니면 방치가 된다. 게이트웨이는 우리 배포물·우리 호스트라
-- 엣지 제외 근거에 해당하지 않는다).
--
-- 이 파일은 **이미 적재된 기존 DB**를 위한 마이그레이션이다. 새로 만드는 DB는
-- 01_tables.sql이 이미 넷을 담고 있으므로 이 파일이 필요 없다(적재해도 무해하다 —
-- 결과 정의가 같다).
--
-- ⚠️ 실행 전 확인:
--   - 배포 창 락이 비어 있을 때(배포·커트오프 미진행) 실행한다. ALTER는 테이블 메타데이터
--     락을 잡으므로 진행 중 배포의 이력 append와 겹치면 그 배포가 대기·실패할 수 있다.
--   - 두 ALTER는 값을 **추가만** 한다(기존 값의 순서·이름을 바꾸지 않는다) — 기존 행의
--     저장 값은 그대로 유지된다. 순서를 바꾸거나 값을 지우면 기존 행이 조용히 재해석되므로
--     그렇게 하지 않는다.
--   - NULL 허용 여부·기본값은 원 정의를 그대로 유지한다(deploy_mode = NOT NULL,
--     deploy_history = NULL). MODIFY는 컬럼 정의 전체를 대체하므로 빠뜨리면 제약이 바뀐다.
--
-- 검증(실행 후):
--   SHOW COLUMNS FROM `deploy`.`deploy_mode`    LIKE 'target';
--   SHOW COLUMNS FROM `deploy`.`deploy_history` LIKE 'target';
--   -- 둘 다 enum(...,'gateway') 이어야 한다.

USE `deploy`;

ALTER TABLE `deploy_mode`
  MODIFY COLUMN `target` ENUM('core','settlement','ledger','gateway') NOT NULL;

ALTER TABLE `deploy_history`
  MODIFY COLUMN `target` ENUM('core','settlement','ledger','gateway') NULL;
