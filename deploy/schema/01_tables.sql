-- deploy/schema/01_tables.sql
--
-- 배포 스키마의 테이블. 정본: ADR-022 DT-9, DT-12; ADR-027 DO-10, DO-17.
--
-- 설계 속성(DT-12 ⑶): 배포 스키마에는 자유롭게 갱신되는 행이 없다. 락 행은 일곱 개의
-- 전이 프로시저(02_procedures)를 통해서만 바뀌며; 그 밖의 모든 테이블은 append-only다
-- (INSERT만; 최신 행이 현재 상태). 이는 두 번 강제된다 — 이 정의들과 grant
-- (03_grants)에 의해. ⚠ append-only가 grant만으로 강제될 수 있는지, 아니면 trigger/
-- REVOKE 조합이 필요한지는 [구현 검증] CDV-19다(ADR-022 R8).

USE `deploy`;

-- deploy_window_lock — 단일 행 배포 윈도우 락(DT-9 ⑴).
-- 이 락의 제공자는 어떤 애플리케이션이 아니라 DB 자체이므로, core가 내려가 있어도
-- 락을 원자적으로 획득할 수 있다(ADR-022 §2.1, 잔여-1).
-- 이 락은 동일한 행에서 두 주체가 경합한다: deploy-agent와 batch/cutoff 스케줄러
-- (CD-3 원자 계약; 양방향 경합).
-- 오직 전이 프로시저를 통해서만 변경된다 — 어떤 계정도 여기에 raw DML을 갖지 않는다.
CREATE TABLE IF NOT EXISTS `deploy_window_lock` (
  -- lock_id는 테이블을 단일 행에 고정한다(DT-9 ⑴: 단일 행 락).
  `lock_id`            TINYINT UNSIGNED NOT NULL DEFAULT 1,
  -- holder_kind / holder_id — 지금 누가 락을 보유하는가.
  `holder_kind`        ENUM('NONE','AGENT','BATCH_CUTOFF') NOT NULL DEFAULT 'NONE',
  `holder_id`          VARCHAR(255) NULL,
  -- fencing_token — 엄격히 단조 증가; 모든 (override_)acquire마다 증가하고, 절대
  -- 감소하지 않으며, 리셋되지 않는다(CD-3 fencing; 낡은 holder는 다음 재확인 시
  -- 토큰 불일치로 감지된다 — ADR-024 §2.4 ⑷).
  `fencing_token`      BIGINT UNSIGNED NOT NULL DEFAULT 0,
  -- lease_expires_at — lease 지평; lease가 만료되었다는 것은 holder가 갱신하지
  -- 않는다는 것, 즉 돌고 있지 않다는 뜻이다(ADR-024 §2.4 ⑵: "갱신이 없다 = 돌고 있지 않다").
  `lease_expires_at`   DATETIME(6) NULL,
  -- Preempt 핸드셰이크 필드(ADR-024 §2.4 경계 ⑶ — "정지 후 인계"이며, 단일 UPDATE가
  -- 아니다): PREEMPT_REQUESTED가 먼저 기록되고, holder는 그대로 남으며, holder가
  -- 정지를 ack하거나 lease가 만료되기 전까지 롤백은 시작되지 않는다.
  `preempt_requested`  TINYINT(1) NOT NULL DEFAULT 0,
  `preempt_requester`  VARCHAR(255) NULL,
  `preempt_request_id` VARCHAR(255) NULL,
  `preempt_deadline`   DATETIME(6) NULL,
  -- safety_ack — 선점된 스케줄러가 BR-52 단계 경계에서 멈췄음을 기록한 것. Override는
  -- 이것이 설정되었거나 OR lease가 만료된 뒤에만 인계할 수 있다(ADR-024 §2.4 경계
  -- ⑶ ⑵-⑶). "열림" 적재가 cutoff 프로시저에 의해 커밋된 뒤에만 설정된다(경계 ⑷
  -- 전제조건; fail-closed).
  `safety_ack`         TINYINT(1) NOT NULL DEFAULT 0,
  -- open_debt — "「열림」 미적재 채무"(ADR-024 §2.4 경계 ⑷): lease 만료를 통해 인계가
  -- 일어났을 때 설정된다(스케줄러가 "열림"을 적재하지 못하고 죽음). 다음 cutoff 실행은
  -- 이것이 해소되기 전까지 그 영업일을 마감할 수 없다.
  `open_debt`          TINYINT(1) NOT NULL DEFAULT 0,
  `updated_at`         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                     ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`lock_id`),
  CONSTRAINT `ck_single_row` CHECK (`lock_id` = 1)
) ENGINE=InnoDB;

-- 단일 행을 시드한다. 멱등적: 재실행해도 기존 행은 건드리지 않는다.
INSERT INTO `deploy_window_lock` (`lock_id`, `holder_kind`, `fencing_token`)
VALUES (1, 'NONE', 0)
ON DUPLICATE KEY UPDATE `lock_id` = `lock_id`;

-- deploy_request_ledger — 재생 방어 예약 ledger(ADR-027 DO-10 ⑶⑷).
-- Append-only. requestId와 jti는 어떤 부작용이 있기 전에 예약된다; UNIQUE 제약은
-- 재생(동일 requestId, 또는 재사용된 OIDC jti)을 재실행 대신 INSERT 시점에 요란하게
-- 실패시킨다. 예약은 삭제할 수 없으므로(append-only, DT-12 ⑵) 재생 방어는 writer의
-- 선의에 의존하지 않는다.
CREATE TABLE IF NOT EXISTS `deploy_request_ledger` (
  `request_id`  VARCHAR(255) NOT NULL,
  `jti`         VARCHAR(255) NULL,
  `body_digest` VARCHAR(128) NOT NULL,   -- 동일 requestId + 다른 digest = 거부(DO-10 ⑷)
  `reserved_at` DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`request_id`),
  UNIQUE KEY `uq_jti` (`jti`)
) ENGINE=InnoDB;

-- deploy_mode — 대상별 mode, 단조 증가하는 버전을 가진 append-only(ADR-027 DO-17 ⑵).
-- 토글은 덮어쓰기가 아니라 새 행이므로, "누가·언제·무엇으로 바꿨나"가 절대 유실되지
-- 않는다(DT-12 ⑵). 대상별 최신 행이 현재 mode이며; 버전은 토글 대 요청 경쟁을 닫는다
-- (락 획득 시 원자적으로 검사 — DO-17 ⑴). fail-closed 기본값은 operational이다(DO-17 ⑷).
CREATE TABLE IF NOT EXISTS `deploy_mode` (
  `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  -- target — 배포 대상의 닫힌 집합(ADR-027 DO-20 v0.5: 2026-08-12에 셋 → 넷. 게이트웨이는
  -- 우리 배포물·우리 호스트라 엣지 제외 근거에 해당하지 않는다). ENUM이라 그 밖의 값은
  -- INSERT 시점에 거부된다 — 닫힌 집합이 DB에서도 한 번 더 강제된다.
  `target`       ENUM('core','settlement','ledger','gateway') NOT NULL,
  `mode`         ENUM('dev','operational') NOT NULL,
  `mode_version` BIGINT UNSIGNED NOT NULL,   -- 대상별 단조 증가 = 그 append
  `actor`        VARCHAR(255) NOT NULL,       -- 인증된 subject에서 파생(DO-12 ⑶)
  `changed_at`   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_target_version` (`target`, `mode_version`)
) ENGINE=InnoDB;

-- deploy_history — append-only 배포 이력(DT-9 ⑵). 요청의 모든 생애주기 전이
-- (reserved -> progress -> step result -> completed / rejected), 그리고 락
-- acquire/release 시각과 fencing token이 각각 새 행이며; 최신 행이 현재 상태다.
-- INSERT만 — UPDATE/DELETE 없음 — 이므로 "배포 이력이 곧 사실"을 writer가 다시 쓸 수
-- 없다(C8-audit 형태, DT-12 ⑵). 락과 동일한 스키마에 살기 때문에, "락을 잡은 시각과
-- 배포 이력이 맞나"는 하나의 읽기 트랜잭션에서 판정된다(ADR-022 §2.1, 잔여-2).
CREATE TABLE IF NOT EXISTS `deploy_history` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `event_at`        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `request_id`      VARCHAR(255) NOT NULL,
  -- event_type: RESERVED / PROGRESS / STEP_RESULT / COMPLETED / REJECTED /
  -- LOCK_ACQUIRED / LOCK_RELEASED / PREEMPT / SAFETY_ACK / OVERRIDE_ACQUIRED.
  `event_type`      VARCHAR(32) NOT NULL,
  `target`          ENUM('core','settlement','ledger','gateway') NULL,  -- DO-20 v0.5 — 넷
  `commit_sha`      VARCHAR(64)  NULL,
  `manifest_digest` VARCHAR(128) NULL,
  `step`            VARCHAR(64)  NULL,   -- CD-4 스텝 이름
  `result`          VARCHAR(32)  NULL,   -- 예: UNEXECUTED / DONE / UNKNOWN (DO-16)
  `reject_reason`   VARCHAR(512) NULL,   -- RL-8: 기록된 거부 사유
  `fencing_token`   BIGINT UNSIGNED NULL,
  `detail`          JSON NULL,
  PRIMARY KEY (`id`),
  KEY `ix_request` (`request_id`, `event_at`)
) ENGINE=InnoDB;
