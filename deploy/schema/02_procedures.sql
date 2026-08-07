-- deploy/schema/02_procedures.sql
--
-- 일곱 개의 락 전이(ADR-022 DT-12; ADR-024 §2.4 핸드셰이크) + 모드 append 프로시저
-- (ADR-027 DO-17 ⑵ 단조 version). 락 행은 오직 이 전이들을 통해서만 변경된다 — 어떤
-- 계정도 여기에 raw DML을 갖지 않는다. fencing-token 단조성, holder 조건, lease 검사,
-- 전이 가드는 프로시저 내부에 살기 때문에, EXECUTE할 수 있는 계정조차 owner/token/lease를
-- 위조할 수 없다(DB 권한으로 강제되는 CD-3 원자 계약). 같은 이유로 mode의 단조 version도
-- 프로시저 안(현재 max + 1 계산·삽입)에 가둔다 — 임의 version 삽입 경로를 없앤다.
--
-- 각 프로시저는 하나의 조건부 UPDATE와 OUT ok 플래그이며; 성공은 ROW_COUNT() = 1이다.
-- 어느 계정이 어느 전이를 호출할 수 있는지는 grant(03_grants)에서 분리된다:
-- PREEMPT/override = deploy-agent 전용; ACK/debt-resolve = cutoff 전용;
-- acquire/renew/release = 둘 다.
--
-- SQL SECURITY DEFINER는 EXECUTE 전용이고 테이블 권한이 없는 계정이 전이를 실행할 수
-- 있게 한다. ⚠ 이것이 MySQL에서 실제로 성립하는지(DEFINER 권한; EXECUTE가 그 외 어떤
-- 것도 누설하지 않음)는 [구현 검증] CDV-19 / ADR-022 R8이다. DEFINER 계정은 스키마
-- 소유자이며 프로비저닝 시점에 설정된다 — 여기에 하드코딩되지 않는다.

USE `deploy`;

DELIMITER $$

-- 전이 1 — 획득 (acquire). agent와 cutoff 둘 다 호출 가능(양방향 경합). 락이 비어
-- 있거나 lease가 만료된 경우에만 성공하며; fencing token이 증가하므로 동시 획득자 중
-- 정확히 하나가 승리한다(CD-3).
DROP PROCEDURE IF EXISTS `sp_lock_acquire` $$
CREATE PROCEDURE `sp_lock_acquire`(
  IN  p_holder_kind   VARCHAR(16),
  IN  p_holder_id     VARCHAR(255),
  IN  p_lease_seconds INT,
  OUT p_token         BIGINT UNSIGNED,
  OUT p_ok            TINYINT
)
SQL SECURITY DEFINER
BEGIN
  UPDATE `deploy_window_lock`
     SET `holder_kind`       = p_holder_kind,
         `holder_id`         = p_holder_id,
         `fencing_token`     = `fencing_token` + 1,
         `lease_expires_at`  = NOW(6) + INTERVAL p_lease_seconds SECOND,
         `preempt_requested` = 0,
         `preempt_requester` = NULL,
         `preempt_request_id`= NULL,
         `preempt_deadline`  = NULL,
         `safety_ack`        = 0
   WHERE `lock_id` = 1
     AND (`holder_kind` = 'NONE' OR `lease_expires_at` < NOW(6));
  IF ROW_COUNT() = 1 THEN
    SELECT `fencing_token` INTO p_token FROM `deploy_window_lock` WHERE `lock_id` = 1;
    SET p_ok = 1;
  ELSE
    SET p_token = NULL;
    SET p_ok = 0;
  END IF;
END $$

-- 전이 2 — lease 갱신 (renew / 보유 재확인). 둘 다. 호출자가 여전히 holder이고
-- (kind + id + token) lease가 만료되지 않은 동안에만 갱신한다.
DROP PROCEDURE IF EXISTS `sp_lock_renew` $$
CREATE PROCEDURE `sp_lock_renew`(
  IN  p_holder_kind   VARCHAR(16),
  IN  p_holder_id     VARCHAR(255),
  IN  p_token         BIGINT UNSIGNED,
  IN  p_lease_seconds INT,
  OUT p_ok            TINYINT
)
SQL SECURITY DEFINER
BEGIN
  UPDATE `deploy_window_lock`
     SET `lease_expires_at` = NOW(6) + INTERVAL p_lease_seconds SECOND
   WHERE `lock_id` = 1
     AND `holder_kind`     = p_holder_kind
     AND `holder_id`       = p_holder_id
     AND `fencing_token`   = p_token
     AND `lease_expires_at` >= NOW(6);
  SET p_ok = (ROW_COUNT() = 1);
END $$

-- 전이 3 — PREEMPT_REQUESTED 기록 (record preempt). deploy-agent 전용. 행을
-- 표시한다; holder는 그대로 남고 롤백은 아직 시작되지 않는다(ADR-024 §2.4 ⑶ ⑴).
-- 이미 대기 중인 preempt가 없는 BATCH_CUTOFF holder에 대해서만 유효하다.
DROP PROCEDURE IF EXISTS `sp_lock_record_preempt` $$
CREATE PROCEDURE `sp_lock_record_preempt`(
  IN  p_requester  VARCHAR(255),
  IN  p_request_id VARCHAR(255),
  IN  p_deadline   DATETIME(6),
  OUT p_ok         TINYINT
)
SQL SECURITY DEFINER
BEGIN
  UPDATE `deploy_window_lock`
     SET `preempt_requested`  = 1,
         `preempt_requester`  = p_requester,
         `preempt_request_id` = p_request_id,
         `preempt_deadline`   = p_deadline
   WHERE `lock_id` = 1
     AND `holder_kind`      = 'BATCH_CUTOFF'
     AND `preempt_requested` = 0;
  SET p_ok = (ROW_COUNT() = 1);
END $$

-- 전이 4 — 안전 경계 ACK (safety-boundary ack). cutoff 전용. 선점된 스케줄러가
-- BR-52 단계 경계에서 멈췄음을 기록한다. preempt가 대기 중이고 호출자가 현재
-- holder일 때에만 유효하다. ⚠ 전제조건(§2.4 경계 ⑷): cutoff 프로시저는 이것을
-- 호출하기 전에 "열림" 적재를 커밋하므로, ACK가 서 있다는 것은 적재가 커밋되었음을
-- 함의한다(fail-closed).
DROP PROCEDURE IF EXISTS `sp_lock_ack_safety_boundary` $$
CREATE PROCEDURE `sp_lock_ack_safety_boundary`(
  IN  p_holder_id VARCHAR(255),
  IN  p_token     BIGINT UNSIGNED,
  OUT p_ok        TINYINT
)
SQL SECURITY DEFINER
BEGIN
  UPDATE `deploy_window_lock`
     SET `safety_ack` = 1
   WHERE `lock_id` = 1
     AND `holder_kind`      = 'BATCH_CUTOFF'
     AND `holder_id`        = p_holder_id
     AND `fencing_token`    = p_token
     AND `preempt_requested` = 1;
  SET p_ok = (ROW_COUNT() = 1);
END $$

-- 전이 5 — override 우선 획득 (override preempt-acquire). deploy-agent 전용.
-- 긴급 롤백 인계: preempt가 기록되었고 AND holder가 정지를 ack했거나(safety_ack)
-- 그 lease가 만료된 뒤에만 성공한다(ADR-024 §2.4 ⑶). 락을 절대 무시하지 않는다 —
-- 새롭고 더 높은 fencing token으로 인계한다. 인계가 ACK 없이 lease 만료를 통한
-- 것이라면 스케줄러가 "열림"을 적재하기 전에 죽은 것이므로 open_debt가 설정된다
-- (§2.4 경계 ⑷).
DROP PROCEDURE IF EXISTS `sp_lock_override_acquire` $$
CREATE PROCEDURE `sp_lock_override_acquire`(
  IN  p_holder_id     VARCHAR(255),
  IN  p_lease_seconds INT,
  OUT p_token         BIGINT UNSIGNED,
  OUT p_ok            TINYINT
)
SQL SECURITY DEFINER
BEGIN
  UPDATE `deploy_window_lock`
     SET `open_debt`         = CASE WHEN `safety_ack` = 1 THEN `open_debt` ELSE 1 END,
         `holder_kind`       = 'AGENT',
         `holder_id`         = p_holder_id,
         `fencing_token`     = `fencing_token` + 1,
         `lease_expires_at`  = NOW(6) + INTERVAL p_lease_seconds SECOND,
         `preempt_requested` = 0,
         `preempt_requester` = NULL,
         `preempt_request_id`= NULL,
         `preempt_deadline`  = NULL,
         `safety_ack`        = 0
   WHERE `lock_id` = 1
     AND `preempt_requested` = 1
     AND (`safety_ack` = 1 OR `lease_expires_at` < NOW(6));
  IF ROW_COUNT() = 1 THEN
    SELECT `fencing_token` INTO p_token FROM `deploy_window_lock` WHERE `lock_id` = 1;
    SET p_ok = 1;
  ELSE
    SET p_token = NULL;
    SET p_ok = 0;
  END IF;
END $$

-- 전이 6 — 「열림」 채무 해소 (resolve open debt). cutoff 전용. 다음 cutoff 실행은
-- 누락된 "열림"을 적재한 뒤 채무를 지운다; 그 전까지는 그 영업일을 마감할 수 없다
-- (ADR-024 §2.4 경계 ⑷ / ⑻).
DROP PROCEDURE IF EXISTS `sp_lock_resolve_open_debt` $$
CREATE PROCEDURE `sp_lock_resolve_open_debt`(
  OUT p_ok TINYINT
)
SQL SECURITY DEFINER
BEGIN
  UPDATE `deploy_window_lock`
     SET `open_debt` = 0
   WHERE `lock_id` = 1
     AND `open_debt` = 1;
  SET p_ok = (ROW_COUNT() = 1);
END $$

-- 전이 7 — 해제 (release). 둘 다. 호출자가 현재 holder(kind + id + token)인 경우에만
-- 해제한다. fencing token은 리셋되지 않으며(단조), open_debt는 여기서 지워지지 않는다
-- (채무는 전이 6까지 release를 넘어 존속한다).
DROP PROCEDURE IF EXISTS `sp_lock_release` $$
CREATE PROCEDURE `sp_lock_release`(
  IN  p_holder_kind VARCHAR(16),
  IN  p_holder_id   VARCHAR(255),
  IN  p_token       BIGINT UNSIGNED,
  OUT p_ok          TINYINT
)
SQL SECURITY DEFINER
BEGIN
  UPDATE `deploy_window_lock`
     SET `holder_kind`       = 'NONE',
         `holder_id`         = NULL,
         `lease_expires_at`  = NULL,
         `preempt_requested` = 0,
         `preempt_requester` = NULL,
         `preempt_request_id`= NULL,
         `preempt_deadline`  = NULL,
         `safety_ack`        = 0
   WHERE `lock_id` = 1
     AND `holder_kind`   = p_holder_kind
     AND `holder_id`     = p_holder_id
     AND `fencing_token` = p_token;
  SET p_ok = (ROW_COUNT() = 1);
END $$

-- 모드 append — 단조 version 강제(ADR-027 DO-17 ⑵). 토글은 임의 version이 아니라
-- 「현재 max + 1」로만 들어간다: 대상별 현재 최대 version을 읽어 그 다음 값으로 INSERT하므로,
-- append된 행은 항상 최신(= Current가 반환하는 행)이 된다. 임의 version 삽입을 허용하면
-- 더 작은 version이 들어가 토글이 Current에 반영되지 않는 fail-open이 생긴다(현재 dev/v2인데
-- operational/v1이 삽입돼도 Current는 dev/v2 — 운영 토글 무반영). 계산·삽입을 프로시저
-- 내부 단일 문장에 가둬 임의 version 삽입 경로를 없앤다(락 전이와 같은 패턴, EXECUTE로만
-- 호출). 동시 두 호출이 같은 max를 읽어 같은 version을 노려도 UNIQUE(target, mode_version)가
-- 한쪽을 INSERT 시점에 거부한다 — 단조성이 두 계층(프로시저 계산 + UNIQUE)에서 강제된다.
-- target/mode의 유효성은 deploy_mode의 ENUM 컬럼이 INSERT 시점에 거른다.
DROP PROCEDURE IF EXISTS `sp_mode_append` $$
CREATE PROCEDURE `sp_mode_append`(
  IN p_target VARCHAR(32),
  IN p_mode   VARCHAR(16),
  IN p_actor  VARCHAR(255)
)
SQL SECURITY DEFINER
BEGIN
  INSERT INTO `deploy_mode` (`target`, `mode`, `mode_version`, `actor`)
  SELECT p_target, p_mode, COALESCE(MAX(`mode_version`), 0) + 1, p_actor
    FROM `deploy_mode`
   WHERE `target` = p_target;
END $$

DELIMITER ;
