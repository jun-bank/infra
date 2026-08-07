-- deploy/schema/03_grants.sql
--
-- 두 개의 배포 스키마 계정(ADR-022 DT-10, DT-11)과 그 권한 단위 = raw DML이 아니라
-- "정의된 연산"이다(DT-12). 정본:
--   - DT-10  deploy-agent: 배포 스키마 전용; core/settlement/ledger에 단 한 셀도
--            아니다(R7은 무관용). 읽기 + 정의된 연산.
--   - DT-11  cutoff-lock:  락 테이블 SELECT + 전이 EXECUTE만; history/ledger/mode
--            접근은 전혀 없음.
--   - DT-12  두 계정 모두 락 행에 raw UPDATE/DELETE를 갖지 않는다; 각 전이를 호출할
--            수 있는 계정은 분리된다; history는 INSERT 전용이다.
--
-- ⚠ VALUES 0 / SECRETS 0: 아래 비밀번호는 플레이스홀더다. 실제 자격증명은 시크릿
-- 스토어에서 대역외로 프로비저닝되며 절대 커밋되지 않는다. 여기서 호스트는 이식성을
-- 위해 '%'이며; 프로비저닝은 반드시 두 계정을 LAN으로 제한해야 한다(DT-10 ⑶ / IN-5 —
-- DB는 인터넷에 노출되지 않는다). grant가 MySQL에서 실제로 이 최소 형태를 표현하는지는
-- [구현 검증] CDV-19 / ADR-022 R7·R8이다.

-- =============================================================================
-- deploy-agent 계정 (DT-10)
-- =============================================================================
CREATE USER IF NOT EXISTS 'deploy_agent'@'%'
  IDENTIFIED BY '__PLACEHOLDER_PROVISIONED_FROM_SECRET_STORE__';

-- 락 행: SELECT만(읽기/비교용). raw DML 없음(DT-12).
GRANT SELECT ON `deploy`.`deploy_window_lock` TO 'deploy_agent'@'%';

-- agent가 호출할 수 있는 락 전이: acquire, renew, release는 ★ agent 역할 wrapper만
-- (kind='AGENT' 결박 — S2-1). record_preempt, override_acquire는 agent 전용.
-- ⚠ 공유 impl(sp_lock_*_impl)에는 EXECUTE를 주지 않는다 — 그래야 상대 kind로 호출할 수
-- 있는 경로가 없다. ack_safety_boundary·resolve_open_debt도 아님(cutoff 전용 — DT-12).
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_lock_acquire_agent`    TO 'deploy_agent'@'%';
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_lock_renew_agent`      TO 'deploy_agent'@'%';
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_lock_record_preempt`   TO 'deploy_agent'@'%';
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_lock_override_acquire` TO 'deploy_agent'@'%';
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_lock_release_agent`    TO 'deploy_agent'@'%';

-- Ledger, mode, history: INSERT + SELECT만. Append-only — UPDATE/DELETE 없음 —
-- 이므로 재생 ledger와 history를 writer가 다시 쓸 수 없다(DT-12 ⑵; C8-audit 형태).
-- "배포 이력이 곧 사실"은 그것을 쓰는 계정이 지울 수 없다.
GRANT SELECT, INSERT ON `deploy`.`deploy_request_ledger` TO 'deploy_agent'@'%';
GRANT SELECT, INSERT ON `deploy`.`deploy_mode`           TO 'deploy_agent'@'%';
GRANT SELECT, INSERT ON `deploy`.`deploy_history`        TO 'deploy_agent'@'%';

-- 모드 토글의 유일한 쓰기 경로 = sp_mode_append (ADR-027 DO-17 ⑵ 단조 version). store는
-- 임의 version을 INSERT하지 않고 이 프로시저를 EXECUTE해 「현재 max + 1」로만 append한다.
-- (위 deploy_mode INSERT grant는 append-only 계약을 위한 것이며, 단조 version 쓰기는
-- 프로시저를 경유한다.)
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_mode_append` TO 'deploy_agent'@'%';

-- 다른 어떤 스키마에도 GRANT 없음. 그 부재가 곧 강제다(DT-10 ⑵): deploy-agent는
-- core/settlement/ledger에 접근이 전혀 없다 — 읽기 포함(R7).

-- =============================================================================
-- cutoff-lock 계정 (DT-11)  — batch/cutoff 스케줄러의 락 경합 계정
-- =============================================================================
CREATE USER IF NOT EXISTS 'cutoff_lock'@'%'
  IDENTIFIED BY '__PLACEHOLDER_PROVISIONED_FROM_SECRET_STORE__';

-- 락 행: SELECT만(비교 + 채무 읽기). raw DML 없음(DT-12 — v0.3의 "SELECT + UPDATE"에서
-- "SELECT + 전이 EXECUTE"로 좁혀짐).
GRANT SELECT ON `deploy`.`deploy_window_lock` TO 'cutoff_lock'@'%';

-- cutoff 계정이 호출할 수 있는 락 전이: acquire, renew, release는 ★ cutoff 역할 wrapper만
-- (kind='BATCH_CUTOFF' 결박 — S2-1). ack_safety_boundary, resolve_open_debt는 cutoff 전용.
-- ⚠ 공유 impl에는 EXECUTE 없음. record_preempt·override_acquire도 아님(agent 전용).
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_lock_acquire_cutoff`      TO 'cutoff_lock'@'%';
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_lock_renew_cutoff`        TO 'cutoff_lock'@'%';
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_lock_ack_safety_boundary` TO 'cutoff_lock'@'%';
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_lock_resolve_open_debt`   TO 'cutoff_lock'@'%';
GRANT EXECUTE ON PROCEDURE `deploy`.`sp_lock_release_cutoff`      TO 'cutoff_lock'@'%';

-- history/ledger/mode 접근 없음, 다른 스키마도 없음(DT-11): cutoff 계정은 정확히
-- 하나의 경계 객체 — 락 테이블 — 만 건드리고 그 밖에는 아무것도 건드리지 않는다.
