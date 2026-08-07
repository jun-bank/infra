-- deploy/schema/00_schema.sql
--
-- 배포 스키마: 공유 MySQL 클러스터의 네 번째 스키마다(ADR-022 DT-1, DT-9). 어떤
-- 비즈니스 컨텍스트가 아니라 배포 도메인이 소유한다. 운영 기록 — 배포 윈도우 락,
-- 요청/멱등성 ledger, mode, history — 을 담으며, 그 자체는 배포 대상이 아니다
-- (ADR-027 DO-20). money 데이터를 담지 않으며 정산 읽기에 들어가지 않는다
-- (ADR-022 DT-4/DT-7: T2/T4의 영향을 받지 않음).
--
-- 정본: ADR-022 DT-9(스키마 존재), DT-1(단일 클러스터).

CREATE SCHEMA IF NOT EXISTS `deploy`
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_0900_ai_ci;

USE `deploy`;
