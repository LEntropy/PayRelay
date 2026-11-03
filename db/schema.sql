SET NAMES utf8mb4;
-- PayRelay schema (MySQL 8.x, InnoDB, utf8mb4).
-- Loaded by the MySQL container on first start (docker-entrypoint-initdb.d).

CREATE DATABASE IF NOT EXISTS payrelay CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE payrelay;

-- Merchants (가맹점). mac_key signs every telegram the merchant sends; tps_limit feeds the
-- per-merchant token bucket in the gateway.
CREATE TABLE merchants (
  merchant_id  CHAR(10)      NOT NULL,
  name         VARCHAR(100)  NOT NULL,
  mac_key_hex  CHAR(64)      NOT NULL,
  status       ENUM('ACTIVE','SUSPENDED') NOT NULL DEFAULT 'ACTIVE',
  tps_limit    SMALLINT UNSIGNED NOT NULL DEFAULT 20,
  created_at   DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (merchant_id)
) ENGINE=InnoDB;

-- One row per payment. The card number itself is never stored: only BIN, last 4 digits and
-- an HMAC token (PCI DSS: do not keep what you do not need).
--
-- Status machine:
--   PENDING ─► APPROVED ─► CANCELED
--      │  └──► DECLINED
--      └──► TIMEOUT ─► NET_CANCELED          (VAN did not answer in time, reversal confirmed)
--                └──► REVERSAL_FAILED        (reversal unconfirmed: reconciliation decides)
CREATE TABLE transactions (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  pg_tx_id        CHAR(20)      NOT NULL,
  merchant_id     CHAR(10)      NOT NULL,
  order_no        VARCHAR(20)   NOT NULL,
  terminal_id     CHAR(8)       NOT NULL,
  trace_no        CHAR(6)       NOT NULL,
  amount          BIGINT UNSIGNED NOT NULL,
  currency        CHAR(3)       NOT NULL DEFAULT 'KRW',
  installment     TINYINT UNSIGNED NOT NULL DEFAULT 0,
  card_bin        CHAR(6)       NOT NULL,
  card_last4      CHAR(4)       NOT NULL,
  card_token      CHAR(64)      NOT NULL,
  status          ENUM('PENDING','APPROVED','DECLINED','TIMEOUT','NET_CANCELED','REVERSAL_FAILED','CANCELED') NOT NULL,
  resp_code       CHAR(4)       NULL,
  approval_no     CHAR(8)       NULL,
  cancel_approval CHAR(8)       NULL,
  van_latency_ms  INT UNSIGNED  NULL,
  client_ip       VARCHAR(45)   NOT NULL,
  requested_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  responded_at    DATETIME(3)   NULL,
  canceled_at     DATETIME(3)   NULL,
  updated_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_pg_tx (pg_tx_id),
  -- Idempotency: the same merchant order can be charged only once, even if the POS retries.
  UNIQUE KEY uq_merchant_order (merchant_id, order_no),
  KEY ix_status_time (status, requested_at),
  KEY ix_merchant_time (merchant_id, requested_at),
  KEY ix_card_token (card_token),
  CONSTRAINT fk_tx_merchant FOREIGN KEY (merchant_id) REFERENCES merchants (merchant_id)
) ENGINE=InnoDB;

-- Every state change, for dispute handling and audits.
CREATE TABLE tx_events (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  pg_tx_id    CHAR(20)     NOT NULL,
  event       VARCHAR(32)  NOT NULL,
  detail      VARCHAR(255) NULL,
  created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY ix_tx (pg_tx_id, id)
) ENGINE=InnoDB;

-- Protocol violations, bad MACs, rate limiting and bans, per source IP.
CREATE TABLE security_events (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  client_ip   VARCHAR(45)  NOT NULL,
  event       VARCHAR(32)  NOT NULL,
  merchant_id CHAR(10)     NULL,
  detail      VARCHAR(255) NULL,
  created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY ix_ip_time (client_ip, created_at),
  KEY ix_time (created_at)
) ENGINE=InnoDB;

-- What the PG expects the VAN to have booked, per transaction, for reconciliation (대사).
-- Net effect: approved and still standing = +amount, everything else = 0.
CREATE VIEW v_settlement AS
SELECT DATE(requested_at)      AS biz_date,
       merchant_id,
       pg_tx_id,
       order_no,
       amount,
       status,
       approval_no,
       CASE WHEN status = 'APPROVED' THEN amount ELSE 0 END AS net_amount
  FROM transactions;

-- Daily per-merchant totals for the dashboard and settlement reports.
CREATE VIEW v_daily_merchant AS
SELECT DATE(requested_at) AS biz_date,
       merchant_id,
       COUNT(*)                                             AS tx_count,
       SUM(status = 'APPROVED')                              AS approved_count,
       SUM(status = 'DECLINED')                              AS declined_count,
       SUM(status IN ('TIMEOUT','NET_CANCELED','REVERSAL_FAILED')) AS timeout_count,
       SUM(status = 'CANCELED')                              AS canceled_count,
       SUM(CASE WHEN status = 'APPROVED' THEN amount ELSE 0 END) AS net_amount
  FROM transactions
 GROUP BY DATE(requested_at), merchant_id;

-- Least privilege: the gateway may only read merchants and write transactions/events.
CREATE USER IF NOT EXISTS 'gateway'@'%' IDENTIFIED BY 'gateway-demo-pw';
GRANT SELECT ON payrelay.merchants TO 'gateway'@'%';
GRANT SELECT, INSERT, UPDATE ON payrelay.transactions TO 'gateway'@'%';
GRANT INSERT ON payrelay.tx_events TO 'gateway'@'%';
GRANT INSERT ON payrelay.security_events TO 'gateway'@'%';

-- The admin console only reads (unban goes through the gateway control port).
CREATE USER IF NOT EXISTS 'admin_ro'@'%' IDENTIFIED BY 'admin-demo-pw';
GRANT SELECT ON payrelay.* TO 'admin_ro'@'%';

-- Demo merchants. Keys are demo values (64 hex chars = 32 bytes).
INSERT INTO merchants (merchant_id, name, mac_key_hex, tps_limit) VALUES
  ('M000000001', '데모 쇼핑몰', '6d65726368616e742d312d64656d6f2d6b65792d303030303030303030303030', 20),
  ('M000000002', '데모 카페', '6d65726368616e742d322d64656d6f2d6b65792d303030303030303030303030', 5),
  ('M000000009', '부하 테스트용',  '6d65726368616e742d392d6c6f61642d6b65792d303030303030303030303030', 5000);
INSERT INTO merchants (merchant_id, name, mac_key_hex, status) VALUES
  ('M000000003', '정지된 가맹점', '6d65726368616e742d332d64656d6f2d6b65792d303030303030303030303030', 'SUSPENDED');
