CREATE TABLE IF NOT EXISTS security_scans (
  id             varchar(64)  NOT NULL,
  tenant_id      varchar(64)  NOT NULL,
  triggered_at   datetime(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  tool           varchar(32)  NOT NULL,
  target         text,
  image          text,
  status         varchar(16)  NOT NULL,
  critical       int NOT NULL DEFAULT 0,
  high           int NOT NULL DEFAULT 0,
  medium         int NOT NULL DEFAULT 0,
  low            int NOT NULL DEFAULT 0,
  findings_total int NOT NULL DEFAULT 0,
  artifact_url   text,
  raw_format     varchar(16),
  duration_ms    bigint,
  source         varchar(32),
  commit_sha     varchar(64),
  branch         varchar(64),
  PRIMARY KEY (id),
  KEY idx_tenant_dt (tenant_id, triggered_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Stores AI analysis results
CREATE TABLE IF NOT EXISTS security_analyze (
  id          varchar(64)  NOT NULL,
  tenant_id   varchar(64)  NOT NULL,
  scan_id     varchar(64)  DEFAULT NULL,
  file_url    text         NOT NULL,
  result_json json         NOT NULL,
  created_at  datetime(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY idx_analyze_tenant_created (tenant_id, created_at),
  KEY idx_analyze_scan (scan_id),
  CONSTRAINT fk_analyze_scan FOREIGN KEY (scan_id) REFERENCES security_scans(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Stores scan errors for easier troubleshooting
CREATE TABLE IF NOT EXISTS security_scan_errors (
  id           BIGINT       NOT NULL AUTO_INCREMENT,
  tenant_id    varchar(64)  NOT NULL,
  scan_id      varchar(64)  NOT NULL,
  tool         varchar(32),
  phase        varchar(32),
  message      text         NOT NULL,
  details_json json,
  created_at   datetime(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY idx_err_tenant_created (tenant_id, created_at),
  KEY idx_err_scan (scan_id),
  CONSTRAINT fk_err_scan FOREIGN KEY (scan_id) REFERENCES security_scans(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
