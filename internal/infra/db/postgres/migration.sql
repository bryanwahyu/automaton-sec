CREATE TABLE IF NOT EXISTS security_scans (
  id             varchar(64)  PRIMARY KEY,
  tenant_id      varchar(64)  NOT NULL,
  triggered_at   timestamptz  NOT NULL DEFAULT NOW(),
  tool           varchar(32)  NOT NULL,
  target         text,
  image          text,
  status         varchar(16)  NOT NULL,
  critical       integer       NOT NULL DEFAULT 0,
  high           integer       NOT NULL DEFAULT 0,
  medium         integer       NOT NULL DEFAULT 0,
  low            integer       NOT NULL DEFAULT 0,
  findings_total integer       NOT NULL DEFAULT 0,
  artifact_url   text,
  raw_format     varchar(16),
  duration_ms    bigint,
  source         varchar(32),
  commit_sha     varchar(64),
  branch         varchar(64)
);
CREATE INDEX IF NOT EXISTS idx_tenant_dt ON security_scans (tenant_id, triggered_at DESC);

CREATE TABLE IF NOT EXISTS security_analyze (
  id          varchar(64)  PRIMARY KEY,
  tenant_id   varchar(64)  NOT NULL,
  scan_id     varchar(64),
  file_url    text         NOT NULL,
  result_json jsonb        NOT NULL,
  created_at  timestamptz  NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_analyze_scan FOREIGN KEY (scan_id) REFERENCES security_scans(id)
);
CREATE INDEX IF NOT EXISTS idx_analyze_tenant_created ON security_analyze (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyze_scan ON security_analyze (scan_id);

CREATE TABLE IF NOT EXISTS security_scan_errors (
  id           BIGSERIAL    PRIMARY KEY,
  tenant_id    varchar(64)  NOT NULL,
  scan_id      varchar(64)  NOT NULL,
  tool         varchar(32),
  phase        varchar(32),
  message      text         NOT NULL,
  details_json jsonb,
  created_at   timestamptz  NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_err_scan FOREIGN KEY (scan_id) REFERENCES security_scans(id)
);
CREATE INDEX IF NOT EXISTS idx_err_tenant_created ON security_scan_errors (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_err_scan ON security_scan_errors (scan_id);

