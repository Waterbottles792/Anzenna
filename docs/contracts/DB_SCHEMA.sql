CREATE TABLE orgs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    stripe_customer_id TEXT,
    plan TEXT NOT NULL DEFAULT 'free',       -- free | pro | scale
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id),
    email TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id),
    key_hash TEXT NOT NULL,                  -- store hash, never plaintext
    key_prefix TEXT NOT NULL,                -- first 8 chars, shown in dashboard for identification
    label TEXT,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scan_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id),
    api_key_id UUID NOT NULL REFERENCES api_keys(id),
    direction TEXT NOT NULL,                 -- input | output
    verdict TEXT NOT NULL,                   -- allow | flag | block
    risk_score INT NOT NULL,
    categories TEXT[],
    latency_ms INT,
    -- do NOT store raw scanned text long-term by default (privacy); store a truncated hash/preview only
    text_preview TEXT,                       -- first ~100 chars, for dashboard display
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_scan_logs_org_created ON scan_logs(org_id, created_at DESC);

CREATE TABLE usage_counters (
    org_id UUID NOT NULL REFERENCES orgs(id),
    period_start DATE NOT NULL,
    scan_count INT NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, period_start)
);
