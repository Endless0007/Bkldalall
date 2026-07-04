-- migrations/0001_init.sql

-- 1. DEVICES TABLE
-- Privacy-first: Only stores the hash and usage metrics. No PII.
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_hash TEXT UNIQUE NOT NULL, -- Enforced as 64 hex chars in app layer
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    verification_count INTEGER NOT NULL DEFAULT 0
);

-- 2. LICENSES TABLE
-- Core licensing engine. Optimized for atomic updates and operational tracking.
CREATE TABLE licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE NOT NULL, -- Enforced as ~40 chars in app layer
    status TEXT NOT NULL DEFAULT 'UNUSED' CHECK(status IN ('UNUSED', 'ACTIVE', 'REVOKED', 'EXPIRED')),
    plan TEXT NOT NULL,
    device_id INTEGER,
    created_at INTEGER NOT NULL,
    activated_at INTEGER,
    last_verified INTEGER,
    expires_at INTEGER,               -- Null for lifetime, Unix timestamp for subscriptions
    revoked_reason TEXT,              -- e.g., 'refund', 'chargeback', 'shared_key'
    created_by TEXT,                  -- e.g., 'admin', 'stripe', 'manual'
    batch_name TEXT,                  -- e.g., 'launch_batch_1', 'promo_2026'
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
);

-- 3. ACTIVATION LOGS TABLE
-- Immutable audit trail.
CREATE TABLE activation_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT NOT NULL,
    device_hash TEXT,
    action TEXT NOT NULL CHECK(action IN ('GENERATED', 'ACTIVATED', 'VERIFY', 'FAILED', 'RESET', 'REVOKED')),
    result TEXT NOT NULL CHECK(result IN ('SUCCESS', 'FAILED', 'DENIED')),
    timestamp INTEGER NOT NULL,
    worker_version TEXT
);

-- 4. SETTINGS TABLE
-- Single-row configuration table. The CHECK constraint ensures only one row can ever exist.
CREATE TABLE settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    database_version TEXT NOT NULL DEFAULT '1.0.0',
    backend_version TEXT NOT NULL DEFAULT '1.0.0',
    minimum_app_version TEXT NOT NULL DEFAULT '1.0.0',
    token_version INTEGER NOT NULL DEFAULT 1,
    maintenance_mode INTEGER NOT NULL DEFAULT 0
);

-- Seed the single allowed settings row
INSERT INTO settings (id, database_version, backend_version, minimum_app_version, token_version, maintenance_mode)
VALUES (1, '1.0.0', '1.0.0', '1.0.0', 1, 0);

-- 5. PERFORMANCE INDEXES
CREATE INDEX idx_licenses_status ON licenses(status);
CREATE INDEX idx_licenses_device_id ON licenses(device_id);
CREATE INDEX idx_activation_logs_license_key ON activation_logs(license_key);
CREATE INDEX idx_activation_logs_timestamp ON activation_logs(timestamp);