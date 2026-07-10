CREATE TABLE diagnosis_sessions (
    session_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE actions (
    request_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES diagnosis_sessions(session_id) ON DELETE RESTRICT,
    tool TEXT NOT NULL,
    target_id TEXT,
    risk TEXT NOT NULL,
    summary TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    error_json TEXT
);

CREATE INDEX idx_actions_session_created ON actions(session_id, created_at);
CREATE INDEX idx_actions_state_expires ON actions(state, expires_at);

CREATE TABLE action_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL REFERENCES actions(request_id) ON DELETE RESTRICT,
    from_state TEXT,
    to_state TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_action_events_request ON action_events(request_id, event_id);

CREATE TABLE execution_plans (
    request_id TEXT PRIMARY KEY REFERENCES actions(request_id) ON DELETE RESTRICT,
    plan_json TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    target_version TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE sanitized_results (
    request_id TEXT PRIMARY KEY REFERENCES actions(request_id) ON DELETE RESTRICT,
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE audit_entries (
    sequence INTEGER PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    request_id TEXT,
    session_id TEXT,
    data_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE
);

CREATE INDEX idx_audit_request ON audit_entries(request_id, sequence);
CREATE INDEX idx_audit_session ON audit_entries(session_id, sequence);

CREATE TRIGGER audit_entries_no_update
BEFORE UPDATE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit entries are append-only');
END;

CREATE TRIGGER audit_entries_no_delete
BEFORE DELETE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit entries are append-only');
END;

CREATE TABLE idempotency_keys (
    client_request_id TEXT PRIMARY KEY,
    payload_hash TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE REFERENCES actions(request_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL
);

CREATE TABLE known_host_fingerprints (
    target_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL CHECK(port >= 1 AND port <= 65535),
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(target_id, hostname, port)
);
