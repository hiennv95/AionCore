-- Refresh-token rotation grants (ADR-022). One row per issued session. Stores
-- ids and timestamps only, never a token: the current pair can be re-signed
-- byte-for-byte from `current_jti` and the stored times (HS256 is deterministic),
-- which is how a retry inside the grace window gets the same successor.

CREATE TABLE IF NOT EXISTS refresh_grants (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT,
    current_jti TEXT NOT NULL,
    -- Times of the current pair, in seconds (JWT iat/exp).
    issued_at INTEGER NOT NULL,
    access_expires_at INTEGER NOT NULL,
    refresh_expires_at INTEGER NOT NULL,
    -- The jti the current one replaced, and when (ms); accepted for a short grace.
    previous_jti TEXT,
    rotated_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_grants_user ON refresh_grants(user_id);
