-- Client devices allowed to use this host without an account login (ADR-011).
--
-- Every token issued to the Flutter desktop app, a paired phone or a paired
-- browser carries the device id; revoking the row makes those tokens fail on
-- the next request. Pairing handshakes are short-lived and kept in memory.

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    -- desktop_app | mobile | browser
    kind TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id, created_at);
