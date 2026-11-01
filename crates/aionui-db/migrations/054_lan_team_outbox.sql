CREATE TABLE IF NOT EXISTS lan_team_outbox (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    peer_id TEXT NOT NULL REFERENCES network_peers(id) ON DELETE CASCADE,
    remote_team_id TEXT NOT NULL,
    content TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'delivered', 'revoked')),
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS lan_team_outbox_pending ON lan_team_outbox(state, created_at);
