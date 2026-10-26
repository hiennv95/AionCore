-- Private-LAN host peers, agent shares and remote requests (ADR-009).
--
-- A peer is another host identified by the SHA-256 fingerprint of its
-- self-signed certificate. IP, hostname and display name are labels only;
-- authorization always goes through `fingerprint` + `state = 'trusted'`.

CREATE TABLE IF NOT EXISTS network_peers (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    -- Base URL of the peer listener, when this host knows how to call it.
    peer_url TEXT,
    -- pending_inbound | pending_outbound | trusted | revoked
    state TEXT NOT NULL,
    -- 6-digit code derived from both fingerprints, compared out of band.
    verification_code TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- What this host shares with one peer. Rows are never deleted while requests
-- may reference them; unsharing sets `revoked_at`.
CREATE TABLE IF NOT EXISTS network_shares (
    id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL REFERENCES network_peers(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    backend TEXT NOT NULL,
    mode TEXT NOT NULL,
    workspace TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'chat',
    expires_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_network_shares_peer ON network_shares(peer_id);

-- Requests other hosts sent to this host (durable inbox). `request_id` is the
-- requester's idempotency key, unique per peer. `version` increases on every
-- change so pollers can wait for news. `claim_token` fences execution to the
-- process that claimed it.
CREATE TABLE IF NOT EXISTS network_inbound_requests (
    id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL REFERENCES network_peers(id) ON DELETE CASCADE,
    share_id TEXT NOT NULL REFERENCES network_shares(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    error_code TEXT,
    waiting_kind TEXT,
    conversation_id TEXT,
    result_text TEXT,
    deadline_at INTEGER NOT NULL,
    claim_token TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    finished_at INTEGER,
    UNIQUE (peer_id, request_id)
);

CREATE INDEX IF NOT EXISTS idx_network_inbound_state ON network_inbound_requests(state);
CREATE INDEX IF NOT EXISTS idx_network_inbound_thread ON network_inbound_requests(peer_id, share_id, thread_id);

-- Requests this host sent to peers (durable outbox) and their last known state.
CREATE TABLE IF NOT EXISTS network_outbound_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    peer_id TEXT NOT NULL REFERENCES network_peers(id) ON DELETE CASCADE,
    share_id TEXT NOT NULL,
    share_label TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE,
    thread_id TEXT NOT NULL,
    content TEXT NOT NULL,
    state TEXT NOT NULL,
    error_code TEXT,
    waiting_kind TEXT,
    result_text TEXT,
    remote_version INTEGER NOT NULL DEFAULT 0,
    peer_reachable INTEGER NOT NULL DEFAULT 1,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    deadline_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    finished_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_network_outbound_user ON network_outbound_requests(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_network_outbound_state ON network_outbound_requests(state);
