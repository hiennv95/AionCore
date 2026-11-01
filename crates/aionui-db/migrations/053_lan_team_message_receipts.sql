CREATE TABLE IF NOT EXISTS lan_team_message_receipts (
    peer_id TEXT NOT NULL REFERENCES network_peers(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    remote_team_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    PRIMARY KEY (peer_id, request_id)
);
