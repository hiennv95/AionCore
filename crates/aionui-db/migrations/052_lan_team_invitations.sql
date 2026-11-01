CREATE TABLE IF NOT EXISTS lan_team_members (
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    remote_team_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    PRIMARY KEY (team_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS lan_team_invitations (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    candidate_fingerprint TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'rejected', 'cancelled', 'completed')),
    created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS lan_team_one_pending_invitation
    ON lan_team_invitations(team_id) WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS lan_team_invitation_votes (
    invitation_id TEXT NOT NULL REFERENCES lan_team_invitations(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('pending', 'approved', 'rejected')),
    remote_team_id TEXT,
    PRIMARY KEY (invitation_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS lan_team_poll_consents (
    coordinator_fingerprint TEXT NOT NULL,
    invitation_id TEXT NOT NULL,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    participants TEXT NOT NULL,
    PRIMARY KEY (coordinator_fingerprint, invitation_id)
);

CREATE TABLE IF NOT EXISTS lan_team_pair_attestations (
    invitation_id TEXT NOT NULL REFERENCES lan_team_invitations(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    attested_at INTEGER NOT NULL,
    PRIMARY KEY (invitation_id, fingerprint)
);
