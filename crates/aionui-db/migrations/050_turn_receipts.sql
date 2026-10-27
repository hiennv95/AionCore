-- Result receipt per turn (B05.R1): what the host itself observed when a turn ended,
-- kept apart from what the agent claims and from the owner's acceptance.
--
-- `workspace_state` is 'git' (head + fingerprint read from the repository), 'not_git' (the
-- workspace is not a git work tree) or 'unknown' (no workspace, or it could not be read).
-- `workspace_fingerprint` hashes the head and every changed path with its size and mtime, so a
-- later edit makes the receipt's evidence stale. `accepted_at` is the owner's own call; it says
-- nothing about checks passing. Rows go with their turn outcome.

CREATE TABLE IF NOT EXISTS turn_receipts (
    turn_id TEXT PRIMARY KEY REFERENCES turn_outcomes(turn_id) ON DELETE CASCADE,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    started_at INTEGER NOT NULL,
    workspace_state TEXT NOT NULL CHECK (workspace_state IN ('git', 'not_git', 'unknown')),
    workspace_head TEXT,
    workspace_fingerprint TEXT,
    accepted_at INTEGER
);
