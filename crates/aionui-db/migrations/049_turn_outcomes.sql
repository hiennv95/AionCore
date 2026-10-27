-- How each agent turn ended, for the local attention inbox (B05, ADR-018).
--
-- One row per turn (dedup by turn id). `outcome` comes from the host's own terminal signal:
-- 'finished' = the turn ended without an error signal (NOT proof of success), 'failed' = an
-- error terminal or a turn that could not start, 'stopped' = the user cancelled it. A user
-- stop wins over a later finish/fail of the same turn. `source` names the signal. `seen_at`
-- is set when the owner opened the chat; rows go with their conversation.

CREATE TABLE IF NOT EXISTS turn_outcomes (
    turn_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    outcome TEXT NOT NULL CHECK (outcome IN ('finished', 'failed', 'stopped')),
    source TEXT NOT NULL,
    error_code TEXT,
    ended_at INTEGER NOT NULL,
    seen_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_turn_outcomes_user_unseen
    ON turn_outcomes(user_id, seen_at, ended_at);

CREATE INDEX IF NOT EXISTS idx_turn_outcomes_conversation
    ON turn_outcomes(conversation_id);
