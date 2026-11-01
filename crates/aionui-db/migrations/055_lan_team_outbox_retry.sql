ALTER TABLE lan_team_outbox ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS lan_team_outbox_retry ON lan_team_outbox(state, next_attempt_at);
