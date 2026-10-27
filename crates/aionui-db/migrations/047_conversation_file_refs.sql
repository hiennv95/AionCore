-- Files a chat may preview (ADR-017, Preview v1).
--
-- The host records a file only when an agent result in that conversation reports it and the
-- reported path resolves to an existing regular file inside the conversation's workspace.
-- Only the path relative to that workspace is kept; every read re-validates it. Rows go with
-- their conversation.

CREATE TABLE IF NOT EXISTS conversation_file_refs (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    rel_path TEXT NOT NULL,
    workspace_canonical TEXT NOT NULL,
    call_id TEXT,
    size INTEGER NOT NULL,
    mtime_ms INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (conversation_id, rel_path)
);

CREATE INDEX IF NOT EXISTS idx_conversation_file_refs_conversation
    ON conversation_file_refs(conversation_id, updated_at);

-- Owner setting: may paired phones and browsers preview files? Off unless the desktop turns it on.
CREATE TABLE IF NOT EXISTS preview_settings (
    user_id TEXT PRIMARY KEY,
    devices_allowed INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);
