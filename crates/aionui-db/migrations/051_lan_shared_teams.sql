-- A team is visible to trusted LAN peers only after its owner enables sharing.
CREATE TABLE lan_shared_teams (
    team_id TEXT PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE
);
