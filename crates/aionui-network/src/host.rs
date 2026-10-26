//! This host's network identity and owner-editable settings, persisted next to
//! the identity key in `<data_dir>/peer/network.json`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use aionui_peer::{Fingerprint, PeerIdentity};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::NetworkError;
use crate::policy::DEFAULT_PEER_PORT;

const SETTINGS_FILE: &str = "network.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkSettings {
    /// Accept peer connections (the owner turned LAN collaboration on).
    pub enabled: bool,
    pub listen_port: u16,
    pub display_name: String,
}

/// Identity + settings shared by the inbound and outbound sides.
pub struct HostContext {
    identity: Arc<PeerIdentity>,
    settings: RwLock<NetworkSettings>,
    settings_path: PathBuf,
    owner_user_id: String,
    /// Directory where default share workspaces are created.
    workspace_root: PathBuf,
}

impl HostContext {
    /// Load (or create) the identity and settings under `peer_dir`.
    pub fn load(peer_dir: &Path, owner_user_id: String, workspace_root: PathBuf) -> Result<Self, NetworkError> {
        let identity = PeerIdentity::load_or_create(peer_dir, "aionx-host")
            .map_err(|e| NetworkError::Internal(format!("peer identity: {e}")))?;
        let settings_path = peer_dir.join(SETTINGS_FILE);
        let settings = match std::fs::read(&settings_path) {
            Ok(bytes) => match serde_json::from_slice::<NetworkSettings>(&bytes) {
                Ok(settings) => settings,
                Err(error) => {
                    // A corrupt settings file must not take the host down; LAN stays off.
                    warn!(%error, "network settings unreadable; LAN collaboration stays off");
                    default_settings(identity.fingerprint())
                }
            },
            Err(_) => default_settings(identity.fingerprint()),
        };
        Ok(Self {
            identity: Arc::new(identity),
            settings: RwLock::new(settings),
            settings_path,
            owner_user_id,
            workspace_root,
        })
    }

    pub fn identity(&self) -> &Arc<PeerIdentity> {
        &self.identity
    }

    pub fn fingerprint(&self) -> &Fingerprint {
        self.identity.fingerprint()
    }

    pub fn owner_user_id(&self) -> &str {
        &self.owner_user_id
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn settings(&self) -> NetworkSettings {
        self.settings.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn display_name(&self) -> String {
        self.settings().display_name
    }

    /// Persist new settings atomically (write temp file, then rename).
    pub fn save_settings(&self, settings: NetworkSettings) -> Result<(), NetworkError> {
        let bytes = serde_json::to_vec_pretty(&settings).map_err(|e| NetworkError::Internal(e.to_string()))?;
        let tmp = self.settings_path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).map_err(|e| NetworkError::Internal(format!("write settings: {e}")))?;
        std::fs::rename(&tmp, &self.settings_path)
            .map_err(|e| NetworkError::Internal(format!("save settings: {e}")))?;
        *self.settings.write().unwrap_or_else(|e| e.into_inner()) = settings;
        Ok(())
    }
}

fn default_settings(fingerprint: &Fingerprint) -> NetworkSettings {
    NetworkSettings {
        enabled: false,
        listen_port: DEFAULT_PEER_PORT,
        display_name: format!("AionX host {}", &fingerprint.as_str()[..6]),
    }
}
