//! Which peer fingerprints this host trusts. M2.1 keeps it in memory; pairing (M2.2) persists it.

use std::collections::HashSet;
use std::sync::RwLock;

use crate::identity::Fingerprint;

/// Read side used by the peer listener to authorize callers.
pub trait TrustStore: Send + Sync {
    fn is_trusted(&self, fingerprint: &Fingerprint) -> bool;
}

#[derive(Default)]
pub struct InMemoryTrustStore {
    trusted: RwLock<HashSet<Fingerprint>>,
}

impl InMemoryTrustStore {
    pub fn trust(&self, fingerprint: Fingerprint) {
        self.trusted
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(fingerprint);
    }

    pub fn revoke(&self, fingerprint: &Fingerprint) {
        self.trusted
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(fingerprint);
    }
}

impl TrustStore for InMemoryTrustStore {
    fn is_trusted(&self, fingerprint: &Fingerprint) -> bool {
        self.trusted
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(fingerprint)
    }
}
