//! "Connect device" handshake state (ADR-011 §3), kept in memory: pairings live
//! for minutes and a restart simply asks the owner to start again.
//!
//! Open → (device presents secret or code) → Requested → (owner) → Approved |
//! Rejected → (device claims once) → Claimed. Anything not claimed within
//! [`PAIRING_TTL_MS`] of creation expires. A secret works once.

use std::collections::HashMap;

use aionui_api_types::{DeviceKind, DeviceSession, PairingState, PairingView};

use crate::error::DeviceError;
use crate::secret::{digest, digest_eq, normalize_code, random_code, random_secret};

pub const PAIRING_TTL_MS: i64 = 5 * 60 * 1000;
pub const MAX_OPEN_PAIRINGS: usize = 8;

struct Pairing {
    id: String,
    state: PairingState,
    created_at: i64,
    secret_digest: [u8; 32],
    code_digest: [u8; 32],
    claim_digest: Option<[u8; 32]>,
    device_name: Option<String>,
    device_kind: Option<DeviceKind>,
    /// Issued on approval, handed out on the first claim, then dropped.
    session: Option<DeviceSession>,
}

impl Pairing {
    fn expires_at(&self) -> i64 {
        self.created_at + PAIRING_TTL_MS
    }

    fn view(&self, now: i64) -> PairingView {
        let expired = now >= self.expires_at()
            && matches!(
                self.state,
                PairingState::Open | PairingState::Requested | PairingState::Approved
            );
        PairingView {
            id: self.id.clone(),
            state: if expired { PairingState::Expired } else { self.state },
            expires_at: self.expires_at(),
            device_name: self.device_name.clone(),
            device_kind: self.device_kind,
        }
    }
}

/// What the owner needs to show the device: the view plus the one-time secrets.
pub struct OpenedPairing {
    pub view: PairingView,
    pub secret: String,
    pub code: String,
}

/// What a device learned when it presented a valid secret.
pub struct PresentedPairing {
    pub id: String,
    pub claim_token: String,
    pub device_kind: DeviceKind,
}

#[derive(Default)]
pub struct PairingBook {
    pairings: HashMap<String, Pairing>,
    /// Device ids of approved pairings that expired unclaimed, still to be revoked.
    pending_revocations: Vec<String>,
}

impl PairingBook {
    /// Prunes expired pairings and returns the device ids still to be revoked: approved
    /// pairings that expired unclaimed, plus earlier ids whose revocation failed.
    pub fn prune_unclaimed_approved(&mut self, now: i64) -> Vec<String> {
        self.prune(now);
        std::mem::take(&mut self.pending_revocations)
    }

    /// Re-queues device ids whose revocation failed, for the next prune.
    pub fn queue_failed_revocations(&mut self, device_ids: Vec<String>) {
        for id in device_ids {
            if !self.pending_revocations.contains(&id) {
                self.pending_revocations.push(id);
            }
        }
    }

    /// Drop pairings that ended or expired more than one TTL ago. An approved pairing
    /// that expired unclaimed gives up its session, and its device id is queued for
    /// revocation; claimed and rejected pairings keep their state.
    fn prune(&mut self, now: i64) {
        for p in self.pairings.values_mut() {
            if now >= p.expires_at()
                && p.state == PairingState::Approved
                && let Some(session) = p.session.take()
                && !self.pending_revocations.contains(&session.device_id)
            {
                self.pending_revocations.push(session.device_id);
            }
        }
        self.pairings.retain(|_, p| now < p.expires_at() + PAIRING_TTL_MS);
    }

    fn live(&self, id: &str, now: i64) -> Result<&Pairing, DeviceError> {
        let pairing = self.pairings.get(id).ok_or(DeviceError::PairingNotFound)?;
        if pairing.view(now).state == PairingState::Expired {
            return Err(DeviceError::PairingExpired);
        }
        Ok(pairing)
    }

    pub fn open(&mut self, now: i64) -> Result<OpenedPairing, DeviceError> {
        self.prune(now);
        let open = self
            .pairings
            .values()
            .filter(|p| p.view(now).state == PairingState::Open)
            .count();
        if open >= MAX_OPEN_PAIRINGS {
            return Err(DeviceError::PairingLimit);
        }
        let (secret, code) = (random_secret()?, random_code()?);
        let pairing = Pairing {
            id: format!("pair_{}", &random_secret()?[..24]),
            state: PairingState::Open,
            created_at: now,
            secret_digest: digest(&secret),
            code_digest: digest(&code),
            claim_digest: None,
            device_name: None,
            device_kind: None,
            session: None,
        };
        let view = pairing.view(now);
        self.pairings.insert(pairing.id.clone(), pairing);
        Ok(OpenedPairing { view, secret, code })
    }

    /// A device presents the QR secret or the typed code.
    pub fn present(
        &mut self,
        secret_or_code: &str,
        device_name: &str,
        device_kind: DeviceKind,
        now: i64,
    ) -> Result<PresentedPairing, DeviceError> {
        let as_secret = digest(secret_or_code.trim());
        let as_code = digest(&normalize_code(secret_or_code));
        // Compare against every pairing so timing does not reveal which matched.
        let mut found: Option<String> = None;
        for pairing in self.pairings.values() {
            let hit = digest_eq(&pairing.secret_digest, &as_secret) | digest_eq(&pairing.code_digest, &as_code);
            if hit {
                found = Some(pairing.id.clone());
            }
        }
        let id = found.ok_or(DeviceError::PairingNotFound)?;
        let state = self.live(&id, now)?.state;
        if state != PairingState::Open {
            return Err(DeviceError::PairingUsed);
        }
        let claim_token = random_secret()?;
        let pairing = self.pairings.get_mut(&id).ok_or(DeviceError::PairingNotFound)?;
        pairing.state = PairingState::Requested;
        pairing.claim_digest = Some(digest(&claim_token));
        pairing.device_name = Some(device_name.to_owned());
        pairing.device_kind = Some(device_kind);
        Ok(PresentedPairing {
            id,
            claim_token,
            device_kind,
        })
    }

    /// Device name/kind of a pairing waiting for the owner's decision.
    pub fn requested(&self, id: &str, now: i64) -> Result<(String, DeviceKind), DeviceError> {
        let pairing = self.live(id, now)?;
        match (pairing.state, &pairing.device_name, pairing.device_kind) {
            (PairingState::Requested, Some(name), Some(kind)) => Ok((name.clone(), kind)),
            _ => Err(DeviceError::PairingNotRequested),
        }
    }

    pub fn approve(&mut self, id: &str, session: DeviceSession, now: i64) -> Result<PairingView, DeviceError> {
        self.requested(id, now)?;
        let pairing = self.pairings.get_mut(id).ok_or(DeviceError::PairingNotFound)?;
        pairing.state = PairingState::Approved;
        pairing.session = Some(session);
        Ok(pairing.view(now))
    }

    pub fn reject(&mut self, id: &str, now: i64) -> Result<PairingView, DeviceError> {
        let pairing = self.live(id, now)?;
        if !matches!(pairing.state, PairingState::Open | PairingState::Requested) {
            return Err(DeviceError::PairingNotRequested);
        }
        let pairing = self.pairings.get_mut(id).ok_or(DeviceError::PairingNotFound)?;
        pairing.state = PairingState::Rejected;
        Ok(pairing.view(now))
    }

    /// The device asks for its result. The session is handed out exactly once.
    pub fn claim(
        &mut self,
        id: &str,
        claim_token: &str,
        now: i64,
    ) -> Result<(PairingState, Option<DeviceSession>), DeviceError> {
        let pairing = self.pairings.get(id).ok_or(DeviceError::PairingNotFound)?;
        let presented = digest(claim_token.trim());
        if !pairing.claim_digest.is_some_and(|d| digest_eq(&d, &presented)) {
            return Err(DeviceError::PairingNotFound);
        }
        match pairing.view(now).state {
            PairingState::Expired => Err(DeviceError::PairingExpired),
            PairingState::Rejected => Err(DeviceError::PairingRejected),
            PairingState::Claimed => Err(DeviceError::PairingUsed),
            PairingState::Approved => {
                let pairing = self.pairings.get_mut(id).ok_or(DeviceError::PairingNotFound)?;
                // Its session went to revocation when a prune found it expired.
                if pairing.session.is_none() {
                    return Err(DeviceError::PairingExpired);
                }
                pairing.state = PairingState::Claimed;
                Ok((PairingState::Claimed, pairing.session.take()))
            }
            other => Ok((other, None)),
        }
    }

    pub fn view(&self, id: &str, now: i64) -> Result<PairingView, DeviceError> {
        Ok(self.pairings.get(id).ok_or(DeviceError::PairingNotFound)?.view(now))
    }

    /// Device id the pairing was approved for, if any (to undo on expiry).
    pub fn approved_device(&self, id: &str) -> Option<String> {
        self.pairings
            .get(id)
            .and_then(|p| p.session.as_ref().map(|s| s.device_id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> DeviceSession {
        DeviceSession {
            device_id: "dev_1".into(),
            access_token: "a".into(),
            refresh_token: "r".into(),
        }
    }

    #[test]
    fn full_handshake_hands_the_session_out_once() {
        let mut book = PairingBook::default();
        let opened = book.open(0).unwrap();
        let presented = book.present(&opened.secret, "Pixel", DeviceKind::Mobile, 10).unwrap();
        assert_eq!(book.view(&presented.id, 10).unwrap().state, PairingState::Requested);
        let (state, session_before) = book.claim(&presented.id, &presented.claim_token, 11).unwrap();
        assert_eq!(state, PairingState::Requested);
        assert!(session_before.is_none());
        book.approve(&presented.id, session(), 20).unwrap();
        let (state, got) = book.claim(&presented.id, &presented.claim_token, 21).unwrap();
        assert_eq!(state, PairingState::Claimed);
        assert_eq!(got.unwrap().device_id, "dev_1");
        assert!(matches!(
            book.claim(&presented.id, &presented.claim_token, 22),
            Err(DeviceError::PairingUsed)
        ));
    }

    #[test]
    fn typed_code_works_and_secret_cannot_be_replayed() {
        let mut book = PairingBook::default();
        let opened = book.open(0).unwrap();
        let typed = format!("{}-{}", &opened.code[..4].to_lowercase(), &opened.code[4..]);
        book.present(&typed, "Browser", DeviceKind::Browser, 1).unwrap();
        assert!(matches!(
            book.present(&opened.secret, "Attacker", DeviceKind::Mobile, 2),
            Err(DeviceError::PairingUsed)
        ));
        assert!(matches!(
            book.present("wrong", "Attacker", DeviceKind::Mobile, 2),
            Err(DeviceError::PairingNotFound)
        ));
    }

    #[test]
    fn expired_pairings_refuse_present_and_claim() {
        let mut book = PairingBook::default();
        let opened = book.open(0).unwrap();
        assert!(matches!(
            book.present(&opened.secret, "Late", DeviceKind::Mobile, PAIRING_TTL_MS),
            Err(DeviceError::PairingExpired)
        ));
        let opened = book.open(0).unwrap();
        let p = book.present(&opened.secret, "Slow", DeviceKind::Mobile, 1).unwrap();
        book.approve(&p.id, session(), 2).unwrap();
        assert!(matches!(
            book.claim(&p.id, &p.claim_token, PAIRING_TTL_MS + 1),
            Err(DeviceError::PairingExpired)
        ));
    }

    #[test]
    fn wrong_claim_token_and_rejection() {
        let mut book = PairingBook::default();
        let opened = book.open(0).unwrap();
        let p = book.present(&opened.secret, "Pixel", DeviceKind::Mobile, 1).unwrap();
        assert!(matches!(
            book.claim(&p.id, "forged", 2),
            Err(DeviceError::PairingNotFound)
        ));
        book.reject(&p.id, 3).unwrap();
        assert!(matches!(
            book.claim(&p.id, &p.claim_token, 4),
            Err(DeviceError::PairingRejected)
        ));
        assert!(matches!(
            book.approve(&p.id, session(), 5),
            Err(DeviceError::PairingNotRequested)
        ));
    }

    #[test]
    fn open_pairings_are_capped() {
        let mut book = PairingBook::default();
        for _ in 0..MAX_OPEN_PAIRINGS {
            book.open(0).unwrap();
        }
        assert!(matches!(book.open(0), Err(DeviceError::PairingLimit)));
        // Once they expire, new ones can be opened again.
        assert!(book.open(PAIRING_TTL_MS).is_ok());
    }

    /// Pruning only collects approved-but-unclaimed sessions; it must not rewrite
    /// the terminal state of claimed or rejected pairings (a repeated claim stays
    /// "used", not "expired").
    #[test]
    fn prune_keeps_terminal_states() {
        let mut book = PairingBook::default();
        let o1 = book.open(0).unwrap();
        let claimed = book.present(&o1.secret, "Claimed", DeviceKind::Mobile, 1).unwrap();
        book.approve(&claimed.id, session(), 2).unwrap();
        book.claim(&claimed.id, &claimed.claim_token, 3).unwrap();
        let o2 = book.open(0).unwrap();
        let rejected = book.present(&o2.secret, "Rejected", DeviceKind::Mobile, 1).unwrap();
        book.reject(&rejected.id, 2).unwrap();

        assert!(book.prune_unclaimed_approved(PAIRING_TTL_MS).is_empty());
        assert_eq!(
            book.view(&claimed.id, PAIRING_TTL_MS).unwrap().state,
            PairingState::Claimed
        );
        assert_eq!(
            book.view(&rejected.id, PAIRING_TTL_MS).unwrap().state,
            PairingState::Rejected
        );
        assert!(matches!(
            book.claim(&claimed.id, &claimed.claim_token, PAIRING_TTL_MS),
            Err(DeviceError::PairingUsed)
        ));
        assert!(matches!(
            book.claim(&rejected.id, &rejected.claim_token, PAIRING_TTL_MS),
            Err(DeviceError::PairingRejected)
        ));
    }

    #[test]
    fn prune_unclaimed_approved_extracts_orphan_devices_and_preserves_claimed() {
        let mut book = PairingBook::default();
        // 1. Unclaimed approved pairing
        let open1 = book.open(0).unwrap();
        let p1 = book.present(&open1.secret, "Orphan", DeviceKind::Mobile, 1).unwrap();
        book.approve(&p1.id, session(), 2).unwrap();

        // 2. Claimed approved pairing
        let open2 = book.open(0).unwrap();
        let p2 = book.present(&open2.secret, "Claimed", DeviceKind::Mobile, 1).unwrap();
        book.approve(&p2.id, session(), 2).unwrap();
        let _ = book.claim(&p2.id, &p2.claim_token, 3).unwrap();

        // Before expiration: no orphans
        assert!(book.prune_unclaimed_approved(PAIRING_TTL_MS - 1).is_empty());

        // At expiration: orphan device id extracted, claimed device is not
        let orphans = book.prune_unclaimed_approved(PAIRING_TTL_MS);
        assert_eq!(orphans, vec!["dev_1"]);

        // Calling again does not re-extract the same orphan
        assert!(book.prune_unclaimed_approved(PAIRING_TTL_MS).is_empty());

        // Retry queue retains failed revocations
        book.queue_failed_revocations(vec!["dev_failed".into()]);
        let retried = book.prune_unclaimed_approved(PAIRING_TTL_MS);
        assert_eq!(retried, vec!["dev_failed"]);
    }
}
