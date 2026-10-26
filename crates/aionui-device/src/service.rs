//! Business logic of client devices (ADR-011). The host owner is the system
//! user: there is no account login, so every device session belongs to it.

use std::sync::{Arc, Mutex};

use aionui_api_types::{
    AppSessionRequest, ClaimRequest, ClaimResponse, CreatePairingResponse, DeviceKind, DeviceListenerStatus,
    DeviceSession, DeviceView, HostProofRequest, HostProofResponse, PairRequest, PairResponse, PairingView,
    UpdateDeviceListenerRequest,
};
use aionui_auth::JwtService;
use aionui_common::now_ms;
use aionui_db::models::User;
use aionui_db::{DeviceRow, IDeviceRepository, IUserRepository};
use tracing::info;

use crate::bootstrap::BootstrapToken;
use crate::error::DeviceError;
use crate::listener::DeviceListener;
use crate::pairing::PairingBook;

const MAX_DEVICE_NAME: usize = 64;

/// Who makes an owner request, as authentication established it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// A session without a device: the legacy login or local mode.
    Session,
    /// A device-bound session.
    Device(String),
    /// An agent's helper CLI on the runtime-token channel. Acts for the owner's
    /// conversation, never as a device manager.
    RuntimeHelper,
}

impl Caller {
    fn device(&self) -> Option<&str> {
        match self {
            Self::Device(id) => Some(id),
            Self::Session | Self::RuntimeHelper => None,
        }
    }
}

/// Called with the device id after a device is revoked (e.g. to close its sockets).
pub type DeviceRevokedHook = dyn Fn(&str) + Send + Sync;

pub struct DeviceService {
    devices: Arc<dyn IDeviceRepository>,
    users: Arc<dyn IUserRepository>,
    jwt: Arc<JwtService>,
    bootstrap: BootstrapToken,
    pairings: Mutex<PairingBook>,
    listener: Option<Arc<DeviceListener>>,
    on_revoked: Option<Arc<DeviceRevokedHook>>,
}

fn clean_name(name: &str) -> Result<String, DeviceError> {
    let name: String = name.trim().chars().filter(|c| !c.is_control()).collect();
    if name.is_empty() || name.chars().count() > MAX_DEVICE_NAME {
        return Err(DeviceError::InvalidRequest(format!(
            "device name must be 1-{MAX_DEVICE_NAME} characters"
        )));
    }
    Ok(name)
}

fn view(row: DeviceRow, current: Option<&str>) -> DeviceView {
    DeviceView {
        current: current == Some(row.id.as_str()),
        kind: DeviceKind::parse(&row.kind).unwrap_or(DeviceKind::Browser),
        id: row.id,
        name: row.name,
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        revoked_at: row.revoked_at,
    }
}

impl DeviceService {
    pub fn new(
        devices: Arc<dyn IDeviceRepository>,
        users: Arc<dyn IUserRepository>,
        jwt: Arc<JwtService>,
        bootstrap: BootstrapToken,
        listener: Option<Arc<DeviceListener>>,
        on_revoked: Option<Arc<DeviceRevokedHook>>,
    ) -> Self {
        Self {
            devices,
            users,
            jwt,
            bootstrap,
            pairings: Mutex::new(PairingBook::default()),
            listener,
            on_revoked,
        }
    }

    fn listener(&self) -> Result<&Arc<DeviceListener>, DeviceError> {
        self.listener
            .as_ref()
            .ok_or_else(|| DeviceError::InvalidRequest("the device listener is unavailable on this host".into()))
    }

    pub async fn listener_status(&self, user_id: &str, caller: &Caller) -> Result<DeviceListenerStatus, DeviceError> {
        self.ensure_manager(user_id, caller).await?;
        Ok(self.listener()?.status())
    }

    pub async fn update_listener(
        &self,
        user_id: &str,
        caller: &Caller,
        req: UpdateDeviceListenerRequest,
    ) -> Result<DeviceListenerStatus, DeviceError> {
        self.ensure_manager(user_id, caller).await?;
        self.listener()?.update(req).await
    }

    fn book(&self) -> std::sync::MutexGuard<'_, PairingBook> {
        self.pairings.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn owner(&self) -> Result<User, DeviceError> {
        self.users
            .get_system_user()
            .await?
            .ok_or_else(|| DeviceError::Internal("host owner account missing".into()))
    }

    async fn ensure_owner(&self, user_id: &str) -> Result<User, DeviceError> {
        let owner = self.owner().await?;
        if owner.id != user_id {
            return Err(DeviceError::OwnerOnly);
        }
        Ok(owner)
    }

    /// Owner who may manage devices: the desktop app (or a session without a
    /// device, i.e. the legacy login / local mode). Paired phones and browsers
    /// cannot pair or revoke other devices, nor can an agent's helper CLI.
    async fn ensure_manager(&self, user_id: &str, caller: &Caller) -> Result<User, DeviceError> {
        let owner = self.ensure_owner(user_id).await?;
        match caller {
            Caller::Session => {}
            Caller::RuntimeHelper => return Err(DeviceError::OwnerOnly),
            Caller::Device(device_id) => {
                let manager = self
                    .devices
                    .find(device_id)
                    .await?
                    .is_some_and(|d| d.kind == DeviceKind::DesktopApp.as_str() && d.revoked_at.is_none());
                if !manager {
                    return Err(DeviceError::OwnerOnly);
                }
            }
        }
        Ok(owner)
    }

    async fn issue_session(&self, name: &str, kind: DeviceKind) -> Result<DeviceSession, DeviceError> {
        let owner = self.owner().await?;
        // A relaunched desktop app reuses its live device row instead of adding one
        // per start: the bootstrap secret already proves desktop-app trust, so this
        // grants nothing new. A revoked row is never reused, so revocation sticks.
        let reusable = if kind == DeviceKind::DesktopApp {
            self.devices
                .list(&owner.id)
                .await?
                .into_iter()
                .find(|d| d.kind == DeviceKind::DesktopApp.as_str() && d.revoked_at.is_none() && d.name == name)
        } else {
            None
        };
        let device = match reusable {
            Some(device) => {
                self.devices.touch(&device.id, now_ms()).await?;
                device
            }
            None => self.devices.insert(&owner.id, name, kind.as_str()).await?,
        };
        let (access_token, refresh_token) = self
            .jwt
            .sign_session_pair(
                &owner.id,
                owner.username.as_deref().unwrap_or("owner"),
                owner.session_generation,
                Some(&device.id),
            )
            .map_err(|e| DeviceError::Internal(format!("token signing failed: {e}")))?;
        info!(device_id = %device.id, kind = kind.as_str(), "device: session issued");
        Ok(DeviceSession {
            device_id: device.id,
            access_token,
            refresh_token,
        })
    }

    /// The desktop app exchanges this launch's bootstrap secret for a session.
    pub async fn app_session(&self, req: AppSessionRequest) -> Result<DeviceSession, DeviceError> {
        if !self.bootstrap.matches(&req.bootstrap_token) {
            tracing::warn!("device: app-session with an invalid bootstrap token");
            return Err(DeviceError::BootstrapInvalid);
        }
        let name = clean_name(req.device_name.as_deref().unwrap_or("Desktop app"))?;
        self.issue_session(&name, DeviceKind::DesktopApp).await
    }

    /// The host proves to the desktop app that it wrote this launch's secret.
    pub fn host_proof(&self, req: HostProofRequest) -> Result<HostProofResponse, DeviceError> {
        let nonce = req.nonce.trim();
        if !(32..=128).contains(&nonce.len()) || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(DeviceError::InvalidRequest(
                "nonce must be 32 to 128 hex characters".into(),
            ));
        }
        Ok(HostProofResponse {
            proof: self.bootstrap.prove(nonce),
        })
    }

    pub async fn create_pairing(&self, user_id: &str, caller: &Caller) -> Result<CreatePairingResponse, DeviceError> {
        self.ensure_manager(user_id, caller).await?;
        let opened = self.book().open(now_ms())?;
        let listener = self.listener.as_ref().and_then(|listener| listener.info());
        let mut qr_uri = format!("aionx://pair?v=1&secret={}", opened.secret);
        if let Some(info) = &listener {
            qr_uri.push_str(&format!(
                "&port={}&fp={}&hosts={}",
                info.port,
                info.fingerprint,
                info.addresses.join(",")
            ));
        }
        info!(pairing_id = %opened.view.id, "device: pairing opened");
        Ok(CreatePairingResponse {
            pairing: opened.view,
            secret: opened.secret,
            code: opened.code,
            qr_uri,
            listener,
        })
    }

    pub async fn pairing(&self, user_id: &str, caller: &Caller, id: &str) -> Result<PairingView, DeviceError> {
        self.ensure_manager(user_id, caller).await?;
        self.book().view(id, now_ms())
    }

    pub async fn approve(&self, user_id: &str, caller: &Caller, id: &str) -> Result<PairingView, DeviceError> {
        self.ensure_manager(user_id, caller).await?;
        let (name, kind) = self.book().requested(id, now_ms())?;
        let session = self.issue_session(&name, kind).await?;
        let device_id = session.device_id.clone();
        let approved = self.book().approve(id, session, now_ms());
        match approved {
            Ok(view) => {
                info!(pairing_id = %id, %device_id, "device: pairing approved");
                Ok(view)
            }
            Err(error) => {
                // Expired between the two steps: do not leave a usable device behind.
                let _ = self.devices.revoke(user_id, &device_id, now_ms()).await;
                Err(error)
            }
        }
    }

    pub async fn reject(&self, user_id: &str, caller: &Caller, id: &str) -> Result<PairingView, DeviceError> {
        self.ensure_manager(user_id, caller).await?;
        let view = self.book().reject(id, now_ms())?;
        info!(pairing_id = %id, "device: pairing rejected");
        Ok(view)
    }

    /// A new device presents the QR secret or typed code.
    pub async fn pair(&self, req: PairRequest) -> Result<PairResponse, DeviceError> {
        let name = clean_name(&req.device_name)?;
        // Only the bootstrap app-session path may create desktop-app devices: that
        // kind carries the manager role, which a paired device must never claim.
        if req.device_kind == DeviceKind::DesktopApp {
            return Err(DeviceError::InvalidRequest(
                "a paired device cannot be a desktop app".into(),
            ));
        }
        let presented = self
            .book()
            .present(&req.secret, &name, req.device_kind, now_ms())
            .inspect_err(|e| {
                tracing::warn!(code = e.code(), "device: pairing attempt refused");
            })?;
        info!(pairing_id = %presented.id, kind = presented.device_kind.as_str(), "device: pairing requested");
        Ok(PairResponse {
            pairing_id: presented.id,
            claim_token: presented.claim_token,
        })
    }

    /// The second value, when present, is a browser session to deliver as cookies.
    pub async fn claim(&self, req: ClaimRequest) -> Result<(ClaimResponse, Option<DeviceSession>), DeviceError> {
        let now = now_ms();
        let result = self.book().claim(&req.pairing_id, &req.claim_token, now);
        if matches!(result, Err(DeviceError::PairingExpired)) {
            // Approved but never collected: the device row must not stay usable.
            let approved_device = self.book().approved_device(&req.pairing_id);
            if let Some(device_id) = approved_device {
                let owner = self.owner().await?;
                let _ = self.devices.revoke(&owner.id, &device_id, now).await;
            }
        }
        let (state, session) = result?;
        // Browsers get their session as HttpOnly cookies only (set by the route):
        // the tokens never reach page JavaScript.
        let device_kind = match &session {
            Some(session) => self.devices.find(&session.device_id).await?.map(|d| d.kind),
            None => None,
        };
        if device_kind.as_deref() == Some(DeviceKind::Browser.as_str())
            && let Some(cookie_session) = session
        {
            let visible = DeviceSession {
                device_id: cookie_session.device_id.clone(),
                access_token: String::new(),
                refresh_token: String::new(),
            };
            return Ok((
                ClaimResponse {
                    state,
                    session: Some(visible),
                },
                Some(cookie_session),
            ));
        }
        Ok((ClaimResponse { state, session }, None))
    }

    pub async fn list(&self, user_id: &str, caller: &Caller) -> Result<Vec<DeviceView>, DeviceError> {
        let owner = self.ensure_owner(user_id).await?;
        Ok(self
            .devices
            .list(&owner.id)
            .await?
            .into_iter()
            .map(|row| view(row, caller.device()))
            .collect())
    }

    pub async fn revoke(&self, user_id: &str, caller: &Caller, device_id: &str) -> Result<(), DeviceError> {
        // A device may always sign itself out; revoking others needs the desktop app.
        let owner = if caller.device() == Some(device_id) {
            self.ensure_owner(user_id).await?
        } else {
            self.ensure_manager(user_id, caller).await?
        };
        if !self.devices.revoke(&owner.id, device_id, now_ms()).await? {
            return Err(DeviceError::DeviceNotFound);
        }
        info!(%device_id, "device: revoked");
        if let Some(hook) = &self.on_revoked {
            hook(device_id);
        }
        Ok(())
    }
}
