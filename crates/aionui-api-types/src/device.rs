//! Client devices without an account login (ADR-011): desktop app bootstrap,
//! "connect device" pairing, device list and revocation.

use serde::{Deserialize, Serialize};

/// What kind of client a device is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    DesktopApp,
    Mobile,
    Browser,
}

impl DeviceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DesktopApp => "desktop_app",
            Self::Mobile => "mobile",
            Self::Browser => "browser",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "desktop_app" => Some(Self::DesktopApp),
            "mobile" => Some(Self::Mobile),
            "browser" => Some(Self::Browser),
            _ => None,
        }
    }
}

/// Access + refresh token pair bound to one device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSession {
    pub device_id: String,
    pub access_token: String,
    pub refresh_token: String,
}

/// `POST /api/devices/app-session`: the desktop app proves it can read the
/// per-launch bootstrap file of this host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSessionRequest {
    pub bootstrap_token: String,
    /// Shown in the device list, e.g. the machine name.
    #[serde(default)]
    pub device_name: Option<String>,
}

/// `POST /api/devices/host-proof`: before sending the bootstrap secret, the
/// desktop app makes the host prove it knows this launch's secret, so another
/// process holding the loopback port cannot pose as the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProofRequest {
    /// Fresh random hex chosen by the app, 32 to 128 characters.
    pub nonce: String,
}

/// `proof` is hex HMAC-SHA256 over `"aionx-host-proof:" + nonce`, keyed with
/// SHA-256 of the bootstrap secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProofResponse {
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub kind: DeviceKind,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub revoked_at: Option<i64>,
    /// The device making this request.
    pub current: bool,
}

/// How a device on the LAN reaches this host (device listener, ADR-011 §4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceListenerInfo {
    pub port: u16,
    /// SHA-256 fingerprint of the host certificate the device must pin.
    pub fingerprint: String,
    /// Candidate LAN addresses of this host.
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingState {
    /// Waiting for a device to present the secret.
    Open,
    /// A device presented the secret; the owner has to approve it.
    Requested,
    Approved,
    Rejected,
    /// The device collected its credentials; nothing more can happen.
    Claimed,
    Expired,
}

/// Owner side of one pairing. `secret` and `code` are returned only when created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingView {
    pub id: String,
    pub state: PairingState,
    pub expires_at: i64,
    pub device_name: Option<String>,
    pub device_kind: Option<DeviceKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePairingResponse {
    pub pairing: PairingView,
    /// Long single-use secret carried by the QR code.
    pub secret: String,
    /// Short code for typing by hand (same single use and expiry).
    pub code: String,
    /// `aionx://pair?...` URI to render as a QR code.
    pub qr_uri: String,
    /// `None` while the device listener is off: only same-machine browsers can pair.
    pub listener: Option<DeviceListenerInfo>,
}

/// `POST /api/devices/pair` from the new device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    /// The QR secret or the short code.
    pub secret: String,
    pub device_name: String,
    pub device_kind: DeviceKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairResponse {
    pub pairing_id: String,
    /// Proves on claim that this is the device that presented the secret.
    pub claim_token: String,
}

/// `POST /api/devices/pair/claim`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub pairing_id: String,
    pub claim_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResponse {
    pub state: PairingState,
    /// Present exactly once, on the first claim after the owner approved.
    pub session: Option<DeviceSession>,
}

/// Owner view of the device listener (HTTPS for phones and other-machine browsers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceListenerStatus {
    pub enabled: bool,
    /// Configured port (also while off).
    pub port: u16,
    pub running: bool,
    pub fingerprint: String,
    pub addresses: Vec<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateDeviceListenerRequest {
    pub enabled: Option<bool>,
    pub port: Option<u16>,
}
