#![allow(clippy::disallowed_types)]

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Json, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use aionui_api_types::{ApiResponse, ConversationFileView, FileDiffView, FilePreviewSettings};
use aionui_auth::{CurrentDevice, CurrentUser, DevicelessSession, RuntimeHelperCaller, is_paired_device};
use aionui_common::ApiError;

use crate::error::PreviewError;
use crate::kind::SVG;
use crate::state::PreviewRouterState;

const SVG_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
const CONTENT_CSP: &str = "default-src 'none'; sandbox";

pub fn preview_routes(state: PreviewRouterState) -> Router {
    Router::new()
        .route("/api/conversations/{id}/files", get(list))
        .route("/api/conversations/{id}/files/{file_id}/content", get(content))
        .route("/api/conversations/{id}/files/{file_id}/diff", get(diff))
        .route("/api/devices/file-preview", get(get_setting).put(put_setting))
        .with_state(state)
}

impl From<PreviewError> for ApiError {
    fn from(err: PreviewError) -> Self {
        match err {
            PreviewError::ConversationNotFound => ApiError::NotFound("Conversation not found".into()),
            PreviewError::FileNotFound => {
                ApiError::coded(StatusCode::NOT_FOUND, "FILE_NOT_FOUND", "File not found.", None)
            }
            PreviewError::TooLarge => ApiError::coded(
                StatusCode::PAYLOAD_TOO_LARGE,
                "PREVIEW_TOO_LARGE",
                "This file is too large to preview.",
                None,
            ),
            PreviewError::Unsupported => ApiError::coded(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "PREVIEW_UNSUPPORTED",
                "This file type cannot be previewed.",
                None,
            ),
            PreviewError::Database(e) => ApiError::Internal(format!("Database error: {e}")),
            PreviewError::Internal(msg) => ApiError::Internal(msg),
        }
    }
}

/// Previews read host files, so the agent helper never reads them (ADR-013), and paired phones
/// and browsers only while the owner allows it (ADR-017 D2, off by default).
async fn ensure_reader(
    state: &PreviewRouterState,
    user: &CurrentUser,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
) -> Result<(), ApiError> {
    if helper.is_some() {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "FS_OWNER_ONLY",
            "Only the desktop app can use the host filesystem.",
            None,
        ));
    }
    if (deviceless.is_some() || is_paired_device(device.as_ref().map(|Extension(device)| device)))
        && !state.service.devices_allowed(&user.id).await?
    {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "PREVIEW_DEVICES_DISABLED",
            "File preview on other devices is turned off in the desktop app.",
            None,
        ));
    }
    Ok(())
}

/// The device setting is changed and read in the desktop app only, like other device management.
fn ensure_manager(
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
) -> Result<(), ApiError> {
    if helper.is_some() || deviceless.is_some() || is_paired_device(device.as_ref().map(|Extension(device)| device)) {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "DEVICE_OWNER_ONLY",
            "Only the desktop app can manage devices.",
            None,
        ));
    }
    Ok(())
}

async fn list(
    State(state): State<PreviewRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Vec<ConversationFileView>>>, ApiError> {
    ensure_reader(&state, &user, helper, device, deviceless).await?;
    Ok(Json(ApiResponse::ok(state.service.list(&user.id, &id).await?)))
}

async fn content(
    State(state): State<PreviewRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    Path((id, file_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    ensure_reader(&state, &user, helper, device, deviceless).await?;
    let content = state.service.read(&user.id, &id, &file_id).await?;
    let csp = if content.mime == SVG { SVG_CSP } else { CONTENT_CSP };
    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content.mime)),
            (header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
            (header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment")),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp)),
        ],
        content.bytes,
    )
        .into_response())
}

/// PV06 (ADR-024): git HEAD against the file on disk, under the same reader gate as content.
async fn diff(
    State(state): State<PreviewRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    Path((id, file_id)): Path<(String, String)>,
) -> Result<Json<ApiResponse<FileDiffView>>, ApiError> {
    ensure_reader(&state, &user, helper, device, deviceless).await?;
    Ok(Json(ApiResponse::ok(
        state.service.diff(&user.id, &id, &file_id).await?,
    )))
}

async fn get_setting(
    State(state): State<PreviewRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
) -> Result<Json<ApiResponse<FilePreviewSettings>>, ApiError> {
    ensure_manager(helper, device, deviceless)?;
    let devices_allowed = state.service.devices_allowed(&user.id).await?;
    Ok(Json(ApiResponse::ok(FilePreviewSettings { devices_allowed })))
}

async fn put_setting(
    State(state): State<PreviewRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    body: Result<Json<FilePreviewSettings>, JsonRejection>,
) -> Result<Json<ApiResponse<FilePreviewSettings>>, ApiError> {
    ensure_manager(helper, device, deviceless)?;
    let Json(settings) = body.map_err(ApiError::from)?;
    state
        .service
        .set_devices_allowed(&user.id, settings.devices_allowed)
        .await?;
    Ok(Json(ApiResponse::ok(settings)))
}
