//! Minting file refs and reading them back (ADR-017). A ref names a regular file inside the chat
//! folder, relative to the folder as it resolved when the ref was minted. Every read re-checks the
//! folder, the containment and that the opened file is the one at that path.

use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use aionui_api_types::{ConversationFileView, FileDiffView, PreviewKind};
use aionui_common::OnFilesReported;
use aionui_db::{ConversationFileRefRow, IConversationRepository, IPreviewRepository, UpsertFileRefParams};

use crate::error::PreviewError;
use crate::kind::{Kind, SNIFF_LEN, classify};

/// The bytes of a previewable file and the only Content-Type to serve them with.
#[derive(Debug)]
pub struct PreviewContent {
    pub mime: &'static str,
    pub bytes: Vec<u8>,
}

pub struct PreviewService {
    refs: Arc<dyn IPreviewRepository>,
    conversations: Arc<dyn IConversationRepository>,
}

impl PreviewService {
    pub fn new(refs: Arc<dyn IPreviewRepository>, conversations: Arc<dyn IConversationRepository>) -> Self {
        Self { refs, conversations }
    }

    /// Mint (or refresh) the ref for a path an agent reported in a conversation of `user_id`.
    /// Anything that is not an existing regular file inside the chat folder mints nothing.
    pub async fn mint(
        &self,
        user_id: &str,
        conversation_id: &str,
        reported: &str,
        call_id: Option<&str>,
    ) -> Result<Option<ConversationFileRefRow>, PreviewError> {
        let Some(workspace) = self.workspace(user_id, conversation_id).await? else {
            return Ok(None);
        };
        let reported = reported.trim().to_owned();
        let found = blocking(move || Ok(locate(&workspace, &reported).map(|found| (workspace, found)))).await?;
        let Some((workspace, (rel_path, meta))) = found else {
            tracing::debug!(conversation_id, "preview: reported path not minted");
            return Ok(None);
        };
        let row = self
            .refs
            .upsert_file_ref(UpsertFileRefParams {
                conversation_id,
                rel_path: &rel_path,
                workspace_canonical: &workspace.to_string_lossy(),
                call_id,
                size: meta.len() as i64,
                mtime_ms: mtime_ms(&meta),
            })
            .await?;
        Ok(Some(row))
    }

    /// The conversation's refs, newest first, with what each previews as now.
    pub async fn list(&self, user_id: &str, conversation_id: &str) -> Result<Vec<ConversationFileView>, PreviewError> {
        let workspace = self.owned_workspace(user_id, conversation_id).await?;
        let rows = self.refs.list_file_refs(conversation_id).await?;
        blocking(move || Ok(rows.into_iter().map(|row| view(workspace.as_deref(), row)).collect())).await
    }

    /// The bytes of a ref, if it still names the same kind of file inside the same chat folder.
    pub async fn read(
        &self,
        user_id: &str,
        conversation_id: &str,
        file_id: &str,
    ) -> Result<PreviewContent, PreviewError> {
        let workspace = self.owned_workspace(user_id, conversation_id).await?;
        let row = self
            .refs
            .find_file_ref(conversation_id, file_id)
            .await?
            .ok_or(PreviewError::FileNotFound)?;
        blocking(move || {
            let (kind, bytes) = read_checked(workspace.as_deref(), &row)?;
            Ok(PreviewContent { mime: kind.mime, bytes })
        })
        .await
    }

    /// PV06 (ADR-024): the git HEAD blob of a text ref against the file on disk now.
    pub async fn diff(
        &self,
        user_id: &str,
        conversation_id: &str,
        file_id: &str,
    ) -> Result<FileDiffView, PreviewError> {
        let workspace = self.owned_workspace(user_id, conversation_id).await?;
        let row = self
            .refs
            .find_file_ref(conversation_id, file_id)
            .await?
            .ok_or(PreviewError::FileNotFound)?;
        let (workspace, row, current) = blocking(move || {
            let (kind, bytes) = read_checked(workspace.as_deref(), &row)?;
            if !matches!(kind.preview, PreviewKind::Text | PreviewKind::Markdown) {
                return Err(PreviewError::Unsupported);
            }
            Ok((workspace, row, bytes))
        })
        .await?;
        let workspace = workspace.ok_or(PreviewError::FileNotFound)?;
        crate::diff::file_diff(&workspace, &row.rel_path, current).await
    }

    pub async fn devices_allowed(&self, user_id: &str) -> Result<bool, PreviewError> {
        Ok(self.refs.devices_allowed(user_id).await?)
    }

    pub async fn set_devices_allowed(&self, user_id: &str, allowed: bool) -> Result<(), PreviewError> {
        self.refs.set_devices_allowed(user_id, allowed).await?;
        tracing::info!(allowed, "preview: paired-device file preview setting changed");
        Ok(())
    }

    /// The conversation's chat folder as it resolves now; `ConversationNotFound` unless `user_id`
    /// owns the conversation, `None` when it has no folder or the folder is gone.
    async fn owned_workspace(&self, user_id: &str, conversation_id: &str) -> Result<Option<PathBuf>, PreviewError> {
        let row = self
            .conversations
            .get(user_id, conversation_id)
            .await?
            .ok_or(PreviewError::ConversationNotFound)?;
        let extra: serde_json::Value = serde_json::from_str(&row.extra).unwrap_or_default();
        let workspace = extra.get("workspace").and_then(|v| v.as_str()).unwrap_or("").trim();
        if workspace.is_empty() {
            return Ok(None);
        }
        let workspace = workspace.to_owned();
        blocking(move || Ok(std::fs::canonicalize(workspace).ok().filter(|p| p.is_dir()))).await
    }

    async fn workspace(&self, user_id: &str, conversation_id: &str) -> Result<Option<PathBuf>, PreviewError> {
        match self.owned_workspace(user_id, conversation_id).await {
            Err(PreviewError::ConversationNotFound) => Ok(None),
            other => other,
        }
    }
}

/// Agent tool calls reporting files they wrote mint refs (ADR-017). Every path is
/// validated by `mint`; refused or failed paths are logged without the path.
#[async_trait::async_trait]
impl OnFilesReported for PreviewService {
    async fn on_files_reported(&self, user_id: &str, conversation_id: &str, call_id: &str, paths: &[String]) {
        for path in paths {
            match self.mint(user_id, conversation_id, path, Some(call_id)).await {
                Ok(Some(_)) => tracing::debug!(conversation_id, call_id, "preview: ref minted"),
                Ok(None) => {}
                Err(err) => tracing::warn!(conversation_id, call_id, error = %err, "preview: minting a ref failed"),
            }
        }
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, PreviewError> + Send + 'static,
) -> Result<T, PreviewError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| PreviewError::Internal(e.to_string()))?
}

/// Resolve a reported path (absolute, or relative to the folder) to a regular file strictly inside
/// `workspace`, with its path relative to the folder in `/` form.
fn locate(workspace: &Path, reported: &str) -> Option<(String, Metadata)> {
    if reported.is_empty() {
        return None;
    }
    let target = std::fs::canonicalize(workspace.join(reported)).ok()?;
    let rel = target.strip_prefix(workspace).ok()?;
    let meta = std::fs::metadata(&target).ok().filter(Metadata::is_file)?;
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| (parts.join("/"), meta))
}

/// Open the ref's file only if the folder still resolves to the minted folder, the path still
/// resolves to itself (no symlink swapped in anywhere), it is a regular file, and the opened
/// handle is that same file.
fn open_checked(workspace: &Path, row: &ConversationFileRefRow) -> Option<(File, Metadata)> {
    if workspace.to_string_lossy() != row.workspace_canonical {
        return None;
    }
    let expected = row
        .rel_path
        .split('/')
        .try_fold(workspace.to_path_buf(), |path, part| {
            matches!(Path::new(part).components().next(), Some(Component::Normal(_))).then(|| path.join(part))
        })?;
    let file = File::open(&expected).ok()?;
    let opened = file.metadata().ok()?;
    if std::fs::canonicalize(&expected).ok()? != expected {
        return None;
    }
    let at_path = std::fs::symlink_metadata(&expected).ok()?;
    (at_path.is_file() && opened.is_file() && same_file(&opened, &at_path)).then_some((file, opened))
}

#[cfg(unix)]
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// Stable std has no file identity on other platforms; size and mtime are the closest check.
#[cfg(not(unix))]
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.len() == b.len() && a.modified().ok() == b.modified().ok()
}

/// The ref's kind and bytes, re-checked by `open_checked` and never read past the kind's cap.
fn read_checked(workspace: Option<&Path>, row: &ConversationFileRefRow) -> Result<(Kind, Vec<u8>), PreviewError> {
    let (mut file, meta) = workspace
        .and_then(|workspace| open_checked(workspace, row))
        .ok_or(PreviewError::FileNotFound)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(SNIFF_LEN as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| PreviewError::FileNotFound)?;
    let kind = classify(&row.rel_path, &bytes);
    let cap = kind.cap().ok_or(PreviewError::Unsupported)?;
    if meta.len() > cap {
        return Err(PreviewError::TooLarge);
    }
    // The file may grow after the size check; never read past the cap.
    file.take(cap + 1 - bytes.len() as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| PreviewError::FileNotFound)?;
    if bytes.len() as u64 > cap {
        return Err(PreviewError::TooLarge);
    }
    Ok((kind, bytes))
}

fn mtime_ms(meta: &Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis() as i64)
}

fn view(workspace: Option<&Path>, row: ConversationFileRefRow) -> ConversationFileView {
    let current = workspace.and_then(|workspace| open_checked(workspace, &row));
    let (kind, size, stale) = match current {
        Some((mut file, meta)) => {
            let mut head = Vec::new();
            let read = (&mut file).take(SNIFF_LEN as u64).read_to_end(&mut head).is_ok();
            let kind = if read {
                classify(&row.rel_path, &head)
            } else {
                Kind::UNSUPPORTED
            };
            let changed = meta.len() as i64 != row.size || mtime_ms(&meta) != row.mtime_ms;
            (kind, meta.len(), changed || !read)
        }
        None => (Kind::UNSUPPORTED, row.size.max(0) as u64, true),
    };
    ConversationFileView {
        too_large: kind.cap().is_some_and(|cap| size > cap),
        preview_kind: kind.preview,
        mime: kind.mime.to_owned(),
        size,
        stale,
        id: row.id,
        rel_path: row.rel_path,
        call_id: row.call_id,
        created_at: row.created_at,
    }
}
