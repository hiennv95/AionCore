//! Resolve chat-message file attachments to absolute device paths.
//!
//! The single shared point where a message's [`ChatFileRef`] list becomes
//! concrete paths, called at the send boundary by conversation + team. It
//! reproduces the legacy `[[AION_FILES]]` inlined-attachment content form so
//! every downstream consumer — aionrs `build_content_blocks`, the ACP prompt
//! (content-only), message persistence, and the user-message file chips in the
//! UI — is unchanged: only the *origin* of the paths moves from the client to
//! this backend edge.

use std::path::Path;

use aionui_api_types::ChatFileRef;
use aionui_common::constants::AIONUI_FILES_MARKER;

use crate::canonical;
use crate::service::ProjectService;
use crate::types::{FileOp, ProjectError, ReferenceInput};

/// A chat message whose attachments have been resolved to absolute paths and
/// re-inlined into [`content`](Self::content) via the `[[AION_FILES]]` marker.
#[derive(Debug)]
pub struct ResolvedChatMessage {
    /// User text with the attachment block appended (marker + one absolute path
    /// per line). Used verbatim for persistence, broadcast, and agent input.
    pub content: String,
    /// The resolved absolute paths, in order. Kept alongside `content` so
    /// aionrs's `build_content_blocks` strips the marker (files match) and
    /// re-adds its own; clearing this would leak the raw marker to aionrs.
    pub files: Vec<String>,
}

impl ProjectService {
    /// Resolve a message's `files` to absolute paths and return the inlined
    /// content. Atomic: any bad reference (unknown pe, escape, missing file,
    /// out-of-root upload, unreadable local path) fails the whole message.
    ///
    /// `upload_root` is the managed upload directory (`temp_dir()/aionui`);
    /// `Upload` paths must live under it.
    pub async fn resolve_chat_message(
        &self,
        user_id: &str,
        content: &str,
        files: &[ChatFileRef],
        upload_root: &Path,
    ) -> Result<ResolvedChatMessage, ProjectError> {
        self.resolve_chat_message_scoped(user_id, None, content, files, upload_root)
            .await
    }

    /// Resolve attachments for a message in a specific conversation.
    ///
    /// Conversation-scoped uploads can only be attached to the conversation
    /// named by their managed path. Unscoped (`general`) uploads remain valid
    /// for callers that do not bind an upload to a conversation (for example,
    /// team messages).
    pub async fn resolve_chat_message_for_conversation(
        &self,
        user_id: &str,
        conversation_id: &str,
        content: &str,
        files: &[ChatFileRef],
        upload_root: &Path,
    ) -> Result<ResolvedChatMessage, ProjectError> {
        self.resolve_chat_message_scoped(user_id, Some(conversation_id), content, files, upload_root)
            .await
    }

    async fn resolve_chat_message_scoped(
        &self,
        user_id: &str,
        conversation_id: Option<&str>,
        content: &str,
        files: &[ChatFileRef],
        upload_root: &Path,
    ) -> Result<ResolvedChatMessage, ProjectError> {
        let mut paths = Vec::with_capacity(files.len());
        for file in files {
            paths.push(
                self.resolve_chat_file_ref_scoped(user_id, conversation_id, file, upload_root, FileOp::Read)
                    .await?,
            );
        }

        let content = if paths.is_empty() {
            content.to_owned()
        } else {
            format!("{content}\n\n{AIONUI_FILES_MARKER}\n{}", paths.join("\n"))
        };
        Ok(ResolvedChatMessage { content, files: paths })
    }

    /// Resolve a single [`ChatFileRef`] to an absolute device path.
    ///
    /// The per-ref identity→path core shared by [`resolve_chat_message`](Self::resolve_chat_message)
    /// (send boundary) and the preview content endpoint (`aionui-file`, cross-crate — hence `pub`).
    /// Guards differ by variant:
    /// - `Project` → [`resolve_reference`](Self::resolve_reference) with the caller's `op` (lexical +
    ///   realpath containment; read paths pass `Read`, the write endpoint passes `Write`); must exist
    ///   (file or folder).
    /// - `Upload` → an existing regular file under the managed `upload_root` (D2 invariant).
    /// - `Local` → a canonicalized existing regular file; **no sandbox** (the host picker that
    ///   produced it already exposes the whole filesystem).
    ///
    /// `op` only affects the `Project` arm's containment mode; `Upload`/`Local` are path-based and
    /// identical regardless of op.
    pub async fn resolve_chat_file_ref(
        &self,
        user_id: &str,
        file: &ChatFileRef,
        upload_root: &Path,
        op: FileOp,
    ) -> Result<String, ProjectError> {
        self.resolve_chat_file_ref_scoped(user_id, None, file, upload_root, op)
            .await
    }

    async fn resolve_chat_file_ref_scoped(
        &self,
        user_id: &str,
        conversation_id: Option<&str>,
        file: &ChatFileRef,
        upload_root: &Path,
        op: FileOp,
    ) -> Result<String, ProjectError> {
        match file {
            ChatFileRef::Project { pe_id, relative_path } => {
                let resolved = self
                    .resolve_reference(
                        user_id,
                        ReferenceInput {
                            pe_id: pe_id.clone(),
                            relative_path: relative_path.clone(),
                            op,
                        },
                    )
                    .await?;
                let abs = resolved.absolute_path.ok_or_else(|| ProjectError::ChatFileMissing {
                    path: relative_path.clone(),
                })?;
                // A project ref may point at a file or a folder (the tree
                // allows attaching a directory); require only that it exists.
                if !Path::new(&abs).exists() {
                    return Err(ProjectError::ChatFileMissing { path: abs });
                }
                Ok(abs)
            }
            ChatFileRef::Upload { path } => {
                let candidate = Path::new(path);
                // Containment before existence, and no symlink followed on the way: the
                // answer for a path outside the upload dir, or behind a link in it, never
                // depends on whether something exists outside (audit, held unit 4).
                let rest = upload_path_in_root(upload_root, candidate, path)?;
                // Same refusal as outside the root, so another user's upload is not
                // told apart from a missing one.
                if !upload_owned_by(&rest, user_id) || !upload_matches_conversation(&rest, conversation_id) {
                    return Err(ProjectError::UploadPathOutsideRoot { path: path.clone() });
                }
                if !path_within(upload_root, candidate) {
                    return Err(ProjectError::UploadPathOutsideRoot { path: path.clone() });
                }
                Ok(path.clone())
            }
            ChatFileRef::Local { path } => {
                // A path the user explicitly picked in the host-file browser,
                // which already exposes the whole filesystem. No managed-root
                // restriction (that is the upload channel's D2 invariant only);
                // just canonicalize (collapsing `..`/symlinks) and require an
                // existing regular file.
                let canonical = std::fs::canonicalize(path)
                    .map_err(|_| ProjectError::LocalPathNotReadable { path: path.clone() })?;
                if !canonical.is_file() {
                    return Err(ProjectError::LocalPathNotReadable { path: path.clone() });
                }
                Ok(canonical.to_string_lossy().into_owned())
            }
        }
    }

    /// Upgrade a [`ChatFileRef`] to its strongest identity for `project_id`.
    ///
    /// A file opened from the explorer arrives as `Project{pe_id, relative_path}`,
    /// but the same file opened from a chat link arrives as `Local{path}` — two
    /// unequal refs for one file, so anything keyed on the ref (tab dedupe, the
    /// `fs` channel's change signal) treats them as different files. This turns a
    /// `Local` path that happens to live under one of the project's roots into the
    /// `Project` form, so equality reduces to comparing ref keys.
    ///
    /// Best-effort by design: a ref that cannot be upgraded is returned unchanged
    /// rather than rejected. Callers use the result for addressing, so "no stronger
    /// identity available" is a normal outcome, not an error.
    ///
    /// # Platform casing
    ///
    /// Whether two paths naming the same file compare equal is a platform
    /// property: `fs::canonicalize` resolves through a case-insensitive volume on
    /// macOS/Windows but not on Linux, the same divide
    /// [`canonical::IGNORE_PATH_CASING`] encodes for lexical identity. A caller
    /// doing its own `starts_with` on raw strings would miss matches on macOS and —
    /// worse — conflate distinct files on Linux, which is why this lives on the
    /// backend. Comparison here is between two realpaths, so the platform's own
    /// rule applies rather than a folding step of ours.
    pub async fn upgrade_chat_file_ref(
        &self,
        user_id: &str,
        project_id: &str,
        file: &ChatFileRef,
    ) -> Result<ChatFileRef, ProjectError> {
        // `Project` is already terminal, and `Upload` lives in a managed directory
        // that belongs to no root. Returning early also keeps the explorer's own
        // open path (already `Project`) from paying for a lookup it cannot use.
        let ChatFileRef::Local { path } = file else {
            return Ok(file.clone());
        };

        // Resolve symlinks and `..` before comparing, matching `path_within` and
        // `realpath_within`. A path that does not exist cannot be placed under a
        // root, and the caller still has a missing-file state to render, so keep the
        // local ref rather than failing.
        let Ok(absolute) = std::fs::canonicalize(path) else {
            return Ok(file.clone());
        };

        match self.find_owning_entry(user_id, project_id, &absolute).await? {
            Some((pe_id, relative_path)) => Ok(ChatFileRef::Project { pe_id, relative_path }),
            None => Ok(file.clone()),
        }
    }

    /// Find which of `project_id`'s roots contains `target`, with the path relative
    /// to it. `None` when the file sits outside every root. `target` must already be
    /// a realpath.
    ///
    /// The inverse of [`containment::resolve_relative`], which the codebase only had
    /// in the forward direction (given a root, is this path inside it). A project
    /// holds a handful of roots, so this walks them rather than indexing.
    ///
    /// At most one root can contain the file, so the first match is the answer:
    /// `attach_folder` focuses the existing entry when a descendant of a root is
    /// attached and rejects an ancestor as an overlap, which leaves the roots of a
    /// project mutually non-nesting.
    async fn find_owning_entry(
        &self,
        user_id: &str,
        project_id: &str,
        target: &Path,
    ) -> Result<Option<(String, String)>, ProjectError> {
        // Via the public project view rather than the store directly: this module
        // sits outside `service`, and widening the store's visibility to save one
        // hop would expose the whole data layer to every sibling module.
        let detail = self.get_project(user_id, project_id).await?;

        for entry in detail.explorer.entries {
            // Both sides must be realpaths for the prefix test to mean anything: a
            // stored root is lexical while the target came back from
            // `fs::canonicalize`, and on macOS that alone is the difference between
            // `/var/...` and `/private/var/...`.
            //
            // `uri_to_path` rather than `canonicalize`, matching `realpath_within`.
            // `canonicalize` would additionally ASCII-lowercase the path on
            // macOS/Windows, which serves lexical comparison — pointless here, since
            // the next line resolves the path for real. On a case-sensitive APFS
            // volume the lowercased form need not exist, and the failure would be
            // silent: this root would simply never match.
            let Ok(root_path) = canonical::uri_to_path(&entry.folder.resource_canonical) else {
                tracing::warn!(
                    pe_id = %entry.pe_id,
                    "stored folder URI is unparseable; skipping it while resolving a ref"
                );
                continue;
            };
            let Ok(root_path) = std::fs::canonicalize(&root_path) else {
                // A root whose folder is gone (unmounted, deleted) cannot own
                // anything; skip it instead of failing the whole lookup.
                tracing::warn!(
                    pe_id = %entry.pe_id,
                    "folder root is unreachable on disk; skipping it while resolving a ref"
                );
                continue;
            };
            // Not this root — the ordinary outcome for every root but one, so no log.
            let Ok(relative) = target.strip_prefix(&root_path) else {
                continue;
            };

            // Forward slashes on every platform: `relative_path` is a wire value
            // (protocol.md), not a host path.
            let relative_path = relative
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            return Ok(Some((entry.pe_id, relative_path)));
        }

        Ok(None)
    }
}

/// An upload ref must name a regular file reached from the upload root through
/// regular directories only. The path must be absolute, without `..`, and start with
/// `root` (as given or resolved). Each component below the root is then looked at
/// with `symlink_metadata`, which does not follow links:
/// - a symlink anywhere is refused as outside the root, without looking behind it;
/// - a missing component is `ChatFileMissing`, which only describes the inside of
///   the root.
///
/// This is a read-time check, not a guarantee from the writer: `create_upload_file`
/// creates directories along a path, so whatever is on disk is checked here.
fn upload_path_in_root(root: &Path, target: &Path, path: &str) -> Result<std::path::PathBuf, ProjectError> {
    let outside = || ProjectError::UploadPathOutsideRoot { path: path.to_owned() };
    if !target.is_absolute()
        || target
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(outside());
    }
    if !trusted_upload_root(root) {
        tracing::warn!(root = %root.display(), "upload root is not a private directory of this user; refusing upload refs");
        return Err(outside());
    }
    let (base, rest) = match target.strip_prefix(root) {
        Ok(rest) => (root.to_path_buf(), rest.to_path_buf()),
        Err(_) => {
            let canonical = std::fs::canonicalize(root).map_err(|_| outside())?;
            let rest = target.strip_prefix(&canonical).map_err(|_| outside())?.to_path_buf();
            (canonical, rest)
        }
    };
    let parts: Vec<_> = rest.components().collect();
    if parts.is_empty() {
        return Err(outside());
    }
    let mut current = base;
    for (index, part) in parts.iter().enumerate() {
        current.push(part);
        let meta =
            std::fs::symlink_metadata(&current).map_err(|_| ProjectError::ChatFileMissing { path: path.to_owned() })?;
        if meta.file_type().is_symlink() {
            return Err(outside());
        }
        let last = index + 1 == parts.len();
        if (last && !meta.is_file()) || (!last && !meta.is_dir()) {
            return Err(ProjectError::ChatFileMissing { path: path.to_owned() });
        }
        // A directory another account can write could have links planted or swapped in.
        if !last && !private_dir(&meta) {
            return Err(outside());
        }
    }
    Ok(rest)
}

/// Directory under the upload root that holds one user's uploads
/// (`users/<user dir>/<conversation|general>/<file>`, written by `create_upload_file`).
pub const UPLOAD_USERS_DIR: &str = "users";

/// Whether an upload (`rest`, relative to the upload root) belongs to `user_id`: it sits
/// in that user's namespace. Uploads from before the namespace (`<conversation>/<file>`)
/// have no recorded owner; they stay readable only by the single-owner account
/// `system_default_user`, never by anyone else.
fn upload_owned_by(rest: &Path, user_id: &str) -> bool {
    let mut parts = rest.components().map(|c| c.as_os_str());
    match parts.next() {
        Some(first) if first == UPLOAD_USERS_DIR => aionui_common::user_dir_name(user_id)
            .is_ok_and(|dir| parts.next().is_some_and(|owner| owner == dir.as_str())),
        _ => user_id == LEGACY_UPLOAD_OWNER,
    }
}

/// Whether a namespaced upload belongs to the conversation at the send
/// boundary. Generic file endpoints pass `None` because their request does not
/// carry a conversation identity.
fn upload_matches_conversation(rest: &Path, conversation_id: Option<&str>) -> bool {
    let mut parts = rest.components().map(|c| c.as_os_str());
    if parts.next() != Some(std::ffi::OsStr::new(UPLOAD_USERS_DIR)) {
        return conversation_id.is_none();
    }
    let _owner = parts.next();
    let Some(scope) = parts.next() else { return false };
    match conversation_id {
        None => true,
        Some(id) => scope == std::ffi::OsStr::new("general") || scope == std::ffi::OsStr::new(id),
    }
}

const LEGACY_UPLOAD_OWNER: &str = "system_default_user";

/// The upload root itself is a real directory (not a symlink) that passes [`private_dir`].
/// Otherwise a root planted in a shared temp dir, or replaced with a link, would make any
/// directory count as "the upload dir". The directories above the root are trusted (on
/// macOS `temp_dir()` itself lives under `/var`, a link).
fn trusted_upload_root(root: &Path) -> bool {
    std::fs::symlink_metadata(root).is_ok_and(|meta| meta.file_type().is_dir() && private_dir(&meta))
}

/// On unix: owned by this user and writable by neither group nor others (mode bits only;
/// ACLs are not inspected). Elsewhere: no ownership model is checked.
fn private_dir(meta: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and cannot fail.
        meta.uid() == unsafe { libc::geteuid() } && meta.permissions().mode() & 0o022 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        true
    }
}

/// Whether `target` resolves inside `root` (both canonicalized, so `..` and
/// symlinks cannot escape). `target` is expected to exist (checked before).
fn path_within(root: &Path, target: &Path) -> bool {
    let (Ok(root), Ok(target)) = (std::fs::canonicalize(root), std::fs::canonicalize(target)) else {
        return false;
    };
    target.starts_with(root)
}

#[cfg(test)]
#[path = "chat_files_test.rs"]
mod chat_files_test;
