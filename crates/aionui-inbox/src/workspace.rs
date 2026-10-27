//! What the chat folder looked like when a turn ended (B05.R1), read by the host itself.
//!
//! The fingerprint hashes the head commit and every changed path (untracked included,
//! ignored excluded) with its status, size and modification time. Any later edit, commit
//! or checkout changes it, which makes a receipt's evidence stale. File contents are never
//! read, and nothing is logged with a path.
use std::path::Path;
use std::time::UNIX_EPOCH;

use git2::{ErrorCode, Repository, StatusOptions};
use sha2::{Digest, Sha256};

/// Most changed paths hashed; beyond it the fingerprint marks the list as cut off.
const MAX_ENTRIES: usize = 20_000;

/// A read of the chat folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceRead {
    /// A git work tree: the head commit (when one exists) and the fingerprint.
    Git { head: Option<String>, fingerprint: String },
    /// A readable folder that is not inside a git work tree.
    NotGit,
    /// No folder, or it could not be read.
    Unknown,
}

impl WorkspaceRead {
    pub fn state(&self) -> &'static str {
        match self {
            Self::Git { .. } => "git",
            Self::NotGit => "not_git",
            Self::Unknown => "unknown",
        }
    }
}

/// Reads the folder; blocking (git status walks the tree), so call it off the async runtime.
pub fn read_workspace(path: &Path) -> WorkspaceRead {
    if !path.is_dir() {
        return WorkspaceRead::Unknown;
    }
    let repo = match Repository::discover(path) {
        Ok(repo) if !repo.is_bare() => repo,
        Ok(_) => return WorkspaceRead::NotGit,
        Err(e) if e.code() == ErrorCode::NotFound => return WorkspaceRead::NotGit,
        Err(_) => return WorkspaceRead::Unknown,
    };
    let head = match repo.head() {
        Ok(head) => head.target().map(|oid| oid.to_string()),
        Err(e) if matches!(e.code(), ErrorCode::UnbornBranch | ErrorCode::NotFound) => None,
        Err(_) => return WorkspaceRead::Unknown,
    };
    let mut options = StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_ignored(false)
        .renames_head_to_index(false);
    let Ok(statuses) = repo.statuses(Some(&mut options)) else {
        return WorkspaceRead::Unknown;
    };
    let workdir = repo.workdir().map(Path::to_path_buf);
    let mut entries: Vec<(String, u32, u64, u128)> = statuses
        .iter()
        .take(MAX_ENTRIES + 1)
        .filter_map(|entry| {
            let rel = entry.path().ok()?.to_owned();
            let (size, mtime) = workdir
                .as_ref()
                .and_then(|root| std::fs::symlink_metadata(root.join(&rel)).ok())
                .map(|meta| {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map_or(0, |d| d.as_nanos());
                    (meta.len(), mtime)
                })
                .unwrap_or((0, 0));
            Some((rel, entry.status().bits(), size, mtime))
        })
        .collect();
    entries.sort();
    let mut hasher = Sha256::new();
    hasher.update(head.as_deref().unwrap_or("unborn").as_bytes());
    for (path, status, size, mtime) in entries.iter().take(MAX_ENTRIES) {
        hasher.update([0u8]);
        hasher.update(path.as_bytes());
        hasher.update(status.to_le_bytes());
        hasher.update(size.to_le_bytes());
        hasher.update(mtime.to_le_bytes());
    }
    if entries.len() > MAX_ENTRIES {
        hasher.update(b"truncated");
    }
    WorkspaceRead::Git {
        head,
        fingerprint: hex::encode(hasher.finalize()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &Path) -> Repository {
        let repo = Repository::init(dir).unwrap();
        std::fs::write(dir.join("a.txt"), "one").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("a.txt")).unwrap();
        index.write().unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let sig = git2::Signature::now("t", "t@example.com").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[]).unwrap();
        drop(tree);
        repo
    }

    fn fingerprint(read: &WorkspaceRead) -> String {
        match read {
            WorkspaceRead::Git { fingerprint, .. } => fingerprint.clone(),
            other => panic!("not git: {other:?}"),
        }
    }

    #[test]
    fn an_edit_or_a_new_file_changes_the_fingerprint_and_a_reread_does_not() {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path());
        let clean = read_workspace(dir.path());
        assert!(matches!(&clean, WorkspaceRead::Git { head: Some(h), .. } if h.len() == 40));
        assert_eq!(fingerprint(&read_workspace(dir.path())), fingerprint(&clean));

        std::fs::write(dir.path().join("a.txt"), "two!").unwrap();
        let edited = read_workspace(dir.path());
        assert_ne!(fingerprint(&edited), fingerprint(&clean));

        std::fs::write(dir.path().join("new.txt"), "x").unwrap();
        assert_ne!(fingerprint(&read_workspace(dir.path())), fingerprint(&edited));
    }

    #[test]
    fn ignored_files_do_not_count() {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path());
        std::fs::write(dir.path().join(".gitignore"), "build/\n").unwrap();
        let before = fingerprint(&read_workspace(dir.path()));
        std::fs::create_dir(dir.path().join("build")).unwrap();
        std::fs::write(dir.path().join("build/out.bin"), "x").unwrap();
        assert_eq!(fingerprint(&read_workspace(dir.path())), before);
    }

    #[test]
    fn an_unborn_repo_a_plain_folder_and_a_missing_folder() {
        let dir = tempfile::tempdir().unwrap();
        Repository::init(dir.path()).unwrap();
        assert!(matches!(
            read_workspace(dir.path()),
            WorkspaceRead::Git { head: None, .. }
        ));

        let plain = tempfile::tempdir().unwrap();
        assert_eq!(read_workspace(plain.path()), WorkspaceRead::NotGit);
        assert_eq!(read_workspace(&plain.path().join("missing")), WorkspaceRead::Unknown);
    }
}
