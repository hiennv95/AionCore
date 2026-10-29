//! PV06 (ADR-024): the git HEAD blob of one previewable file against the file on disk now.
//!
//! Git only finds the repo and reads the HEAD blob; the diff itself runs with `--no-index` on
//! scratch copies, so no repo config, attribute, external diff or textconv applies to it.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use aionui_api_types::{FileDiffBase, FileDiffSource, FileDiffStatus, FileDiffView};
use aionui_runtime::Builder;
use tokio::io::AsyncReadExt;

use crate::error::PreviewError;
use crate::kind::{TEXT_CAP, is_text};

/// Diff text stops at 256 KB (`truncated: true`); separate from the 1 MB input cap per side.
pub const OUTPUT_CAP: usize = 256 * 1024;
/// Every git call is killed after this.
const GIT_TIMEOUT: Duration = Duration::from_secs(10);

/// `current` is the file's checked bytes (at most 1 MB of text); `rel` is its `/` path inside
/// the canonical `workspace`.
pub(crate) async fn file_diff(workspace: &Path, rel: &str, current: Vec<u8>) -> Result<FileDiffView, PreviewError> {
    let file = rel
        .split('/')
        .fold(workspace.to_path_buf(), |path, part| path.join(part));
    let dir = file.parent().unwrap_or(workspace);
    // Discovery never looks above the workspace; the root it finds must still be inside it.
    let ceiling = workspace.parent().unwrap_or(workspace);
    let top = git(ceiling, dir, ["rev-parse", "--show-toplevel"], 4096)
        .await?
        .and_then(|(out, _)| String::from_utf8(out).ok())
        .and_then(|out| std::fs::canonicalize(out.trim_end_matches(['\r', '\n'])).ok())
        .filter(|top| top.starts_with(workspace));
    let Some(repo_rel) = top.as_deref().and_then(|top| relative(&file, top)) else {
        return Ok(FileDiffView {
            source: FileDiffSource::HeadVsDisk,
            status: FileDiffStatus::NotARepo,
            base: None,
            diff: String::new(),
            truncated: false,
        });
    };
    let top = top.as_deref().unwrap_or(workspace);
    let spec = format!("HEAD:{repo_rel}");
    let base = match git(ceiling, top, ["cat-file", "-s", spec.as_str()], 64).await? {
        None => None,
        Some((size, _)) => {
            let size: u64 = String::from_utf8_lossy(&size).trim().parse().unwrap_or(u64::MAX);
            if size > TEXT_CAP {
                return Err(PreviewError::TooLarge);
            }
            let (blob, over) = git(ceiling, top, ["cat-file", "blob", spec.as_str()], TEXT_CAP as usize)
                .await?
                .ok_or_else(|| PreviewError::Internal("git could not read the HEAD blob".into()))?;
            if over {
                return Err(PreviewError::TooLarge);
            }
            if !is_text(&blob) {
                return Err(PreviewError::Unsupported);
            }
            Some(blob)
        }
    };

    let scratch = tempfile::tempdir().map_err(|e| PreviewError::Internal(e.to_string()))?;
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(scratch.path().join(name), bytes).map_err(|e| PreviewError::Internal(e.to_string()))
    };
    write("b", &current)?;
    let old = match &base {
        Some(blob) => write("a", blob).map(|()| "a")?,
        None => "/dev/null",
    };
    let args = [
        "diff",
        "--no-index",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--",
        old,
        "b",
    ];
    let scratch_ceiling = scratch.path().parent().unwrap_or(scratch.path());
    // Exit code 1 means "differs"; only the text matters.
    let (out, over) = git_any(scratch_ceiling, scratch.path(), args, OUTPUT_CAP + 4096).await?;
    let mut diff = relabel(&String::from_utf8_lossy(&out), rel);
    let mut truncated = over;
    if diff.len() > OUTPUT_CAP {
        let cut = diff[..diff.floor_char_boundary(OUTPUT_CAP)]
            .rfind('\n')
            .map_or(0, |i| i + 1);
        diff.truncate(cut);
        truncated = true;
    }
    Ok(FileDiffView {
        source: FileDiffSource::HeadVsDisk,
        status: FileDiffStatus::Ok,
        base: Some(if base.is_some() {
            FileDiffBase::Head
        } else {
            FileDiffBase::Absent
        }),
        diff,
        truncated,
    })
}

/// `file` relative to `top` in `/` form.
fn relative(file: &Path, top: &Path) -> Option<String> {
    let parts: Option<Vec<&str>> = file.strip_prefix(top).ok()?.iter().map(OsStr::to_str).collect();
    parts.filter(|p| !p.is_empty()).map(|p| p.join("/"))
}

/// Replace the scratch names in the header lines with `a/<rel>` and `b/<rel>`.
fn relabel(diff: &str, rel: &str) -> String {
    let mut out = String::with_capacity(diff.len() + 3 * rel.len());
    let mut in_header = true;
    for line in diff.split_inclusive('\n') {
        if line.starts_with("@@") {
            in_header = false;
        }
        let replaced = if !in_header {
            None
        } else if line.starts_with("diff --git ") {
            Some(format!("diff --git {} {}\n", label("a/", rel), label("b/", rel)))
        } else if line.starts_with("--- a/") {
            Some(format!("--- {}\n", label("a/", rel)))
        } else if line.starts_with("+++ b/") {
            Some(format!("+++ {}\n", label("b/", rel)))
        } else {
            None
        };
        out.push_str(replaced.as_deref().unwrap_or(line));
    }
    out
}

/// A header path; quoted with escapes, as git does, when it has control characters or quotes.
fn label(prefix: &str, rel: &str) -> String {
    let path = format!("{prefix}{rel}");
    if path.chars().any(|c| c.is_control() || c == '"' || c == '\\') {
        format!("{path:?}")
    } else {
        path
    }
}

/// Run git and keep stdout only when it exits 0. `None`: git said no (not a repo, no such blob).
async fn git<'a>(
    ceiling: &Path,
    cwd: &Path,
    args: impl IntoIterator<Item = &'a str>,
    limit: usize,
) -> Result<Option<(Vec<u8>, bool)>, PreviewError> {
    let (out, over, code) = run_git(ceiling, cwd, args, limit).await?;
    Ok((code == Some(0)).then_some((out, over)))
}

/// For `git diff`: exit 0 (same) and 1 (differs) are answers, and so is our own kill at the
/// output cap. Any other exit or a signal is an error, never an empty "ok" diff. Git also exits 1
/// when it cannot read an input, so exit 1 counts only with diff text on stdout.
async fn git_any<'a>(
    ceiling: &Path,
    cwd: &Path,
    args: impl IntoIterator<Item = &'a str>,
    limit: usize,
) -> Result<(Vec<u8>, bool), PreviewError> {
    let (out, over, code) = run_git(ceiling, cwd, args, limit).await?;
    diff_exit_ok(over, code, out.is_empty())?;
    Ok((out, over))
}

fn diff_exit_ok(over: bool, code: Option<i32>, empty: bool) -> Result<(), PreviewError> {
    match (over, code) {
        (true, _) | (false, Some(0)) => Ok(()),
        (false, Some(1)) if !empty => Ok(()),
        (false, code) => Err(PreviewError::Internal(match code {
            Some(code) => format!("git diff failed with exit code {code}"),
            None => "git diff was killed by a signal".into(),
        })),
    }
}

/// Git with no inherited env (no `GIT_DIR`, `GIT_WORK_TREE`, `GIT_CONFIG*`), no system or global
/// config, no prompts or optional locks, at most `limit` bytes of stdout, killed after the timeout.
/// Returns stdout, whether it went over `limit` (then git is killed and has no exit code), and
/// git's exit code (`None` for a signal).
async fn run_git<'a>(
    ceiling: &Path,
    cwd: &Path,
    args: impl IntoIterator<Item = &'a str>,
    limit: usize,
) -> Result<(Vec<u8>, bool, Option<i32>), PreviewError> {
    let internal = |e: std::io::Error| PreviewError::Internal(format!("git: {e}"));
    let mut cmd = Builder::clean_cli("git");
    cmd.env_clear();
    for key in ["PATH", "SYSTEMROOT"] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
    cmd.env("GIT_CEILING_DIRECTORIES", ceiling)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", if cfg!(windows) { "NUL" } else { "/dev/null" })
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C")
        .args(["--no-pager", "-c", "core.fsmonitor=false"])
        .args(args)
        .current_dir(cwd)
        .stderr(Stdio::null());
    let run = async {
        let mut child = cmd.spawn().map_err(internal)?;
        let mut out = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            stdout
                .take(limit as u64 + 1)
                .read_to_end(&mut out)
                .await
                .map_err(internal)?;
        }
        if out.len() > limit {
            out.truncate(limit);
            // Dropping the child kills it (kill_on_drop).
            return Ok((out, true, None));
        }
        let code = child.wait().await.map_err(internal)?.code();
        Ok((out, false, code))
    };
    tokio::time::timeout(GIT_TIMEOUT, run)
        .await
        .map_err(|_| PreviewError::Internal("git timed out".into()))?
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use aionui_api_types::{FileDiffBase, FileDiffSource, FileDiffStatus, FileDiffView};

    use super::*;

    fn git(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(ok.status.success(), "{args:?}: {}", String::from_utf8_lossy(&ok.stderr));
    }

    fn write(dir: &Path, rel: &str, bytes: &[u8]) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    /// A canonical scratch root with a `ws` folder in it.
    fn root() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let ws = std::fs::canonicalize(tmp.path()).unwrap().join("ws");
        std::fs::create_dir(&ws).unwrap();
        (tmp, ws)
    }

    fn commit_all(dir: &Path) {
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-qm", "c"]);
    }

    async fn run(ws: &Path, rel: &str) -> Result<FileDiffView, PreviewError> {
        let current = std::fs::read(ws.join(rel)).unwrap();
        file_diff(ws, rel, current).await
    }

    fn assert_no_paths(view: &FileDiffView, tmp: &tempfile::TempDir) {
        let text = serde_json::to_string(view).unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        assert!(!text.contains(root.to_str().unwrap()), "{text}");
        assert!(!text.contains(tmp.path().to_str().unwrap()), "{text}");
        assert!(
            !text.contains(&std::env::temp_dir().to_string_lossy().to_string()),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_tracked_file_diffs_head_against_disk_with_relative_headers() {
        let (tmp, ws) = root();
        git(&ws, &["init", "-q"]);
        write(&ws, "src/a.txt", b"one\nsame\n");
        commit_all(&ws);
        write(&ws, "src/a.txt", b"two\nsame\n");
        let view = run(&ws, "src/a.txt").await.unwrap();
        assert_eq!(view.source, FileDiffSource::HeadVsDisk);
        assert_eq!(view.status, FileDiffStatus::Ok);
        assert_eq!(view.base, Some(FileDiffBase::Head));
        assert!(!view.truncated);
        assert!(
            view.diff.starts_with("diff --git a/src/a.txt b/src/a.txt\n"),
            "{}",
            view.diff
        );
        assert!(
            view.diff.contains("\n--- a/src/a.txt\n+++ b/src/a.txt\n"),
            "{}",
            view.diff
        );
        assert!(view.diff.contains("\n-one\n+two\n"), "{}", view.diff);
        assert_no_paths(&view, &tmp);
    }

    #[tokio::test]
    async fn an_unchanged_file_has_an_empty_diff() {
        let (_tmp, ws) = root();
        git(&ws, &["init", "-q"]);
        write(&ws, "a.txt", b"x\n");
        commit_all(&ws);
        let view = run(&ws, "a.txt").await.unwrap();
        assert_eq!((view.base, view.diff.as_str()), (Some(FileDiffBase::Head), ""));
    }

    #[tokio::test]
    async fn an_untracked_file_has_an_absent_base_and_adds_every_line() {
        let (tmp, ws) = root();
        git(&ws, &["init", "-q"]);
        write(&ws, "new.txt", b"l1\nl2\n");
        let view = run(&ws, "new.txt").await.unwrap();
        assert_eq!(
            (view.status, view.base),
            (FileDiffStatus::Ok, Some(FileDiffBase::Absent))
        );
        assert!(view.diff.contains("\n--- /dev/null\n+++ b/new.txt\n"), "{}", view.diff);
        assert!(view.diff.contains("\n+l1\n+l2\n"), "{}", view.diff);
        assert!(!view.diff.lines().any(|l| l.starts_with('-') && !l.starts_with("---")));
        assert_no_paths(&view, &tmp);
    }

    #[tokio::test]
    async fn outside_any_repo_is_not_a_repo() {
        let (_tmp, ws) = root();
        write(&ws, "a.txt", b"x\n");
        let view = run(&ws, "a.txt").await.unwrap();
        assert_eq!(view.status, FileDiffStatus::NotARepo);
        assert_eq!((view.base, view.diff.as_str(), view.truncated), (None, "", false));
    }

    #[tokio::test]
    async fn a_repo_above_the_workspace_is_not_found() {
        let (tmp, ws) = root();
        let top = ws.parent().unwrap();
        git(top, &["init", "-q"]);
        write(&ws, "a.txt", b"x\n");
        commit_all(top);
        write(&ws, "a.txt", b"y\n");
        let view = run(&ws, "a.txt").await.unwrap();
        assert_eq!(view.status, FileDiffStatus::NotARepo);
        assert_no_paths(&view, &tmp);
    }

    #[tokio::test]
    async fn a_nested_repo_inside_the_workspace_uses_workspace_relative_headers() {
        let (_tmp, ws) = root();
        let sub = ws.join("sub");
        std::fs::create_dir(&sub).unwrap();
        git(&sub, &["init", "-q"]);
        write(&sub, "x.txt", b"a\n");
        commit_all(&sub);
        write(&sub, "x.txt", b"b\n");
        let view = run(&ws, "sub/x.txt").await.unwrap();
        assert_eq!(view.base, Some(FileDiffBase::Head));
        assert!(
            view.diff.contains("\n--- a/sub/x.txt\n+++ b/sub/x.txt\n"),
            "{}",
            view.diff
        );
    }

    #[tokio::test]
    async fn a_linked_worktree_with_metadata_outside_the_workspace_is_allowed() {
        let (tmp, ws) = root();
        let main = ws.parent().unwrap().join("main");
        std::fs::create_dir(&main).unwrap();
        git(&main, &["init", "-q"]);
        write(&main, "a.txt", b"one\n");
        commit_all(&main);
        std::fs::remove_dir(&ws).unwrap();
        git(&main, &["worktree", "add", "-q", ws.to_str().unwrap()]);
        assert!(ws.join(".git").is_file(), "a gitfile");
        write(&ws, "a.txt", b"two\n");
        let view = run(&ws, "a.txt").await.unwrap();
        assert_eq!(view.base, Some(FileDiffBase::Head));
        assert!(view.diff.contains("\n-one\n+two\n"), "{}", view.diff);
        assert_no_paths(&view, &tmp);
    }

    #[tokio::test]
    async fn a_gitfile_whose_worktree_is_outside_the_workspace_is_refused() {
        let (_tmp, ws) = root();
        let outside = ws.parent().unwrap().join("outside");
        std::fs::create_dir(&outside).unwrap();
        git(&outside, &["init", "-q"]);
        write(&outside, "a.txt", b"secret\n");
        commit_all(&outside);
        let gitdir = outside.join(".git");
        git(&outside, &["config", "core.worktree", outside.to_str().unwrap()]);
        write(&ws, ".git", format!("gitdir: {}\n", gitdir.display()).as_bytes());
        write(&ws, "a.txt", b"mine\n");
        let view = run(&ws, "a.txt").await.unwrap();
        assert_eq!(view.status, FileDiffStatus::NotARepo);
        assert!(!view.diff.contains("secret"));
    }

    #[tokio::test]
    async fn repo_config_cannot_run_external_diff_or_textconv() {
        let (_tmp, ws) = root();
        git(&ws, &["init", "-q"]);
        let marker = ws.parent().unwrap().join("pwned");
        let cmd = format!("sh -c 'touch {}' --", marker.display());
        git(&ws, &["config", "diff.external", &cmd]);
        git(&ws, &["config", "diff.evil.textconv", &cmd]);
        git(&ws, &["config", "diff.evil.command", &cmd]);
        write(&ws, ".gitattributes", b"*.txt diff=evil\n");
        write(&ws, "a.txt", b"one\n");
        commit_all(&ws);
        write(&ws, "a.txt", b"two\n");
        let view = run(&ws, "a.txt").await.unwrap();
        assert!(view.diff.contains("\n-one\n+two\n"), "{}", view.diff);
        assert!(!marker.exists(), "no repo-configured command ran");
    }

    #[tokio::test]
    async fn long_diffs_are_cut_at_the_output_cap() {
        let (_tmp, ws) = root();
        git(&ws, &["init", "-q"]);
        let line = |c: char| format!("{}\n", c.to_string().repeat(99));
        write(&ws, "a.txt", line('a').repeat(4000).as_bytes());
        commit_all(&ws);
        write(&ws, "a.txt", line('b').repeat(4000).as_bytes());
        let view = run(&ws, "a.txt").await.unwrap();
        assert!(view.truncated);
        assert!(view.diff.len() <= OUTPUT_CAP && view.diff.len() > OUTPUT_CAP / 2);
        assert!(view.diff.ends_with('\n'), "cut on a line");
    }

    #[tokio::test]
    async fn a_head_blob_over_the_input_cap_or_binary_is_refused() {
        let (_tmp, ws) = root();
        git(&ws, &["init", "-q"]);
        write(&ws, "big.txt", &vec![b'a'; TEXT_CAP as usize + 1]);
        write(&ws, "bin.txt", b"a\0b");
        commit_all(&ws);
        write(&ws, "big.txt", b"small\n");
        write(&ws, "bin.txt", b"text\n");
        assert!(matches!(run(&ws, "big.txt").await, Err(PreviewError::TooLarge)));
        assert!(matches!(run(&ws, "bin.txt").await, Err(PreviewError::Unsupported)));
    }

    #[tokio::test]
    async fn names_with_control_characters_cannot_forge_header_lines() {
        let (tmp, ws) = root();
        git(&ws, &["init", "-q"]);
        let rel = "x\n+++ b/evil.txt";
        write(&ws, rel, b"a\n");
        let view = run(&ws, rel).await.unwrap();
        assert_eq!(
            view.diff.lines().filter(|l| l.starts_with("+++ ")).count(),
            1,
            "{}",
            view.diff
        );
        assert!(!view.diff.lines().any(|l| l == "+++ b/evil.txt"));
        assert_no_paths(&view, &tmp);
    }

    #[test]
    fn only_diff_exits_0_and_1_or_our_cap_kill_are_answers() {
        assert!(diff_exit_ok(false, Some(0), true).is_ok());
        assert!(diff_exit_ok(false, Some(1), false).is_ok());
        assert!(diff_exit_ok(true, None, false).is_ok(), "killed at the output cap");
        let err = |r: Result<(), PreviewError>| matches!(r, Err(PreviewError::Internal(_)));
        assert!(err(diff_exit_ok(false, Some(1), true)), "exit 1 without diff text");
        assert!(err(diff_exit_ok(false, Some(2), false)));
        assert!(err(diff_exit_ok(false, Some(128), true)));
        assert!(err(diff_exit_ok(false, None, false)), "signal");
    }

    #[tokio::test]
    async fn a_failing_git_diff_is_an_error_not_an_empty_diff() {
        let (_tmp, ws) = root();
        write(&ws, "b", b"x\n");
        let ceiling = ws.parent().unwrap();
        let args = [
            "diff",
            "--no-index",
            "--no-ext-diff",
            "--no-textconv",
            "--",
            "missing",
            "b",
        ];
        let r = git_any(ceiling, &ws, args, OUTPUT_CAP).await;
        assert!(matches!(r, Err(PreviewError::Internal(_))), "{r:?}");
    }

    /// Inherited git env never points discovery or config elsewhere. Every other git call in
    /// this crate's tests clears its env, so setting these here affects nothing else.
    #[tokio::test]
    async fn inherited_git_env_is_ignored() {
        let (_tmp, ws) = root();
        let outside = ws.parent().unwrap().join("outside");
        std::fs::create_dir(&outside).unwrap();
        git(&outside, &["init", "-q"]);
        write(&outside, "a.txt", b"secret\n");
        commit_all(&outside);
        let config = ws.parent().unwrap().join("evil.gitconfig");
        let marker = ws.parent().unwrap().join("pwned");
        std::fs::write(
            &config,
            format!("[diff]\n\texternal = sh -c 'touch {}' --\n", marker.display()),
        )
        .unwrap();
        write(&ws, "a.txt", b"mine\n");
        // SAFETY: test-only; no other code in this binary reads these variables.
        unsafe {
            std::env::set_var("GIT_DIR", outside.join(".git"));
            std::env::set_var("GIT_WORK_TREE", &ws);
            std::env::set_var("GIT_CONFIG_GLOBAL", &config);
            std::env::set_var("GIT_CONFIG_COUNT", "1");
            std::env::set_var("GIT_CONFIG_KEY_0", "diff.external");
            std::env::set_var("GIT_CONFIG_VALUE_0", format!("sh -c 'touch {}' --", marker.display()));
        }
        let view = run(&ws, "a.txt").await.unwrap();
        unsafe {
            for k in [
                "GIT_DIR",
                "GIT_WORK_TREE",
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
            ] {
                std::env::remove_var(k);
            }
        }
        assert_eq!(view.status, FileDiffStatus::NotARepo, "{}", view.diff);
        assert!(!marker.exists());
    }
}
