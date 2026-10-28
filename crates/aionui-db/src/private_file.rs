//! Owner-only files for copies of the database (audit H1). A copy holds the JWT
//! signing and storage-encryption secrets, so it must never exist with the umask's
//! mode, even briefly, and must never be written through a planted symlink.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Creates `path` as a new, empty, owner-only (0600) file. Fails if anything,
/// including a symlink, already exists there.
pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Copies `from` into a new owner-only file at `to` (see [`create_private_file`]).
pub(crate) fn copy_to_private_file(from: &Path, to: &Path) -> io::Result<u64> {
    let mut source = File::open(from)?;
    let mut target = create_private_file(to)?;
    let copied = io::copy(&mut source, &mut target)?;
    target.sync_all()?;
    Ok(copied)
}

/// Restricts an existing regular file to the owner (0600) through a descriptor opened
/// without following a symlink, so the mode of whatever a symlink points at is never
/// changed, even if the path is swapped between a check and the chmod. Refuses a symlink
/// or any non-regular file. The parent directory is trusted (the 0700 data dir).
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        // O_NONBLOCK: opening a planted FIFO must not hang.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
