//! Retention of the dated log tree (`<root>/YYYY/MM/DD/YYYY-MM-DD.<suffix>`).
//!
//! The daily writers never deleted anything, so a long-running host grew its
//! log directory forever. On each day rollover the writer calls
//! [`prune_old_log_days`], which removes whole day directories older than the
//! retention window. Only directories whose names are a valid date are touched,
//! so anything else placed under the log root is left alone.

use std::fs;
use std::path::Path;

use chrono::NaiveDate;

/// Days of logs kept, today included.
pub(super) const LOG_RETENTION_DAYS: i64 = 30;

/// Removes `YYYY/MM/DD` directories dated before `today - (keep_days - 1)`,
/// then any month/year directory left empty. Returns how many day directories
/// were removed. Best effort: an unreadable or locked entry is skipped, never
/// fatal, because this runs inside the log writer.
pub(super) fn prune_old_log_days(root: &Path, today: NaiveDate, keep_days: i64) -> usize {
    let Some(oldest_kept) = today.checked_sub_signed(chrono::Duration::days(keep_days - 1)) else {
        return 0;
    };
    let mut removed = 0;
    for (year_dir, year) in numbered_children(root, 4) {
        for (month_dir, month) in numbered_children(&year_dir, 2) {
            for (day_dir, day) in numbered_children(&month_dir, 2) {
                let Some(date) = NaiveDate::from_ymd_opt(year as i32, month, day) else {
                    continue;
                };
                if date < oldest_kept && fs::remove_dir_all(&day_dir).is_ok() {
                    removed += 1;
                }
            }
            // Fails (and keeps the directory) while it still holds kept days.
            let _ = fs::remove_dir(&month_dir);
        }
        let _ = fs::remove_dir(&year_dir);
    }
    removed
}

/// Child directories named by exactly `width` ASCII digits, with their value.
fn numbered_children(dir: &Path, width: usize) -> Vec<(std::path::PathBuf, u32)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if name.len() != width || !name.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((e.path(), name.parse().ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(root: &Path, y: i32, m: u32, d: u32) -> std::path::PathBuf {
        let dir = root.join(format!("{y:04}/{m:02}/{d:02}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{y:04}-{m:02}-{d:02}.aioncore.log")), b"x").unwrap();
        dir
    }

    #[test]
    fn removes_days_outside_the_window_and_empty_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let old = day(root, 2026, 8, 31);
        let edge_out = day(root, 2026, 9, 25);
        let edge_in = day(root, 2026, 9, 26);
        let today = day(root, 2026, 10, 25);

        let removed = prune_old_log_days(root, NaiveDate::from_ymd_opt(2026, 10, 25).unwrap(), 30);

        assert_eq!(removed, 2);
        assert!(!old.exists() && !edge_out.exists());
        assert!(!root.join("2026/08").exists(), "an emptied month is removed");
        assert!(edge_in.exists() && today.exists(), "the last 30 days stay");
    }

    #[test]
    fn leaves_anything_that_is_not_a_dated_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("archive/2020")).unwrap();
        fs::create_dir_all(root.join("2019/13/40")).unwrap(); // not a real date
        fs::write(root.join("notes.txt"), b"keep").unwrap();

        prune_old_log_days(root, NaiveDate::from_ymd_opt(2026, 10, 25).unwrap(), 30);

        assert!(root.join("archive/2020").exists());
        assert!(root.join("2019/13/40").exists());
        assert!(root.join("notes.txt").exists());
    }

    #[test]
    fn a_missing_root_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            prune_old_log_days(
                &tmp.path().join("nope"),
                NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
                30
            ),
            0
        );
    }
}
