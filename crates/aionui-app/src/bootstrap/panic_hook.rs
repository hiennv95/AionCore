//! Process-wide panic hook: records panics in the tracing log, then defers
//! to the default hook (stderr message / backtrace behaviour is unchanged).

use std::panic::PanicHookInfo;

/// Upper bound on the panic message copied into the log. Panic messages can
/// embed `Debug` output of arbitrary values, so the log copy is capped.
const MAX_MESSAGE_CHARS: usize = 200;

/// Installs the hook. Call once, early in `main`.
pub(crate) fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let (location, message) = describe_panic(info);
        let thread = std::thread::current();
        tracing::error!(thread = thread.name().unwrap_or("<unnamed>"), %location, %message, "panic");
        default_hook(info);
    }));
}

fn describe_panic(info: &PanicHookInfo<'_>) -> (String, String) {
    let location = info.location().map_or_else(
        || "<unknown>".to_owned(),
        |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
    );
    let raw = info.payload_as_str().unwrap_or("<non-string panic payload>");
    (location, truncate_message(raw))
}

fn truncate_message(raw: &str) -> String {
    let mut chars = raw.chars();
    let mut out: String = chars.by_ref().take(MAX_MESSAGE_CHARS).collect();
    if chars.next().is_some() {
        out.push_str("…[truncated]");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// The panic hook is process-global; serialise tests that swap it.
    static HOOK_LOCK: Mutex<()> = Mutex::new(());

    fn capture_panic(f: impl FnOnce() + std::panic::UnwindSafe) -> (String, String) {
        let _guard = HOOK_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let captured = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&captured);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            *sink.lock().unwrap() = Some(describe_panic(info));
        }));
        let _ = std::panic::catch_unwind(f);
        std::panic::set_hook(prev);
        captured.lock().unwrap().take().expect("hook ran")
    }

    #[test]
    fn formats_location_and_str_message() {
        let (location, message) = capture_panic(|| panic!("boom"));
        assert!(location.contains("panic_hook.rs:"), "{location}");
        assert_eq!(message, "boom");
    }

    #[test]
    fn formats_string_message() {
        let (_, message) = capture_panic(|| panic!("value {}", 7));
        assert_eq!(message, "value 7");
    }

    #[test]
    fn non_string_payload_is_not_logged() {
        let (_, message) = capture_panic(|| std::panic::panic_any(42_u32));
        assert_eq!(message, "<non-string panic payload>");
    }

    #[test]
    fn long_message_is_truncated() {
        let long = "x".repeat(MAX_MESSAGE_CHARS + 50);
        assert_eq!(
            truncate_message(&long),
            format!("{}…[truncated]", "x".repeat(MAX_MESSAGE_CHARS))
        );
        assert_eq!(truncate_message("short"), "short");
    }
}
