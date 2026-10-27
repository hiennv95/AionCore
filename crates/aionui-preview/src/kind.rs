//! What a file previews as, decided by the host from its name and its first bytes.

use aionui_api_types::PreviewKind;

/// Text and Markdown previews stop at 1 MB.
pub const TEXT_CAP: u64 = 1024 * 1024;
/// Image previews stop at 20 MB.
pub const IMAGE_CAP: u64 = 20 * 1024 * 1024;
/// Bytes read to decide the kind.
pub const SNIFF_LEN: usize = 8192;

const OCTET_STREAM: &str = "application/octet-stream";
const TEXT: &str = "text/plain; charset=utf-8";
const MARKDOWN: &str = "text/markdown; charset=utf-8";
pub const SVG: &str = "image/svg+xml";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kind {
    pub preview: PreviewKind,
    /// The only Content-Type the host serves this file with.
    pub mime: &'static str,
}

impl Kind {
    pub const UNSUPPORTED: Kind = Kind {
        preview: PreviewKind::Unsupported,
        mime: OCTET_STREAM,
    };

    /// The cap for this kind; `None` for unsupported files.
    pub fn cap(&self) -> Option<u64> {
        match self.preview {
            PreviewKind::Text | PreviewKind::Markdown => Some(TEXT_CAP),
            PreviewKind::Image => Some(IMAGE_CAP),
            PreviewKind::Unsupported => None,
        }
    }
}

/// Text and code files by extension (lower case). HTML and XML are shown as source.
const TEXT_EXTENSIONS: &[&str] = &[
    "txt",
    "text",
    "log",
    "csv",
    "tsv",
    "json",
    "jsonl",
    "json5",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "env",
    "properties",
    "xml",
    "html",
    "htm",
    "xhtml",
    "css",
    "scss",
    "sass",
    "less",
    "js",
    "mjs",
    "cjs",
    "jsx",
    "ts",
    "mts",
    "cts",
    "tsx",
    "vue",
    "svelte",
    "rs",
    "go",
    "py",
    "pyi",
    "rb",
    "java",
    "kt",
    "kts",
    "scala",
    "swift",
    "m",
    "mm",
    "c",
    "h",
    "cc",
    "cpp",
    "cxx",
    "hpp",
    "hh",
    "cs",
    "fs",
    "php",
    "pl",
    "pm",
    "lua",
    "r",
    "dart",
    "ex",
    "exs",
    "erl",
    "hrl",
    "hs",
    "ml",
    "mli",
    "clj",
    "cljs",
    "elm",
    "zig",
    "nim",
    "sh",
    "bash",
    "zsh",
    "fish",
    "ps1",
    "psm1",
    "bat",
    "cmd",
    "sql",
    "graphql",
    "gql",
    "proto",
    "gradle",
    "cmake",
    "mk",
    "dockerfile",
    "tf",
    "hcl",
    "nix",
    "diff",
    "patch",
    "tex",
    "rst",
    "adoc",
    "org",
    "lock",
    "gitignore",
    "gitattributes",
    "dockerignore",
    "editorconfig",
    "npmrc",
    "nvmrc",
];

/// Text files known by their whole name.
const TEXT_NAMES: &[&str] = &[
    "makefile",
    "dockerfile",
    "containerfile",
    "justfile",
    "rakefile",
    "gemfile",
    "procfile",
    "vagrantfile",
    "license",
    "licence",
    "readme",
    "changelog",
    "authors",
    "contributors",
    "notice",
    "copying",
    "codeowners",
];

/// Raster images are recognised by their magic bytes, never by extension alone. SVG, Markdown and
/// text go by an allow-listed name and must also be UTF-8 without NUL bytes. Everything else is
/// unsupported.
pub fn classify(rel_path: &str, head: &[u8]) -> Kind {
    let name = rel_path.rsplit('/').next().unwrap_or_default().to_ascii_lowercase();
    let ext = name.rsplit_once('.').map(|(_, ext)| ext).unwrap_or_default();
    let text = || is_text(head);
    match ext {
        "png" | "jpg" | "jpeg" | "gif" | "webp" => raster(head).map_or(Kind::UNSUPPORTED, |mime| Kind {
            preview: PreviewKind::Image,
            mime,
        }),
        "svg" if text() => Kind {
            preview: PreviewKind::Image,
            mime: SVG,
        },
        "md" | "markdown" if text() => Kind {
            preview: PreviewKind::Markdown,
            mime: MARKDOWN,
        },
        _ if (TEXT_EXTENSIONS.contains(&ext) || TEXT_NAMES.contains(&name.as_str())) && text() => Kind {
            preview: PreviewKind::Text,
            mime: TEXT,
        },
        _ => Kind::UNSUPPORTED,
    }
}

fn raster(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if head.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// UTF-8 without NUL bytes. A multi-byte character cut by the end of the sniffed bytes is fine.
fn is_text(head: &[u8]) -> bool {
    if head.contains(&0) {
        return false;
    }
    match std::str::from_utf8(head) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_come_from_bytes_as_well_as_names() {
        assert_eq!(classify("a.png", b"\x89PNG\r\n\x1a\n").mime, "image/png");
        assert_eq!(
            classify("a.PNG", b"GIF89a..").mime,
            "image/gif",
            "magic wins over extension"
        );
        assert_eq!(classify("a.png", b"<svg/>").preview, PreviewKind::Unsupported);
        assert_eq!(classify("a.webp", b"RIFF\0\0\0\0WEBPVP8 ").mime, "image/webp");
        assert_eq!(classify("a.svg", b"<svg/>").mime, SVG);
        assert_eq!(classify("a.md", b"# t").preview, PreviewKind::Markdown);
        assert_eq!(classify("a.html", b"<b>x</b>").mime, TEXT);
        assert_eq!(classify("Makefile", b"all:").preview, PreviewKind::Text);
        assert_eq!(classify(".env", b"A=1").preview, PreviewKind::Text);
        assert_eq!(classify("dir.d/Dockerfile", b"FROM x").preview, PreviewKind::Text);
        assert_eq!(classify("src/main.RS", b"fn main() {}").preview, PreviewKind::Text);
        // Text needs an allow-listed name as well as UTF-8 (spec 4.4).
        assert_eq!(classify("notes", b"plain").preview, PreviewKind::Unsupported);
        assert_eq!(classify("a.pdf", b"%PDF-1.7").preview, PreviewKind::Unsupported);
        assert_eq!(classify("a.exe", b"MZ").preview, PreviewKind::Unsupported);
        assert_eq!(classify("a.bin", &[0xff, 0xfe, 0, 1]).preview, PreviewKind::Unsupported);
        assert_eq!(classify("a.txt", b"a\0b").preview, PreviewKind::Unsupported);
        assert_eq!(
            classify("a.txt", "xé".as_bytes()[..2].as_ref()).preview,
            PreviewKind::Text
        );
    }
}
