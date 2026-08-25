use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=VALIDATOR_BUILD_REVISION");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");

    let base_revision = std::env::var("VALIDATOR_BUILD_REVISION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(local_revision)
        .unwrap_or_else(|| "unknown".to_string());
    let revision = format!("{base_revision}+src:{:016x}", source_fingerprint());
    println!("cargo:rustc-env=VALIDATOR_GIT_SHA={revision}");
}

fn local_revision() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!sha.is_empty()).then_some(sha)
}

fn source_fingerprint() -> u64 {
    fn collect(path: &Path, files: &mut Vec<PathBuf>) {
        if path.is_file() {
            files.push(path.to_path_buf());
        } else if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                collect(&entry.path(), files);
            }
        }
    }
    fn update(mut hash: u64, bytes: &[u8]) -> u64 {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
        hash
    }

    let mut files = Vec::new();
    collect(Path::new("src"), &mut files);
    for path in ["Cargo.toml", "Cargo.lock", "build.rs"] {
        collect(Path::new(path), &mut files);
    }
    files.sort();

    let mut hash = 0xcbf2_9ce4_8422_2325;
    for path in files {
        hash = update(hash, path.to_string_lossy().as_bytes());
        if let Ok(content) = std::fs::read(path) {
            hash = update(hash, &content);
        }
    }
    hash
}
