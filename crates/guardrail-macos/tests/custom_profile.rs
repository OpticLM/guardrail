#![cfg(target_os = "macos")]

use guardrail_core::{Backend, StdioMode};
use guardrail_macos::MacosBackend;

mod common;

#[test]
fn custom_profile_is_loaded_and_applied() {
    let temp_dir = TempDir::create();
    let secret = temp_dir.path().join("secret.txt");
    std::fs::write(&secret, b"top secret").unwrap();
    let canonical_secret = std::fs::canonicalize(&secret).unwrap_or_else(|_| secret.clone());

    let profile_path = temp_dir.path().join("deny-secret.sb");
    let profile_source = format!(
        "(version 1)\n\
         (allow file-read* (literal \"{}\"))\n\
         (allow file-read* (literal \"{}\"))\n",
        sbpl_string(&secret),
        sbpl_string(&canonical_secret)
    );
    std::fs::write(&profile_path, &profile_source).unwrap();

    let mut config = common::base();
    config.darwin_sandbox_profiles.push(profile_path);
    let mut command = common::probe(&["read-file", secret.to_str().unwrap()]);
    command.stdout = StdioMode::Piped;
    command.stderr = StdioMode::Piped;
    let child = MacosBackend::new(config.clone())
        .and_then(|backend| backend.spawn(command))
        .expect("spawn");
    let output = child.wait_with_output().expect("wait");

    assert!(
        output.status.success(),
        "the imported profile must grant reading a path absent from generated FsAccess rules\n\
         status: {}\n\
         stderr:\n{}\n\
         profile:\n{}\n\
         config: {:#?}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        profile_source,
        config
    );
}

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!(
            "guardrail-macos-custom-profile-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn sbpl_string(path: &std::path::Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}
