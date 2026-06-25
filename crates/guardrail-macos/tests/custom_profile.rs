#![cfg(target_os = "macos")]

use guardrail_macos::MacosBackend;

mod common;

#[test]
fn custom_profile_is_loaded_and_applied() {
    let temp_dir = TempDir::create();
    let secret = temp_dir.path().join("secret.txt");
    std::fs::write(&secret, b"top secret").unwrap();

    let profile_path = temp_dir.path().join("deny-secret.sb");
    std::fs::write(
        &profile_path,
        format!(
            "(version 1)\n\
             (allow default)\n\
             (deny file-read* (literal \"{}\"))\n",
            sbpl_string(&secret)
        ),
    )
    .unwrap();

    let config = common::base()
        .allow_read(temp_dir.path())
        .darwin_sandbox_profile(&profile_path)
        .build();
    let mut child = config
        .spawn_with(
            &MacosBackend::new(),
            common::probe(&["read-file", secret.to_str().unwrap()]),
        )
        .expect("spawn");

    assert!(
        !child.wait().expect("wait").success(),
        "the imported profile must deny reading the explicitly granted secret"
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
