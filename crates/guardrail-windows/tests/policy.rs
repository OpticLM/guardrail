#![cfg(windows)]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::mem;
use std::net::TcpListener;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use guardrail_core::{
    Backend, FsAccess, IpcPolicy, NetworkPolicy, ResourceLimits, SandboxConfig, UserNamespacePolicy,
};
use guardrail_windows::WindowsBackend;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
    GetAce, GetLengthSid, GetSidIdentifierAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    INHERITED_ACE, PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_APPCONTAINER_INFORMATION,
    TOKEN_GROUPS, TOKEN_QUERY, TokenAppContainerSid, TokenRestrictedSids, WELL_KNOWN_SID_TYPE,
    WinBuiltinAnyPackageSid, WinCapabilityInternetClientSid,
};
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::core::PWSTR;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

fn probe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
}

fn probe_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
        .parent()
        .expect("probe binary has a parent directory")
        .to_path_buf()
}

fn spawn_child(config: &SandboxConfig, command: Command) -> guardrail_core::SandboxChild {
    WindowsBackend::new(config.clone())
        .expect("backend")
        .spawn(command)
        .expect("spawn")
}

#[test]
fn default_network_deny_still_launches_process_in_appcontainer() {
    let config = builder_with_system_root();
    let mut command = Command::new("cmd");
    command.args(["/C", "exit", "0"]);
    command.env_clear();
    command.envs(&config.env);

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(status.success(), "cmd /C exit 0 should succeed");
}

#[test]
fn filesystem_read_is_denied_without_grant() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("input.txt");
    fs::write(&file, "guardrail").expect("write input");

    let mut config = builder_with_system_root();
    config.fs.extend([FsAccess::ReadAllow(probe_dir())]);
    let mut command = probe();
    command.arg("read-file").arg(&file);
    command.env_clear();
    command.envs(&config.env);

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "file should not be readable without a declared grant"
    );
}

#[test]
fn read_grant_allows_reading_a_declared_directory() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("input.txt");
    fs::write(&file, "guardrail").expect("write input");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::ReadAllow(temp.path().into()),
    ]);
    let mut command = probe();
    command.arg("read-file").arg(&file);
    command.env_clear();
    command.envs(&config.env);

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(status.success(), "read-granted file should be readable");
}

#[test]
fn write_is_denied_under_read_grant() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("output.txt");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::ReadAllow(temp.path().into()),
    ]);
    let mut command = probe();
    command.arg("write-file").arg(&file);
    command.env_clear();
    command.envs(&config.env);

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "read grant must not allow writing under the directory"
    );
    assert!(
        !file.exists(),
        "read-only grant should not create the output file"
    );
}

#[test]
fn write_grant_allows_writing_under_declared_directory() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("output.txt");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::WriteAllow(temp.path().into()),
    ]);
    let mut command = probe();
    command.arg("write-file").arg(&file);
    command.env_clear();
    command.envs(&config.env);

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "write-granted directory should be writable"
    );
    assert!(file.exists(), "write-granted file should be created");
}

#[test]
fn read_allow_then_read_deny_denies_child_but_allows_sibling() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let public = temp.path().join("public.txt");
    let secret = temp.path().join("secret.txt");
    fs::write(&public, "public").expect("write public");
    fs::write(&secret, "secret").expect("write secret");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::ReadAllow(temp.path().into()),
        FsAccess::ReadDeny(secret.clone()),
    ]);

    assert!(probe_file_allowed(&config, "read-file", &public));
    assert!(!probe_file_allowed(&config, "read-file", &secret));
}

#[test]
fn lpac_removes_all_packages_but_keeps_package_and_capability_allows() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let control = temp.path().join("control.txt");
    let package_grant = temp.path().join("package.txt");
    let all_packages_grant = temp.path().join("all-packages.txt");
    let capability_grant = temp.path().join("capability.txt");
    for file in [
        &control,
        &package_grant,
        &all_packages_grant,
        &capability_grant,
    ] {
        fs::write(file, "guardrail").expect("write test file");
    }

    let mut config = builder_with_system_root();
    config.network = NetworkPolicy::OutboundOnly;
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::ReadAllow(control.clone()),
    ]);
    assert!(
        probe_file_allowed(&config, "read-file", &control),
        "probe control read failed"
    );

    let mut command = probe();
    command
        .args(["delayed-read-file", "5000"])
        .arg(&package_grant);
    command.env_clear();
    command.envs(&config.env);
    let mut package_child = spawn_child(&config, command);
    let package_sid = appcontainer_sid(package_child.id());
    let all_packages_sid = well_known_sid(WinBuiltinAnyPackageSid);
    let capability_sid = well_known_sid(WinCapabilityInternetClientSid);

    install_explicit_read_aces(&package_grant, &[(package_sid.as_psid(), GRANT_ACCESS)]);
    install_explicit_read_aces(
        &all_packages_grant,
        &[(all_packages_sid.as_psid(), GRANT_ACCESS)],
    );
    install_explicit_read_aces(
        &capability_grant,
        &[(capability_sid.as_psid(), GRANT_ACCESS)],
    );
    let package_allowed = package_child.wait().expect("wait").success();
    let all_packages_allowed = probe_file_allowed(&config, "read-file", &all_packages_grant);
    let capability_allowed = probe_file_allowed(&config, "read-file", &capability_grant);

    assert!(
        package_allowed && !all_packages_allowed && capability_allowed,
        "LPAC results: package allow={package_allowed}, \
         ALL APPLICATION PACKAGES allow={all_packages_allowed}, \
         capability allow={capability_allowed}"
    );
}

#[test]
fn filesystem_deny_vetoes_capability_allow() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let capability_grant = temp.path().join("capability.txt");
    fs::write(&capability_grant, "guardrail").expect("write capability file");
    let capability_sid = well_known_sid(WinCapabilityInternetClientSid);
    install_explicit_read_aces(
        &capability_grant,
        &[(capability_sid.as_psid(), GRANT_ACCESS)],
    );

    let mut config = builder_with_system_root();
    config.network = NetworkPolicy::OutboundOnly;
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::ReadDeny(capability_grant.clone()),
    ]);

    assert!(!probe_file_allowed(&config, "read-file", &capability_grant));
}

#[test]
fn read_allow_with_read_deny_keeps_parent_inheritance_for_future_sibling() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let secret = temp.path().join("secret.txt");
    let future = temp.path().join("future.txt");
    fs::write(&secret, "secret").expect("write secret");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::ReadAllow(temp.path().into()),
        FsAccess::ReadDeny(secret.clone()),
    ]);

    let mut command = probe();
    command.args(["delayed-read-file", "750"]).arg(&future);
    command.env_clear();
    command.envs(&config.env);
    let mut child = spawn_child(&config, command);
    fs::write(&future, "future").expect("write future sibling");
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "future sibling should inherit the broad parent read grant"
    );
    assert!(!probe_file_allowed(&config, "read-file", &secret));
}

#[test]
fn future_child_of_denied_directory_inherits_deny() {
    let temp = TempPath::new();
    let denied = temp.path().join("denied");
    fs::create_dir_all(&denied).expect("create denied dir");
    let future = denied.join("future.txt");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::ReadAllow(temp.path().into()),
        FsAccess::ReadDeny(denied),
    ]);
    let mut command = probe();
    command.args(["delayed-read-file", "750"]).arg(&future);
    command.env_clear();
    command.envs(&config.env);
    let mut child = spawn_child(&config, command);
    fs::write(&future, "secret").expect("write future denied child");

    assert!(!child.wait().expect("wait").success());
}

#[test]
fn nested_reallow_is_rejected() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let public = temp.path().join("public.txt");
    fs::write(&public, "public").expect("write public");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadDeny(temp.path().into()),
        FsAccess::ReadAllow(public),
    ]);

    let err = match WindowsBackend::new(config) {
        Ok(_) => panic!("nested re-allow must be rejected"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("cannot re-allow read access"));
    assert!(matches!(
        err,
        guardrail_core::Error::Confinement { stage: "acl", .. }
    ));
}

#[test]
fn dropping_backend_and_child_removes_filesystem_deny_ace() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let secret = temp.path().join("secret.txt");
    let public = temp.path().join("public.txt");
    fs::write(&secret, "secret").expect("write secret");
    fs::write(&public, "public").expect("write public");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::ReadAllow(public.clone()),
        FsAccess::ReadDeny(secret.clone()),
    ]);
    let backend = WindowsBackend::new(config.clone()).expect("backend");
    let mut command = probe();
    command.args(["delayed-read-file", "250"]).arg(&secret);
    command.env_clear();
    command.envs(&config.env);
    let mut child = backend.spawn(command).expect("spawn");
    let package_sid = appcontainer_sid(child.id());
    let filesystem_sid = filesystem_restricting_sid(child.id());

    assert!(dacl_has_explicit_sid(&public, package_sid.as_psid()));
    assert!(dacl_has_explicit_sid(&secret, filesystem_sid.as_psid()));
    assert!(!child.wait().expect("wait").success());
    drop(child);
    drop(backend);
    assert!(!dacl_has_explicit_sid(&public, package_sid.as_psid()));
    assert!(!dacl_has_explicit_sid(&secret, filesystem_sid.as_psid()));
}

#[test]
fn deny_tree_with_junction_is_rejected() {
    let tree = TempPath::new();
    let denied = tree.path().join("denied");
    fs::create_dir_all(&denied).expect("create denied dir");
    let outside = TempPath::new();
    fs::create_dir_all(outside.path()).expect("create junction target");
    let junction = denied.join("junction");
    let linked = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(outside.path())
        .status()
        .expect("run mklink");
    assert!(linked.success(), "create directory junction");

    let mut config = builder_with_system_root();
    config
        .fs
        .extend([FsAccess::ReadAllow(probe_dir()), FsAccess::ReadDeny(denied)]);
    let err = match WindowsBackend::new(config) {
        Ok(_) => panic!("deny tree containing a junction must be rejected"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("reparse point"));
    fs::remove_dir(&junction).expect("remove directory junction");
}

#[test]
fn deny_tree_with_protected_descendant_is_rejected() {
    let temp = TempPath::new();
    let child = temp.path().join("protected.txt");
    fs::create_dir_all(temp.path()).expect("create temp dir");
    fs::write(&child, "protected").expect("write protected child");
    protect_dacl(&child);

    let mut config = builder_with_system_root();
    config.fs.push(FsAccess::ReadDeny(temp.path().into()));
    let err = match WindowsBackend::new(config) {
        Ok(_) => panic!("deny tree containing a protected DACL must be rejected"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("protected DACL"));
}

#[test]
fn deny_tree_with_null_dacl_descendant_is_rejected() {
    let temp = TempPath::new();
    let child = temp.path().join("null-dacl.txt");
    fs::create_dir_all(temp.path()).expect("create temp dir");
    fs::write(&child, "null").expect("write null-DACL child");
    set_null_dacl(&child);

    let mut config = builder_with_system_root();
    config.fs.push(FsAccess::ReadDeny(temp.path().into()));
    let err = match WindowsBackend::new(config) {
        Ok(_) => panic!("deny tree containing a null DACL must be rejected"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("null DACL"));
}

#[test]
fn later_read_allow_overrides_same_path_deny() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let public = temp.path().join("public.txt");
    fs::write(&public, "public").expect("write public");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::ReadAllow(temp.path().into()),
        FsAccess::ReadDeny(temp.path().into()),
        FsAccess::ReadAllow(temp.path().into()),
    ]);

    assert!(probe_file_allowed(&config, "read-file", &public));
}

#[test]
fn later_read_deny_overrides_same_path_allow() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let secret = temp.path().join("secret.txt");
    fs::write(&secret, "secret").expect("write secret");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::ReadAllow(temp.path().into()),
        FsAccess::ReadDeny(temp.path().into()),
    ]);

    assert!(!probe_file_allowed(&config, "read-file", &secret));
}

#[test]
fn write_rule_does_not_grant_read() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let output = temp.path().join("output.txt");
    let secret = temp.path().join("secret.txt");
    fs::write(&secret, "secret").expect("write secret");

    let mut config = builder_with_system_root();
    config.fs.extend([
        FsAccess::ReadAllow(probe_dir()),
        FsAccess::WriteAllow(temp.path().into()),
    ]);

    assert!(probe_file_allowed(&config, "write-file", &output));
    assert!(!probe_file_allowed(&config, "read-file", &secret));
}

#[test]
fn default_network_deny_blocks_outbound_tcp_connect() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local listener");
    let port = listener
        .local_addr()
        .expect("listener address")
        .port()
        .to_string();

    let mut config = builder_with_system_root();
    config.fs.extend([FsAccess::ReadAllow(probe_dir())]);
    config.network = NetworkPolicy::Deny;
    let mut command = probe();
    command.args(["tcp-connect", "127.0.0.1", &port]);
    command.env_clear();
    command.envs(&config.env);

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "default network deny should block outbound TCP connect"
    );
}

#[test]
#[ignore = "requires host AppContainer loopback support for the per-run test profile"]
fn outbound_only_allows_loopback_connect_when_host_allows_appcontainer_loopback() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local listener");
    let port = listener
        .local_addr()
        .expect("listener address")
        .port()
        .to_string();

    let mut config = builder_with_system_root();
    config.fs.extend([FsAccess::ReadAllow(probe_dir())]);
    config.network = NetworkPolicy::OutboundOnly;
    let mut command = probe();
    command.args(["tcp-connect", "127.0.0.1", &port]);
    command.env_clear();
    command.envs(&config.env);

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "outbound-only should allow loopback connect when the host permits AppContainer loopback"
    );
}

#[test]
fn full_network_allows_non_loopback_tcp_bind() {
    let mut config = builder_with_system_root();
    config.fs.extend([FsAccess::ReadAllow(probe_dir())]);
    config.network = NetworkPolicy::Full;
    let mut command = probe();
    command.args(["tcp-bind", "0.0.0.0"]);
    command.env_clear();
    command.envs(&config.env);

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "full network policy should allow a non-loopback TCP bind: {status:?}, code={:#x}",
        status.code().unwrap_or_default() as u32,
    );
}

struct TempPath {
    path: PathBuf,
}

fn builder_with_system_root() -> SandboxConfig {
    let mut env = BTreeMap::new();
    for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    SandboxConfig {
        fs: vec![],
        network: NetworkPolicy::Deny,
        linux_ipc: IpcPolicy::Strict,
        limits: ResourceLimits::default(),
        env,
        darwin_sandbox_profiles: vec![],
        linux_user_namespaces: UserNamespacePolicy::Deny,
        windows_cache_namespace: Some(unique_namespace("policy")),
    }
}

fn probe_file_allowed(config: &SandboxConfig, operation: &str, path: &Path) -> bool {
    let mut command = probe();
    command.arg(operation).arg(path);
    command.env_clear();
    command.envs(&config.env);
    let mut child = spawn_child(config, command);
    child.wait().expect("wait").success()
}

struct OwnedSid {
    storage: Vec<usize>,
}

impl OwnedSid {
    fn with_byte_len(len: u32) -> Self {
        assert_ne!(len, 0, "SID length");
        Self {
            storage: vec![0; (len as usize).div_ceil(mem::size_of::<usize>())],
        }
    }

    fn as_psid(&self) -> PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

struct TestHandle(HANDLE);

impl TestHandle {
    fn new(raw: HANDLE, operation: &str) -> Self {
        assert!(
            !raw.is_null(),
            "{operation}: {}",
            std::io::Error::last_os_error()
        );
        Self(raw)
    }
}

impl Drop for TestHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn appcontainer_sid(pid: u32) -> OwnedSid {
    let process = TestHandle::new(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) },
        "open probe process",
    );
    let mut token = ptr::null_mut();
    let opened = unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) };
    win32_bool(opened, "open probe token");
    let token = TestHandle::new(token, "open probe token");

    let mut info_len = 0;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenAppContainerSid,
            ptr::null_mut(),
            0,
            &mut info_len,
        );
    }
    assert_ne!(info_len, 0, "measure TokenAppContainerSid");
    let mut info_storage = vec![0usize; (info_len as usize).div_ceil(mem::size_of::<usize>())];
    let queried = unsafe {
        GetTokenInformation(
            token.0,
            TokenAppContainerSid,
            info_storage.as_mut_ptr().cast(),
            info_len,
            &mut info_len,
        )
    };
    win32_bool(queried, "query TokenAppContainerSid");
    let info = unsafe {
        &*info_storage
            .as_ptr()
            .cast::<TOKEN_APPCONTAINER_INFORMATION>()
    };
    assert!(
        !info.TokenAppContainer.is_null(),
        "probe is not an AppContainer"
    );

    let sid_len = unsafe { GetLengthSid(info.TokenAppContainer) };
    let sid = OwnedSid::with_byte_len(sid_len);
    let copied = unsafe {
        windows_sys::Win32::Security::CopySid(sid_len, sid.as_psid(), info.TokenAppContainer)
    };
    win32_bool(copied, "copy AppContainer SID");
    sid
}

fn filesystem_restricting_sid(pid: u32) -> OwnedSid {
    let process = TestHandle::new(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) },
        "open probe process",
    );
    let mut token = ptr::null_mut();
    let opened = unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) };
    win32_bool(opened, "open probe token");
    let token = TestHandle::new(token, "open probe token");

    let mut groups_len = 0;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenRestrictedSids,
            ptr::null_mut(),
            0,
            &mut groups_len,
        );
    }
    assert_ne!(groups_len, 0, "measure TokenRestrictedSids");
    let mut groups_storage = vec![0usize; (groups_len as usize).div_ceil(mem::size_of::<usize>())];
    let queried = unsafe {
        GetTokenInformation(
            token.0,
            TokenRestrictedSids,
            groups_storage.as_mut_ptr().cast(),
            groups_len,
            &mut groups_len,
        )
    };
    win32_bool(queried, "query TokenRestrictedSids");
    let groups = unsafe { &*groups_storage.as_ptr().cast::<TOKEN_GROUPS>() };
    let restricted =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    let filesystem_sid = restricted
        .iter()
        .map(|entry| entry.Sid)
        .find(|sid| unsafe {
            let authority = GetSidIdentifierAuthority(*sid);
            let count = GetSidSubAuthorityCount(*sid);
            !authority.is_null() && !count.is_null() && (*authority).Value == [0; 6] && *count == 4
        })
        .expect("filesystem restricting SID");

    let sid_len = unsafe { GetLengthSid(filesystem_sid) };
    let sid = OwnedSid::with_byte_len(sid_len);
    let copied =
        unsafe { windows_sys::Win32::Security::CopySid(sid_len, sid.as_psid(), filesystem_sid) };
    win32_bool(copied, "copy filesystem restricting SID");
    sid
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> OwnedSid {
    let mut len = 0;
    unsafe {
        CreateWellKnownSid(kind, ptr::null_mut(), ptr::null_mut(), &mut len);
    }
    let sid = OwnedSid::with_byte_len(len);
    let created = unsafe { CreateWellKnownSid(kind, ptr::null_mut(), sid.as_psid(), &mut len) };
    win32_bool(created, "create well-known SID");
    sid
}

fn install_explicit_read_aces(path: &Path, entries: &[(PSID, ACCESS_MODE)]) {
    let path_wide = wide_null(path.as_os_str());
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let captured = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    win32_status(captured, "capture test DACL");

    let explicit = entries
        .iter()
        .map(|(sid, mode)| EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_GENERIC_READ,
            grfAccessMode: *mode,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.cast::<u16>() as PWSTR,
            },
        })
        .collect::<Vec<_>>();
    let mut new_acl = ptr::null_mut();
    let built =
        unsafe { SetEntriesInAclW(explicit.len() as u32, explicit.as_ptr(), dacl, &mut new_acl) };
    win32_status(built, "build test DACL");
    let installed = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_acl,
            ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(new_acl.cast::<core::ffi::c_void>() as HLOCAL);
        LocalFree(descriptor.cast::<core::ffi::c_void>() as HLOCAL);
    }
    win32_status(installed, "install test DACL");
}

fn protect_dacl(path: &Path) {
    let path_wide = wide_null(path.as_os_str());
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let captured = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    win32_status(captured, "capture DACL to protect");
    let protected = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(descriptor.cast::<core::ffi::c_void>() as HLOCAL);
    }
    win32_status(protected, "protect DACL");
}

fn set_null_dacl(path: &Path) {
    let path_wide = wide_null(path.as_os_str());
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    win32_status(status, "set null DACL");
}

fn dacl_has_explicit_sid(path: &Path, sid: PSID) -> bool {
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;

    let path_wide = wide_null(path.as_os_str());
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let captured = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    win32_status(captured, "capture DACL");

    let found = if dacl.is_null() {
        false
    } else {
        let count = unsafe { (*dacl).AceCount };
        (0..u32::from(count)).any(|index| {
            let mut ace = ptr::null_mut();
            let got = unsafe { GetAce(dacl, index, &mut ace) };
            win32_bool(got, "get ACE");
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if u32::from(header.AceFlags) & INHERITED_ACE != 0
                || (header.AceType != ACCESS_ALLOWED_ACE_TYPE
                    && header.AceType != ACCESS_DENIED_ACE_TYPE)
            {
                return false;
            }
            let ace_sid = unsafe {
                ptr::addr_of!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
                    .cast_mut()
                    .cast()
            };
            unsafe { EqualSid(ace_sid, sid) != 0 }
        })
    };

    unsafe {
        LocalFree(descriptor.cast::<core::ffi::c_void>() as HLOCAL);
    }
    found
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn win32_bool(ok: i32, operation: &str) {
    assert_ne!(ok, 0, "{operation}: {}", std::io::Error::last_os_error());
}

fn win32_status(status: u32, operation: &str) {
    assert_eq!(
        status,
        ERROR_SUCCESS,
        "{operation}: {}",
        std::io::Error::from_raw_os_error(status as i32)
    );
}

impl TempPath {
    fn new() -> Self {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "guardrail-windows-policy-{}-{counter}",
            std::process::id()
        ));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn unique_namespace(label: &str) -> String {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("guardrail-windows-{label}-{}-{counter}", std::process::id())
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
