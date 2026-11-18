//! Operating-system abstraction: Linux, macOS and Windows.
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

pub const OS: &str = std::env::consts::OS;

/// Per-user data directory: `%APPDATA%\nightwatch` (Windows),
/// `$XDG_DATA_HOME|~/.local/share/nightwatch` (Linux), `~/Library/Application Support/nightwatch` (macOS).
pub fn data_dir() -> PathBuf {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(windows) {
        env("APPDATA").or_else(|| env("USERPROFILE"))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library").join("Application Support"))
    } else {
        env("XDG_DATA_HOME").or_else(|| env("HOME").map(|h| h.join(".local").join("share")))
    };
    base.unwrap_or_else(|| PathBuf::from("."))
        .join("nightwatch")
}

pub fn default_key_path() -> PathBuf {
    data_dir().join("report.key")
}

/// Restrict a secret file to the current user. Unix: chmod 0600.
/// Windows: files under %APPDATA% inherit a per-user ACL; we mark it read-only and
/// do not claim more than that.
pub fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let mut p = std::fs::metadata(path)?.permissions();
        p.set_readonly(true);
        std::fs::set_permissions(path, p)?;
    }
    Ok(())
}

/// Write a new secret file; refuses to overwrite.
pub fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    if path.exists() {
        bail!(
            "{} already exists; refusing to overwrite a key",
            path.display()
        );
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
    }
    restrict_file(path)
}

/// OS entropy: /dev/urandom on Unix, RtlGenRandom (SystemFunction036) on Windows.
pub fn os_random(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    #[cfg(unix)]
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    }
    #[cfg(windows)]
    {
        #[link(name = "advapi32")]
        extern "system" {
            #[link_name = "SystemFunction036"]
            fn RtlGenRandom(buf: *mut u8, len: u32) -> u8;
        }
        if unsafe { RtlGenRandom(buf.as_mut_ptr(), n as u32) } == 0 {
            bail!("RtlGenRandom failed");
        }
    }
    Ok(buf)
}

/// Names of capture interfaces visible without privileges (Linux: /sys/class/net).
/// Windows/macOS need a capture driver (Npcap / BPF); not bundled, so empty there.
pub fn list_interfaces() -> Vec<String> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        for e in rd.flatten() {
            v.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    v.sort();
    v
}
