/// Kernel kTLS RX-splice support probe, mirroring
/// `tng::config::ktls::kernel_splice_supported` (>= 5.16, parse failure
/// defaults to supported). Duplicated here because the kTLS e2e tests must
/// compile under `--no-default-features` (on-bin/on-podman CI), where the
/// optional `tng` crate dependency is not enabled.
pub fn kernel_splice_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        let release = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok());
        release
            .as_deref()
            .and_then(parse_kernel_version)
            .map(|(major, minor)| (major, minor) >= (5, 16))
            .unwrap_or(true)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let release = release.trim().split('-').next()?;
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}
