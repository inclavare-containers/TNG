//! Three-tier kTLS policy shared by ingress and egress `rats_tls.ktls`.
//!
//! - `"disabled"` — never engage kTLS; use the rustls data plane.
//! - `"best-effort"` (the default) — engage kTLS where the link allows it
//!   (non-multiplexed, on Linux with kernel kTLS support), and transparently
//!   fall back to rustls when the negotiated cipher is not in the kernel's
//!   kTLS support set.
//! - `"required"` — like best-effort, but fail the setup instead of falling
//!   back when the link cannot use kTLS (a multiplexed link, or an
//!   infeasible cipher at handshake time).

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// The per-link kTLS policy tier, deserialized from `rats_tls.ktls`. See the
/// module-level docs for the semantics of each tier; [`Ktls::resolve`] folds in
/// the link constraints and may downgrade `best-effort` to `disabled`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ktls {
    /// Never engage kTLS; always use the rustls data plane.
    Disabled,
    #[default]
    /// Engage kTLS where the link allows it, transparently falling back to
    /// rustls otherwise.
    BestEffort,
    /// Like `best-effort`, but fail the setup instead of falling back when the
    /// link cannot use kTLS.
    Required,
}

/// Config & environment-level reasons kTLS cannot be used, evaluated once at
/// setup against [`KtlsEnvConstraints`]. These are static link/platform/kernel
/// facts known before any handshake; they never include the "stream consumed"
/// case, so `best-effort` can always fall back to rustls here.
#[derive(Debug, thiserror::Error)]
pub enum KtlsEnvUnavailable {
    #[error(
        "kTLS is incompatible with H2 multiplexing (splice far end is demux logic, not a socket)"
    )]
    MultiplexedLink,
    #[error("kTLS is only supported on Linux (running on {os})")]
    NonLinuxPlatform { os: &'static str },
    #[error("kernel kTLS RX splice is broken on {kernel_version} (needs >= v5.16)")]
    KernelSpliceUnsupported { kernel_version: String },
}

/// Per-connection reasons kTLS cannot be used. Some are evaluated at dispatch
/// time (before any handshake), the rest after the rustls handshake but before
/// kTLS is installed. In every case a `best-effort`/`disabled` link can still
/// fall back to the rustls data plane; only `required` bails (see
/// [`EnvCheckedKtls::on_connection_unavailable`]). A failure *during*
/// `config_ktls_*` install is different — the stream is already consumed
/// there, so it is surfaced as a hard error regardless of the policy tier.
#[derive(Debug, thiserror::Error)]
pub enum KtlsConnUnavailable {
    /// The downstream is an erased trait object, not a raw socket — kTLS
    /// installs on a raw fd, so it is impossible here. Evaluated at dispatch
    /// time (before any handshake); the rustls path is the fallback.
    #[error("kTLS impossible: downstream is an opaque (non-raw) stream, no socket to install the ULP on")]
    OpaqueDownstream,
    #[error("kTLS ({side}): negotiated cipher {suite} is not in the kernel kTLS support set")]
    InfeasibleCipher { side: Side, suite: String },
    #[error("kTLS ({side}): no cipher negotiated, cannot probe kernel kTLS support")]
    NoCipherNegotiated { side: Side },
}

/// Which end of the rats_tls link this decision applies to, used in log/error
/// messages (kTLS is installed per-side via `config_ktls_client`/`_server`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}
impl std::fmt::Display for Side {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client => write!(f, "client"),
            Self::Server => write!(f, "server"),
        }
    }
}

/// The outcome of [`EnvCheckedKtls::on_connection_unavailable`]: either fall
/// back to the rustls data plane, or bail the setup entirely.
#[derive(Debug)]
pub enum FallbackDecision {
    /// Drop kTLS and use the standard rustls data plane; traffic still flows.
    FallBack,
    /// Abort the setup — surface the wrapped `KtlsConnUnavailable` as an error.
    Bail(anyhow::Error),
}

/// The kTLS policy tier *after* [`Ktls::resolve`] has folded in the config &
/// environment constraints ([`KtlsEnvConstraints`]). Flat, same three variants
/// as [`Ktls`]: a `best-effort` tier that was statically infeasible collapses to
/// `Disabled`, so "is kTLS actually engaged here?" is just `self != Disabled`
/// (see [`Self::engages`]). The raw [`Ktls`] config tier is only used at resolve
/// time and to deserialize `rats_tls.ktls`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvCheckedKtls {
    /// kTLS not engaged — user configured `disabled`, or `best-effort` fell
    /// back after the env check. Use the rustls data plane.
    Disabled,
    /// Engage kTLS where the per-connection handshake allows it, transparently
    /// falling back to rustls otherwise.
    BestEffort,
    /// Like `best-effort`, but fail the connection instead of falling back when
    /// kTLS is unavailable at handshake time.
    Required,
}

/// Static, link-level facts that determine whether kTLS is usable at all,
/// independent of per-connection handshake facts like the negotiated cipher.
/// Built once via [`KtlsEnvConstraints::link`];
/// [`KtlsEnvConstraints::unavailable_reason`] returns the first reason (if any)
/// that disqualifies kTLS, evaluated in priority order.
#[derive(Debug, Clone, Copy, Default)]
pub struct KtlsEnvConstraints {
    /// `true` if the link multiplexes many streams over H2 CONNECT — kTLS
    /// needs a single raw socket at the splice far end, so multiplexing
    /// disqualifies it.
    pub multiplex: bool,
    /// `true` iff running on Linux (kTLS is Linux-only).
    pub platform_linux: bool,
    /// `true` iff this kernel's kTLS RX-splice path is not broken (>= v5.16).
    pub kernel_splice_ok: bool,
}

impl Ktls {
    /// Resolve this tier against the config & environment constraints. If kTLS
    /// is statically infeasible, apply the policy: `required` bails (the setup
    /// fails), `best-effort` falls back to `Ok(EnvCheckedKtls::Disabled)` with
    /// an info log, `disabled` passes through silently. If feasible, return the
    /// tier unchanged (mapped variant-for-variant) for per-connection
    /// handshake-time probing. These env-level reasons all precede the
    /// handshake, so `best-effort` can always fall back here.
    pub fn resolve(self, ctx: &KtlsEnvConstraints) -> Result<EnvCheckedKtls> {
        if let Some(reason) = ctx.unavailable_reason() {
            match self {
                Ktls::Required => {
                    tracing::error!(?reason, "kTLS required but unavailable; bailing setup");
                    return Err(reason.into());
                }
                Ktls::Disabled => return Ok(EnvCheckedKtls::Disabled),
                Ktls::BestEffort => {
                    tracing::info!(
                        ?reason,
                        "kTLS unavailable; falling back to rustls (best-effort)"
                    );
                    return Ok(EnvCheckedKtls::Disabled);
                }
            }
        }
        Ok(match self {
            Ktls::Disabled => EnvCheckedKtls::Disabled,
            Ktls::BestEffort => EnvCheckedKtls::BestEffort,
            Ktls::Required => EnvCheckedKtls::Required,
        })
    }
}

impl EnvCheckedKtls {
    /// Whether kTLS is actually engaged here — `Disabled` (whether configured or
    /// fallen-back) is not; `BestEffort`/`Required` are.
    pub fn engages(self) -> bool {
        self != EnvCheckedKtls::Disabled
    }

    /// Apply this effective tier to a per-connection `KtlsConnUnavailable`
    /// reason: `Required` bails, `BestEffort`/`Disabled` fall back to rustls.
    pub fn on_connection_unavailable(self, reason: KtlsConnUnavailable) -> FallbackDecision {
        match self {
            EnvCheckedKtls::Required => {
                tracing::error!(?reason, "kTLS required but unavailable; bailing setup");
                FallbackDecision::Bail(reason.into())
            }
            EnvCheckedKtls::BestEffort => {
                tracing::info!(
                    ?reason,
                    "kTLS unavailable; falling back to rustls (best-effort)"
                );
                FallbackDecision::FallBack
            }
            EnvCheckedKtls::Disabled => FallbackDecision::FallBack,
        }
    }
}

impl KtlsEnvConstraints {
    /// Build the constraints for a link, probing the running kernel for kTLS
    /// RX-splice support. `multiplex` describes the link type; the platform
    /// and kernel facts are filled in from `cfg!` and `uname(2)`.
    pub fn link(multiplex: bool) -> Self {
        Self {
            multiplex,
            platform_linux: cfg!(target_os = "linux"),
            kernel_splice_ok: kernel_splice_supported(), // uname(2) >=5.16 RX-splice gate; see super::kernel_splice_supported
        }
    }
    /// The first (highest-priority) static reason kTLS cannot be used on this
    /// link, or `None` if the link is eligible and per-connection probing may
    /// proceed. Order: multiplex > non-Linux > broken kernel splice.
    pub fn unavailable_reason(&self) -> Option<KtlsEnvUnavailable> {
        if self.multiplex {
            return Some(KtlsEnvUnavailable::MultiplexedLink);
        }
        if !self.platform_linux {
            return Some(KtlsEnvUnavailable::NonLinuxPlatform {
                os: std::env::consts::OS,
            });
        }
        if !self.kernel_splice_ok {
            return Some(KtlsEnvUnavailable::KernelSpliceUnsupported {
                kernel_version: kernel_version().unwrap_or_default(),
            });
        }
        None
    }
}

/// Parse `major.minor` out of a kernel release string, ignoring any `-suffix`.
/// Generic detection — no distro-name special-casing (Anolis/cloud kernels etc.).
pub(crate) fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let release = release.split('-').next()?;
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Whether `(major, minor)` is >= 5.16 (the `tls_sw_splice_read` fix
/// `e062fe99cccd`, never backported to 5.10.y).
pub(crate) fn splice_supported_for(version: (u32, u32)) -> bool {
    version >= (5, 16)
}

/// Kernel kTLS RX-splice support. True iff this kernel's kTLS RX splice path is
/// not broken (>= v5.16). `uname(2)` is consulted at runtime; a parse failure
/// defaults to `true` to preserve current behavior (do not silently disable
/// kTLS on an unfamiliar kernel).
pub fn kernel_splice_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        let release = nix::sys::utsname::uname()
            .ok()
            .map(|u| u.release().to_string_lossy().into_owned());
        release
            .as_deref()
            .and_then(parse_kernel_version)
            .map(splice_supported_for)
            .unwrap_or(true)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Best-effort kernel version string for logs.
pub(crate) fn kernel_version() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        nix::sys::utsname::uname()
            .ok()
            .map(|u| u.release().to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(multiplex: bool) -> KtlsEnvConstraints {
        // Bypass the real uname probe in tests by constructing directly.
        KtlsEnvConstraints {
            multiplex,
            platform_linux: true,
            kernel_splice_ok: true,
        }
    }

    fn infeasible() -> KtlsConnUnavailable {
        KtlsConnUnavailable::NoCipherNegotiated { side: Side::Server }
    }

    fn de(s: &str) -> Ktls {
        serde_json::from_str(s).unwrap()
    }

    fn checked(k: Ktls) -> EnvCheckedKtls {
        match k {
            Ktls::Disabled => EnvCheckedKtls::Disabled,
            Ktls::BestEffort => EnvCheckedKtls::BestEffort,
            Ktls::Required => EnvCheckedKtls::Required,
        }
    }

    #[test]
    fn parses_strings() {
        assert_eq!(de("\"best-effort\""), Ktls::BestEffort);
        assert_eq!(de("\"disabled\""), Ktls::Disabled);
        assert_eq!(de("\"required\""), Ktls::Required);
    }

    #[test]
    fn rejects_bool() {
        // A bare boolean is no longer accepted — only the kebab-case policy
        // strings parse.
        assert!(serde_json::from_str::<Ktls>("true").is_err());
        assert!(serde_json::from_str::<Ktls>("false").is_err());
    }

    #[test]
    fn default_is_best_effort() {
        assert_eq!(Ktls::default(), Ktls::BestEffort);
    }

    #[test]
    fn serializes_kebab() {
        assert_eq!(
            serde_json::to_string(&Ktls::BestEffort).unwrap(),
            "\"best-effort\""
        );
        assert_eq!(
            serde_json::to_string(&Ktls::Disabled).unwrap(),
            "\"disabled\""
        );
        assert_eq!(
            serde_json::to_string(&Ktls::Required).unwrap(),
            "\"required\""
        );
    }

    #[test]
    fn resolves_passthrough_on_plain_link() {
        for k in [Ktls::Disabled, Ktls::BestEffort, Ktls::Required] {
            assert_eq!(k.resolve(&link(false)).unwrap(), checked(k));
        }
    }

    #[test]
    fn resolves_best_effort_downgrades_on_incompatible_link() {
        assert_eq!(
            Ktls::Disabled.resolve(&link(true)).unwrap(),
            EnvCheckedKtls::Disabled
        );
    }

    #[test]
    fn resolves_required_fails_on_incompatible_link() {
        assert!(Ktls::Required.resolve(&link(true)).is_err());
    }

    #[test]
    fn resolves_kernel_splice_unsupported_downgrades_or_fails() {
        let ctx = KtlsEnvConstraints {
            multiplex: false,
            platform_linux: true,
            kernel_splice_ok: false,
        };
        assert_eq!(
            Ktls::BestEffort.resolve(&ctx).unwrap(),
            EnvCheckedKtls::Disabled
        );
        assert!(Ktls::Required.resolve(&ctx).is_err());
        assert_eq!(
            Ktls::Disabled.resolve(&ctx).unwrap(),
            EnvCheckedKtls::Disabled
        );
    }

    #[test]
    fn resolves_non_linux_downgrades_or_fails() {
        let ctx = KtlsEnvConstraints {
            multiplex: false,
            platform_linux: false,
            kernel_splice_ok: true,
        };
        assert_eq!(
            Ktls::BestEffort.resolve(&ctx).unwrap(),
            EnvCheckedKtls::Disabled
        );
        assert!(Ktls::Required.resolve(&ctx).is_err());
    }

    #[test]
    fn on_connection_unavailable_required_bails_best_effort_falls_back() {
        assert!(matches!(
            Ktls::Required
                .resolve(&link(false))
                .unwrap()
                .on_connection_unavailable(infeasible()),
            FallbackDecision::Bail(_)
        ));
        assert!(matches!(
            Ktls::BestEffort
                .resolve(&link(false))
                .unwrap()
                .on_connection_unavailable(infeasible()),
            FallbackDecision::FallBack
        ));
        assert!(matches!(
            Ktls::Disabled
                .resolve(&link(false))
                .unwrap()
                .on_connection_unavailable(infeasible()),
            FallbackDecision::FallBack
        ));
    }

    #[test]
    fn on_connection_unavailable_opaque_downstream_required_bails() {
        // An opaque downstream has no raw socket, so kTLS is impossible —
        // `required` bails, the fall-back tiers route it to the rustls plane.
        assert!(matches!(
            Ktls::Required
                .resolve(&link(false))
                .unwrap()
                .on_connection_unavailable(KtlsConnUnavailable::OpaqueDownstream),
            FallbackDecision::Bail(_)
        ));
        assert!(matches!(
            Ktls::BestEffort
                .resolve(&link(false))
                .unwrap()
                .on_connection_unavailable(KtlsConnUnavailable::OpaqueDownstream),
            FallbackDecision::FallBack
        ));
        assert!(matches!(
            Ktls::Disabled
                .resolve(&link(false))
                .unwrap()
                .on_connection_unavailable(KtlsConnUnavailable::OpaqueDownstream),
            FallbackDecision::FallBack
        ));
    }

    #[test]
    fn engages_reflects_resolved_tier() {
        assert!(!Ktls::Disabled.resolve(&link(false)).unwrap().engages());
        assert!(Ktls::BestEffort.resolve(&link(false)).unwrap().engages());
        assert!(Ktls::Required.resolve(&link(false)).unwrap().engages());
        // best-effort on an incompatible link resolves to disabled -> not engaged
        let resolved = Ktls::BestEffort.resolve(&link(true)).unwrap();
        assert!(!resolved.engages());
    }

    #[test]
    fn parses_linux_version_suffixes() {
        // generic detection: take major.minor, ignore distro suffixes
        assert_eq!(
            parse_kernel_version("5.10.134-19.1.al8.x86_64"),
            Some((5, 10))
        );
        assert_eq!(parse_kernel_version("5.16.0"), Some((5, 16)));
        assert_eq!(parse_kernel_version("6.6.10-5.anolis"), Some((6, 6)));
        assert_eq!(parse_kernel_version("4.19.0"), Some((4, 19)));
    }

    #[test]
    fn splice_supported_at_or_above_5_16() {
        assert!(!splice_supported_for((5, 10)));
        assert!(!splice_supported_for((5, 15)));
        assert!(splice_supported_for((5, 16)));
        assert!(splice_supported_for((6, 6)));
    }

    #[test]
    fn unparseable_returns_none() {
        assert_eq!(parse_kernel_version("not-a-version"), None);
    }
}
