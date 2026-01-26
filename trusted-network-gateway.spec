%global debug_package %{nil}

Name: trusted-network-gateway
Version: 2.4.0
Release: 1%{?dist}
Summary: Trusted Network Gateway
Group: Applications/System
License: Apache-2.0
URL: https://www.alibaba.com
Source0: https://github.com/inclavare-containers/tng/releases/download/v%{version}/trusted-network-gateway-%{version}-vendored-source.tar.gz

Requires: curl iptables openssl iproute
Recommends: attestation-agent

BuildRequires: make
BuildRequires: git
BuildRequires: gcc
BuildRequires: pkg-config
BuildRequires: protobuf-devel
BuildRequires: cmake
BuildRequires: wget
BuildRequires: net-tools
BuildRequires: curl
BuildRequires: file
BuildRequires: gnupg
BuildRequires: tree
BuildRequires: libcurl-devel
BuildRequires: libseccomp-devel
BuildRequires: openssl-devel
BuildRequires: binutils-devel
BuildRequires: protobuf-devel
BuildRequires: clang
BuildRequires: jq

%{!?with_rustup:%global use_system_rust 1}
%if 0%{?use_system_rust}
BuildRequires: cargo >= 1.89.0
BuildRequires: rust >= 1.89.0
%endif


ExclusiveArch: x86_64


%description
A tool for establishing secure communication tunnels in confidential computing.


%prep
%setup -q -n %{name}-%{version}


%build
# Build tng
pushd src/
RUSTFLAGS="--cfg tokio_unstable" cargo install --locked --path ./tng/ --root %{_builddir}/%{name}-%{version}/install/tng/
popd


%install
# Install tng
mkdir -p %{buildroot}/usr/bin/
install -p -m 755 %{_builddir}/%{name}-%{version}/install/tng/bin/tng %{buildroot}/usr/bin/tng
mkdir -p %{buildroot}/etc/tng/
install -p -m 755 src/dist/config.json %{buildroot}/etc/tng/config.json
mkdir -p %{buildroot}/usr/lib/systemd/system/
install -p -m 755 src/dist/trusted-network-gateway.service %{buildroot}/usr/lib/systemd/system/trusted-network-gateway.service

%define __requires_exclude librats_rs.so

%files
%license src/LICENSE
/usr/bin/tng
/usr/lib/systemd/system/trusted-network-gateway.service
%dir /etc/tng/
/etc/tng/config.json


%changelog
* Mon Jan 26 2026 Kun Lai <laikun@linux.alibaba.com> - 2.4.0-1
- ohttp: add configurable key management with self-generated default keys and file-based HPKE key loading with auto-reload
- ohttp: support key lookup by SHA-256 hash and hostname-based peer_shared cluster connections
- ohttp: implement serf-based distributed key sharing over Rats-TLS with graceful cluster exit and key broadcasting on node join
- ohttp: trigger key config refresh when server rejects request due to missing key and improve key expiration logic and debugging identifiers
- serf: support multiple addresses per hostname in cluster join
- tng: enable colored CLI output automatically when running in a TTY
- logging: fix missing span in serf logs and remove unnecessary fields from structured log output
- ra: support EAR format tokens from trustee and fetching AS certificate for token verification with custom attestation service headers
- build: upgrade minimal Rust version to 1.89.0, adjust source tarball naming (-vendored-source suffix), and rename release artifacts and SLSA provenance
- build: allow uploading Docker image without waiting for tests and add GitHub Actions workflow for cargo fmt checking
- tests: stabilize OHTTP and egress key rotation tests, fix flaky WASM browser test, and adjust test suite tooling and options
- shell: fix iptables typo in ShellTask and move OHTTP test keys out of /tmp to avoid unintended file watching
- spec: fix incorrect source download URL in RPM spec file
- misc: rename maybe_cached variants and refactor OHTTP security module and internal protocol forwarding abstractions for clarity


* Wed Nov  5 2025 Kun Lai <laikun@linux.alibaba.com> - 2.3.0-1
- Fix TDX attestation failure: use canonical JSON serialization to ensure REPORT_DATA hash consistency in rats-cert
- Enable TCP keepalive (10s idle, 10s interval, 3 probes) for OHTTP tunnel connections to improve connection stability
- Set TCP_NODELAY on all TCP listeners to reduce latency for real-time services
- Add support for clients using "no_ra" when server requires attestation — returns key config with `attestation_info: None` instead of rejecting
- Cache OHTTP passport attestation responses within refresh interval to reduce AS load and improve performance
- Enable gzip/brotli/zstd compression for OHTTP responses (except ohttp-chunked-res) to reduce bandwidth usage
- Log OHTTP forwarding errors to stdout for improved operational visibility


* Mon Sep 29 2025 Kun Lai <laikun@linux.alibaba.com> - 2.2.6-1
- Standardize error handling with machine-readable codes and precise HTTP status mapping
- Honor AS token JWT exp and certificate validity in credential caching TTL calculation
- Migrate OHTTP routing from path-based to header-driven using x-tng-ohttp-api
- Use full URL as OHttpClient cache key for per-path service isolation
- Introduce test load balancer with path rewriting for integration testing
- Unify middleware order in OHTTP server for consistent processing


* Wed Sep 17 2025 Kun Lai <laikun@linux.alibaba.com> - 2.2.5-1
- Update to version v2.2.5
- ohttp: Refactor code structure and rename encap/decap functions to use ohttp prefix
- ohttp: Introduce ohttp server and partial protocol support on egress side
- ohttp: Add support for client-side and server-side attestation (background check and passport models)
- ohttp: Handle HPKE expire_timestamp and attest.refresh_interval configuration
- ohttp: Add Content-Type and User-Agent headers in ohttp requests/responses
- ohttp: Add CORS configuration for egress
- ohttp: Fix socket mark handling in netfilter ingress type
- tng-wasm: Migrate from rats-tls to ohttp protocol; update Chinese documentation
- tng-wasm: Add build/run example documentation
- ra: Add support for passport model and attestation API in trustee 1.6.0
- rats-rs: Use async verifier; deserialize and flatten tcb-status from coco as token
- rats-rs: Move from git submodule to Cargo dependency
- wasm: Support building as WASM module; align fetch() behavior with web standard
- ingress: Remove unused forward_http_request(); fix incorrect to_trusted_tunnel log value
- runtime: Merge tokio runtime with shutdown guard
- testsuite: Fix test filtering issues; ignore tng-wasm test coverage in report
- build: Add GitHub workflow for TNG SDK; fix npm package publishing in CI
- build: Add mac-cross-build target in Makefile
- deps: Unify crate versions across workspace
- cert_verifier: Remove unnecessary spawn_blocking() call
- run-test.sh: Adjust script to skip tng-wasm test reports
- Fix netlink warning on newer kernels in testing environment


* Thu Jul  3 2025 Kun Lai <laikun@linux.alibaba.com> - 2.2.4-1
- ingress/socks5: add dst_filters option for filtering destination domains
- egress: add direct_forward option to allow traffic forwarded directly


* Tue Jun 24 2025 Kun Lai <laikun@linux.alibaba.com> - 2.2.3-1
- ingress/netfilter: add matching dst ip address with ip rannge or ipset
- optimize network throughput
- cli: add --tokio-console option
- egress/transport: add timeout for waiting client tcp connection
- iptables: fix capturing traffics target to docker -p mapping port
- ingress/socks5: add "socks5" ingress type which expose a socks5 server to client


* Tue Jun 17 2025 Kun Lai <laikun@linux.alibaba.com> - 2.2.2-1
- egress/netfilter: Fix tng traffic not captured when tng client server run on same node.
- egress/netfilter: Fix behavior when capture_cgroup is empty and add check for cgroup v2.
- ingress/http_proxy: fix error when both domain and domain_regex are not set


* Thu May 15 2025 Kun Lai <laikun@linux.alibaba.com> - 2.2.1-1
- Fix broken trusted-network-gateway.service


* Tue May 13 2025 Kun Lai <laikun@linux.alibaba.com> - 2.2.0-1
- Add new ingress type "netfilter" with cgroup match support.
- Add systemd service file.
- Fix error when io stream is closed by peer in egress.
- Fix connection refused caused by wrong listen address in netfilter mode egress.
- Fix missing authority header when forwarding http request in http_proxy mode ingress.
- Fix path_rewrites feature.
- Fix decap_from_http.allow_non_tng_traffic_regexes feature.


* Tue Apr 29 2025 Kun Lai <laikun@linux.alibaba.com> - 2.1.0-1
- Fixed the issue of using incorrect spans in some async tasks during request handling.
- Add traces exporter (otlp, stdout) for traces reporting.
- Add the "refresh_interval" field in the configuration to control the evidence caching strategy.
- Add a RESTful control interface ("/readyz", "/livez") to check the status of tng instances.
- Add metrics exporter (otlp, falcon, stdout) for metrics reporting.
- Fix the behavior of the "domain" field in "ingress/http_proxy" and added the "domain_regex" field.


* Thu Mar 20 2025 Kun Lai <laikun@linux.alibaba.com> - 1.0.6
- Add control interface with RESTful API for checking status of tng instances
- Add metric exporter (open-falcon, stdout) for metrics reporting
- Update rats-rs to handle "jwk" field in JWT header, so that tng can be used with CoCo Trustee
- Some improvements on artifacts building and testing workflow

* Mon Mar 3 2025 Kun Lai <laikun@linux.alibaba.com> - 1.0.5
- Extend aa timeout to 2 minutes
- Add trusted_certs_paths to verify field in config file

* Mon Feb 24 2025 Kun Lai <laikun@linux.alibaba.com> - 2.0.0-1
- Rewrite all in rust

* Mon Feb 24 2025 Kun Lai <laikun@linux.alibaba.com> - 1.0.4
- Nothing but some adjust on build script

* Wed Jan 22 2025 Kun Lai <laikun@linux.alibaba.com> - 1.0.3-2
- Rename package name from tng to trusted-network-gateway.

* Tue Dec 17 2024 Kun Lai <laikun@linux.alibaba.com> - 1.0.3-1
- Initial package release.
