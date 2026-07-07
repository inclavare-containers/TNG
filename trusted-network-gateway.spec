%global debug_package %{nil}

Name: trusted-network-gateway
Version: 2.7.1
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
# Build libtng_hook.so (LD_PRELOAD hook for transparent TNG tunneling)
cargo build -p tng-hook-cdylib --release
popd


%install
# Install tng
mkdir -p %{buildroot}/usr/bin/
install -p -m 755 %{_builddir}/%{name}-%{version}/install/tng/bin/tng %{buildroot}/usr/bin/tng
mkdir -p %{buildroot}/etc/tng/
install -p -m 755 src/dist/config.json %{buildroot}/etc/tng/config.json
mkdir -p %{buildroot}/usr/lib/systemd/system/
install -p -m 755 src/dist/trusted-network-gateway.service %{buildroot}/usr/lib/systemd/system/trusted-network-gateway.service

# Install libtng_hook.so (LD_PRELOAD hook for transparent TNG tunneling)
# Built from src/ directory in %build, so target is under src/target/
mkdir -p %{buildroot}/usr/lib/tng/
install -p -m 755 %{_builddir}/%{name}-%{version}/src/target/release/libtng_hook.so %{buildroot}/usr/lib/tng/libtng_hook.so

%define __requires_exclude librats_rs.so

%files
%license src/LICENSE
/usr/bin/tng
/usr/lib/systemd/system/trusted-network-gateway.service
/usr/lib/tng/libtng_hook.so
%dir /etc/tng/
/etc/tng/config.json


%changelog
* Tue Jul 07 2026 Kun Lai <laikun@linux.alibaba.com> - 2.7.1-1
- fix(python-sdk): populate PyPI project description via static readme
- fix(tng): drop incorrect Debug assertions from endpoint test
- fix(ci): upload standalone tng.exe for windows-gnu cross-build

* Tue Jul 07 2026 Kun Lai <laikun@linux.alibaba.com> - 2.7.0-1
- build: bump Python SDK version alongside Rust in make bump-version
- refactor: clarify IP/CIDR/Domain types and add IP/CIDR endpoint filtering
- docs: add Go Reference badge to README
- fix(go-sdk): replace LICENSE symlink with actual Apache 2.0 license file
- fix(python-sdk): fix hatchling build hook for newer hatchling versions
- fix(go-sdk): correct module path to match directory structure
- fix: remove egress-only OHTTP key config from client-side Python SDK docs
- fix: address code review feedback
- docs: add npm/PyPI badges, fix SDK install commands, clean up Python docs
- docs(python-sdk): clean up README, add PyPI link-fix build hook
- docs: update SDK install instructions across all documentation
- docs: update SDK install instructions across all documentation
- ci: remove obsolete 'native' branch trigger from all workflows
- ci: switch to trusted publishing for npm and PyPI, add workflow_dispatch
- ci: add npmjs.com and PyPI publishing workflows, update README quick start
- refactor(rats-cert): simplify CoCo token verifier error chain
- ci: bump upload/download-artifact to v7 for Node.js 24 support
- ci: unify artifact packaging — combine tng and libtng_hook.so with system path layout
- docs(python-sdk): add docstrings, context manager support, and rats-tls server examples
- docs(python-sdk): add rats_tls encryption protocol examples to README
- fix(testsuite): increase veth pair name entropy from 2 to 5 random chars
- docs: add capture_local_traffic field to ingress/egress hook configuration docs
- fix(test): fix egress_hook fmt and ingress_hook_capture_local_traffic_true config
- fix(hook): require local peer to skip encryption with capture_local_traffic=false
- test(hook): add capture_local_traffic=true integration test on client loopback
- test(hook): simplify ingress capture_local_traffic test to client-only loopback
- test(hook): add integration tests for capture_local_traffic default behavior
- fix(tunnel): add with_context() to TcpListener::bind for clearer bind errors
- chore: update Cargo.lock with local-ip-address dependencies
- fix(capture_local_traffic): use is_loopback() for full 127.0.0.0/8 coverage, fix stale comment
- feat(egress): add local IP check to HookEgress encrypted()
- feat(hook): add local IP check to ingress hook find_proxy_port()
- refactor(hook): rename IngressHookProxy to IngressInstance, add capture_local_traffic
- feat(config): add capture_local_traffic field to ingress/egress hook args
- fix(go-sdk): install iptables in CI container for tng-testsuite
- feat(tng-testsuite): check TNG_BINARY env var in binary_locator
- fix(go-sdk): gofmt client.go
- fix(go-sdk): resolve remaining golangci-lint issues
- fix(go-sdk): fix fmt.Fprint returns 2 values not 1
- fix(go-sdk): fix all errcheck lint violations
- fix(go-sdk): disable Go VCS stamping for golangci-lint in container
- fix(go-sdk): remove deprecated check-shadowing from golangci-lint config
- fix(go-sdk): downgrade golangci-lint-action to v6 for v1 support
- fix(go-sdk): revert golangci-lint to v1.64 to match existing config format
- fix(go-sdk): correct golangci-lint v2 config schema
- ci(go-sdk): fix golangci-lint v2 config and TNG_BINARY for unit tests
- ci(go-sdk): merge unit and integration tests into single job
- refactor(go-sdk): remove redundant NoRA RoundTrip integration test
- test(go-sdk): enable ohttp in go_sdk_attestation_info integration test
- feat(go-sdk): expose RatsTls in Config for encryption mode selection
- feat(go-sdk): add tng-testsuite integration tests for Go SDK client
- fix(go-sdk): address code review feedback — error wrapping, cleanup, validation, context key
- feat(go-sdk): add Go SDK with subprocess http_proxy architecture
- feat(udp): add UDP mapping ingress/egress with QUIC datagram tunnel
- fix(tng-testsuite): fix hook integration tests for server IP and NodeType
- fix(tng-testsuite): defer token.cancel() to run after select arm body
- chore: update Cargo.lock with new dependencies (local-ip-address, neli, derive_builder, getset)
- refactor(tng): simplify encrypted() with explicit host_match / ifname_match variables
- fix(tng): add startup warning for missing ifname, fix misleading test comment
- docs: update egress hook config docs for IP+ifname filtering
- fix(tng): use idiomatic map for resolved_ifname_ips in HookEgress::new
- docs(tng): update egress flow comments from CIDR to IP/ifname terminology
- refactor(tng): rewrite HookEgress with IP+ifname filtering, resolve at startup
- refactor(tng): update exec.rs for new TngEgressHookMappingEntry fields
- refactor(tng): remove EgressHookHostFilterRule export
- refactor(tng): replace CIDR with exact IP + ifname in egress_hook config
- fixup: place local-ip-address in correct alphabetical order (between itertools and nix)
- chore(tng): add local-ip-address dependency for interface IP resolution
- fix(tng-hook): downgrade non-IPv4 socket log from warn to debug
- fix(tng): make exec.rs and tracing-appender compile for non-Unix targets
- fix(testsuite): add missing NodeType argument to connect_reject_null_ip test
- chore(deps): add tracing-appender and symlink to Cargo.lock
- docs: add --log-file option documentation
- feat(hook): support TNG_HOOK_LOG_FILE for file logging
- feat(exec): pass TNG_HOOK_LOG_FILE env to child process
- feat(tng): wire --log-file to tracing subscriber
- feat(cli): add --log-file global option
- build: add tracing-appender dependency
- fix(tng): propagate signal exit codes in tng exec
- refactor(tng): make forward_stream errors independent per direction, add data-loss logging
- feat(tng-hook): add sendto hook for TCP Fast Open handling
- feat(tng-hook): add sendto hook for TCP Fast Open handling
- test(hook): add integration test for 0.0.0.0 connect rejection
- feat(tng-hook): reject connections to 0.0.0.0 in connect hook
- fix(tng-hook): fall back to original connect when fcntl fails
- refactor(tng-hook): force blocking mode before connect, remove EINPROGRESS branch
- refactor(tng-hook): split defer blocks for flags and timeout separately
- fix(tng-hook): add SO_TYPE check to avoid hijacking non-TCP sockets
- fix(tng-hook): handle EINPROGRESS for non-blocking sockets in connect hook
- feat(tng): egress hook host filtering at accept time with refactoring
- docs(tng): add comment explaining local_addr() forwarding in hook egress
- fix(tng): centralize port allocation in exec mode to prevent TOCTOU collisions
- fix(tng): remove redundant error log in server cert verifier
- build: bump rtnetlink from 0.17 to 0.21
- fix(testsuite): set failed flag on unit test failure
- test(access-log): update access log format test expectations
- docs: add OHTTP HPKE Auth mode breaking change to version compatibility
- fix(tng): preserve error chains in anyhow wrapping and tracing logs
- docs: add default branch convention to CLAUDE.md
- test(ohttp): add HPKE Auth Mode integration tests
- feat(tng): use client public key for OHTTP Auth mode decapsulation on egress
- feat(tng): use client private key for OHTTP Auth mode encapsulation
- build(tng): bump ohttp/bhttp to git reference at 7d45814
- refactor(access-log): add clone_for_multiplexing for egress inner loop
- build: remove cdylib crate-type from tng lib
- fix(testsuite): resolve tng binary path in TngInstance (external/bin)
- fix(access-log): require upstream local_addr to propagate established log
- test(ingress-hook): refactor test to proper client-server architecture
- refactor: extract show_banner() to deduplicate startup banner
- fix(access-log): suppress duplicate Drop logs during state transitions
- fix: allow access_log and ohttp security types to compile under wasm
- fix: remove cfg guards from *AccessMode::Netfilter to fix cross-platform build
- fix(tng-hook): use tracing_subscriber registry init to fix log output
- feat(tng): add LD_PRELOAD ingress hook with connect() interception
- refactor(access-log): replace monolithic AccessLog enum with RAII state machine
- test(hook): restrict hook_single_port_intercept to on-bin mode only
- fix(rpm): correct libtng_hook.so install path in RPM spec
- build(docker,binary): include libtng_hook.so in Docker images and binary releases
- fix(test): discover test names from Cargo.toml instead of file basenames
- build(rpm): add libtng_hook.so LD_PRELOAD hook to package
- docs(tng-hook): add Chinese and English README
- feat(tng): add LD_PRELOAD-based egress hook for transparent port interception
- fix(serf): replace removed join_serf_cluster with retry_join_peer in join_peers
- chore(testsuite): skip js_sdk_http and restore hardcoded on-source-code features
- test(serf): add sleep before membership verification in deferred join test
- chore: bump memberlist to 0.8.5 and serf to 0.5.2 from crates.io
- feat(egress): retry peer_shared Serf cluster join with exponential backoff
- test(rats-cert): evaluate bundled rego templates through the OPA engine
- docs: document hardware_only as the default attestation policy
- test(tng): update PolicyConfig references and default-policy assertions
- feat(rats-cert): add HardwareOnly and TrustAll to PolicyConfig (default)
- feat(rats-cert): add hardware_only and trust_all rego policy templates
- docs: fix 77 broken links across all markdown documentation
- docs(scenarios): export 05-vllm-ohttp-cluster diagrams to SVG
- docs(scenarios): reorganize scenario docs into numbered subdirectories with diagrams
- feat(ohttp): add split-brain cross-node key query tests and tracing
- fix(testsuite): update comment to match ForegroundContinue mode in ohttp test
- fix(ohttp): skip self-originated queries in serf watcher to avoid spurious deadline logs
- refactor(ohttp): improve tracing logs with explicit spans and key details
- chore(deps): switch memberlist crates to merged upstream al8n/memberlist
- refactor(testsuite): replace [tag] log prefix with tracing span instrumentation
- refactor(testsuite): restore 2D semantics for ShellMode
- fix(testsuite): fix output tag prefix for tasks with overridden node type
- chore: improve test runner and add integration test guidelines
- fix(scripts/bench.sh): fix shellcheck warnings SC2034 and SC2086
- test(tng-testsuite): document why second TcpClient is disabled in mapping_multi_rule
- fix(tng): include full error chain in ErrorResponse message
- fix(tng): default rats_tls.multiplex to false to match documented behavior
- test(tng-testsuite): rename header_passthrough test target to match basename
- fix(tng-testsuite): fix header_passthrough integration tests
- test(tng): add header_passthrough deserialization unit test
- style(tng-testsuite): fmt import formatting in header_passthrough tests
- test(tng): add OHTTP header passthrough integration tests
- docs: remove header_passthrough from version_compatibility tables
- docs: document header_passthrough config field
- style(tng): fmt ordering imports in tunnel.rs
- feat(tng): copy passthrough response headers to outer OHTTP response
- feat(tng): copy passthrough request headers to outer OHTTP POST
- feat(tng): propagate header_passthrough config through Egress chain
- feat(tng): propagate header_passthrough config through Ingress chain
- test(tng): cover header_passthrough in config serialize test
- feat(tng): add EgressHeaderPassthroughConfig to OHttpArgs
- feat(tng): add IngressHeaderPassthroughConfig to OHttpArgs
- fix(test): fix integration test network topology for mapping tests
- test(tng-testsuite): add integration tests for mapping port range and multi-rule
- refactor(ingress): replace channel+spawn with select_all for multi-listener
- fix(ingress): expand port ranges in MappingIngress to match egress
- docs: update mapping configuration docs for multi-rule and port range support
- test(config): add validation tests for mapping multi-rule and port range
- refactor(egress): change AcceptedStream.dst to Arc<TngEndpoint> and implement multi-listener mapping
- feat(tng): change AcceptedStream.dst to Arc<TngEndpoint> and add multi-listener MappingIngress
- feat(config): update EgressMappingArgs to use rules with dual-mode serde
- feat(config): update IngressMappingArgs to use rules with dual-mode serde
- feat(config): add MappingRule and RuleEndpoint types with dual-mode deserialization
- docs: add pasta workaround note for netfilter mode in containers without CAP_NET_ADMIN
- chore: fix cargo fmt and update CLAUDE.md with pre-commit and testing rules
- fix(test): use HttpClientWithReverseProxy and no_ra for port_end test
- test(tng-testsuite): add integration test for http_proxy port_end
- docs: add port_end field to EndpointFilter documentation
- feat(tng): support port range matching in EndpointMatcher
- feat(tng): add port_end field to EndpointFilter for port range matching
- feat(tng): add StatusProvider trait and unified /status/ REST API
- fix(ci): convert newline-separated tags to space-separated in push job
- ci: remove test dependency from push job to allow GHCR publish even if tests fail
- feat(setup-vendor-config): add --internal flag for VPC endpoint access
- feat: add Ubuntu 24.04 as alternative Docker base image with parallel CI
- refactor: separate setup-vendor-config docs and add CI tests
- feat: add setup-vendor-config tool for builtin AS PCCS configuration
- fix(tng): clamp min sleep interval in MaybeCached to prevent busy-wait on past expire timestamps
- refactor(egress): improve timestamp error specificity and sub-second precision
- fix: add missing assertion in background_check_allows_as_addr test
- fix: remove duplicated #[test] attribute in ra.rs
- feat: add skip_as_token_cert_verify option to CoCo verifier
- fix(tng): fix peer-shared key manager rotation and split-brain convergence
- docs: add clarifying comments for tagged_spawn and wasm span instrumentation
- docs: remove CI failure notes from CLAUDE.md
- fix(tng-testsuite): allow trailing comma in run_test! macro
- fix: propagate task span to axum request handlers and runtime shutdown
- fix(tng-testsuite): propagate tracing span to all task spawns
- fix(tng): propagate tracing span to all internal spawned tasks
- fix(tng-testsuite): propagate task tags to tng internal spawns, always include IP
- fix(tng-testsuite): add per-task tracing span for on-source-code mode
- fix(tng-testsuite): improve logging — English strings, NodeType display, per-task tags
- chore(testsuite): remove old flat test files after moving to subdirectories
- chore(testsuite): organize integration tests into functional subdirectories
- refactor(ohttp): extract call_api helper to eliminate duplication
- refactor(testsuite): simplify ShellTask API with ShellMode enum
- test(testsuite): add structured logging with test context and boundaries
- docs(scenarios): add vLLM P/D separation scenario with NIXL/UCX KV cache encryption
- ref(config): rename Builtin AS 'policy' to 'attestation_policy' with default
- docs: redesign README + restructure configuration docs
- docs: add vLLM OHTTP cluster scenario documentation
- chore(docker): install jq for custom shell script
- test(peer_shared): implement comprehensive unit and integration tests
- fix(maybe_cached, key_manager): format SystemTime for wasm compatibility
- docs: add peer_shared key sharing protocol documentation
- fix: resolve clippy lints (type_complexity, manual_next_back, map_entry, useless_conversion)
- feat(maybe_cached): relax expire timestamp validation to allow slightly outdated timestamps
- docs(key_manager): add comment explaining intentional lack of locking for concurrent queries
- refactor(key_manager): return generated public key from generate_pending_key_if_none
- refactor: migrate tracing logs to structured fields and rename public_key_data to public_key
- fix(key-watcher): only trigger key rotation when pending keys activate
- feat(key-manager): implement cluster-wide key query fallback
- fix(serf): only consider alive members for master election
- refactor(serf): simplify task lifecycle management
- fix: use Weak reference for serf in background tasks to enable graceful shutdown
- fix(serf): increase message size limit and compress key encoding to support larger ClusterKeySet
- refactor(cluster-key-set): use unified HashMap with status tag
- refactor(egress): change peer_shared implementation with ClusterKeySet
- refactor(key-manager): change get_client_visible_keys to return single KeyInfo
- refactor(ohttp): remove callback-based key change notification
- refactor(ohttp)!: remove backward compatibility for unspecified key_config_hint
- feat(peer_shared): implement ClusterKeySet and serf_message for serf protocol
- refactor(key_manager): add Pending key status and extract KeyInfo factory methods
- ci(test): update codecov-action to v7
- fix(ci): exclude Windows cross-build from Linux binary step
- refactor(python): make httpx/requests/openai optional dependencies, harden OpenAI tests
- ci(python): add Windows x86_64 target, sync version, consolidate CI steps
- fix(ci): skip E2E tests on cross-compiled aarch64 Linux
- fix(ci): fix wheel install glob pattern
- fix(ci): install protobuf-compiler for rats-cert build
- fix(ci): use correct Rust version (1.89.0) in build-python-sdk workflow
- fix(ci): rename workflows for clarity (Build Python SDK, Build WASM SDK)
- feat(python): create new Python SDK with high-level API and subprocess TNG binary management
- fix(ci): fix Get binary path step to use direct path instead of file detection
- fix(ci): install mingw-w64 for Windows cross-build
- feat: add Windows x86_64-pc-windows-gnu cross-build support
- fix(peer_shared): rename test to snake_case to fix clippy
- test(peer_shared): add 23 unit and integration tests for key manager serf module
- feat(memberlist): switch to inclavare-containers fork with QUIC datagram transport
- feat: exclude access_log from wasm builds
- feat(rustls): replace SingleCertAndKey with DynamicCertResolver for attestation freshness
- docs: update peer_shared documentation to reflect QUIC transport
- chore(deps): upgrade serf to 0.5.1 and adapt join() API
- feat(tests): add cleanup_stale_resources() to BridgeNetwork
- refactor: replace NetTransport with QuicTransport for serf gossip encryption
- fix(test-dep-aa): use dedicated config to disable CDH in ASR
- feat: add inclavare-containers community ASR compatibility
- chore(deps): update hyper to inclavare fork with backpressure fix
- fix: use matching port range on server side for ingress port_range test
- fix: mark cgroup integration tests as ignored for CI environments
- fix: move test module to end of file to satisfy clippy items_after_test_module
- test: add missing unit and integration tests for netfilter port range
- test: add cgroup integration tests for netfilter
- refactor(rats-tls): consolidate shared rustls config into utils/rustls/
- fix(rats-tls): call verity_pending_cert in create_stream_raw and bundle verifier into config
- docs: add pre-commit check for boolean rename correctness, update CI notes
- fix(ci): apply cargo fmt to egress rats_tls/mod.rs
- fix(rats-tls): correct inverted if/else branches in egress ALPN dispatch
- refactor(rats-tls): rename raw_tls/is_direct_mode to multiplex
- fix(ci): add clang to test job dependencies
- fix(build): pin wasm-pack to v0.14.0 to avoid cargo-platform MSRV bump
- fix(ci): remove unused import and fix cargo fmt
- Revert "perf(rats-tls): increase H2 flow control windows from 64KB to 16MB"
- chore(wrapping): downgrade H2 lifecycle logs from info to debug
- fix(socket): remove TCP_USER_TIMEOUT to prevent premature connection teardown
- chore(wrapping): add debug logging for H2 CONNECT lifecycle
- fix(stream): preserve error context in ContextualStream using anyhow::context
- breaking(config): change rats_tls.multiplex default from true to false
- refactor(runtime): move standalone runtime creation into TrustedStreamManager::new
- build: set CC=clang in .cargo/config.toml to fix aws-lc-sys compilation
- perf(rats-cert): switch rustls-webpki from ring to aws-lc-rs for native targets
- perf(rustls): support target-specific crypto provider (aws-lc-rs for native, ring for wasm)
- perf(rustls): switch crypto provider from ring to aws-lc-rs for AVX512/VAES optimization
- perf(forward): add vectored I/O support and increase buffer to 512KB
- perf(rats-tls): fix H2 client window size and add ContextualStream wrap
- feat(stream): add ContextualStream wrapper to tag IO errors with source
- perf(rats-tls): increase H2 flow control windows from 64KB to 16MB
- refactor(bench): add TNG_MULTIPLEX env var to bench script, rename ALPN to rats-tls
- docs: add rats_tls configuration documentation and enforce mutual exclusivity
- feat(config): decouple raw-TLS from no_ra, add rats_tls.multiplex option
- fix(bench): remove duplicate stunnel test and structure configs before loop
- perf(rats-tls): add raw-TLS mode to bypass HTTP/2 CONNECT tunneling
- test(bench): add multi-round iperf3 with median reporting
- perf(ingress): remove redundant SetResponseHeaderLayer from HTTP proxy
- perf(egress): remove TraceLayer and SetResponseHeaderLayer from HTTP/2 server
- perf(metric): batch counter updates and cache KeyValue attributes
- perf(socket): enable TCP_NODELAY on outbound tcp_connect
- perf(forward): increase bidirectional copy buffer from 32KB to 256KB
- fix(egress): clarify timeout error message as first byte read timeout
- fix(ingress): clarify stream forwarding error message
- feat(netfilter): add port_end support for port range capture
- feat(forward): improve error handling with directional ForwardError enum
- feat(access-log): unify ingress/egress log format with connection metadata and mode indicator
- feat(tests): pre-compile test binaries before running tests
- docs: fix egress netfilter traffic direction description in examples
- fix: cargo fmt adjustment for iptables.rs
- docs: update egress netfilter documentation for array-based capture_dst
- feat(egress-netfilter): add cgroup support and multi-match capture_dst
- fix(tests): align test summary output and show failed unit test names
- test: Ignore test_e2e_asr_flow due to ASR/AA version incompatibility
- build: Revert to yum-installed AA with cargo run for ASR
- fix: Use system OpenSSL and correct ASR feature flag for AA+ASR build
- build: Serialize AA and ASR startup with build-first approach
- build: Run AA from guest-components source to match ASR version
- ci: Ignore spurious llvm-cov mismatched data warning in test runner
- ci: Add ASR to test dependency
- docs: Sync Chinese documentation with English version
- fix(tests): update SLSA test to use rv-release-manifest and document test deps
- fix(build): use rv-release-tool instead of removed slsa-generator
- feat(builtin-as): add rv-release-manifest support for RVPS
- feat(rats-cert): add DSSE payload verification and real JWT unit tests
- fix(rats-cert): address code review issues in transparency verification
- docs: clarify transparency context (untrusted provider-hosted TEE)
- feat(rats-cert): remove signer transparency support from builtin AS
- docs: add verify_signer_transparency config option documentation
- feat(rats-cert,tng): add opt-in signer transparency verification for COCO AS JWT
- style: Fix format
- style: Format ASR
- test: Add ASR-focused tests
- feat: Add ASR evidence fetching support
- fix: Allow ITA GPU evidence check in no-nonce flow
- fix: Allow empty runtime data in ITA
- test: Add E2E tests for ITA
- fix: Improve policy matching check in ITAVerifier
- test: Add more ITA unit tests
- fix: Check ITA API key env in passport flow
- fix: Use wasm-compatible sleep in retry and add tests
- fix: Replace again with custom retry in ITA for wasm
- feat: Add ITA provider support
- docs: document known build environment limitations for pre-commit checks
- chore(deps): update openssl to 0.10.78 to fix CVE vulnerabilities

* Wed Apr 22 2026 Kun Lai <laikun@linux.alibaba.com> - 2.6.0-1
- build(rpm): add libtng_hook.so LD_PRELOAD hook library to RPM package
- fix(build): use --locked flag for cargo install commands
- Revert "fix(build): update nightly toolchain from 2025-07-07 to 2025-12-01"
- refactor: improve error messages for hyper serve_connection call sites
- fix(build): update nightly toolchain from 2025-07-07 to 2025-12-01
- docs: add CLAUDE.md with project development guidelines
- Fix fmt, clippy, wasm build failures
- Update as_addr extraction in tng wasm fetch
- Move custom deserialization level in config parsing
- Remove coco.rs as it is renamed to ra.rs
- Add provider wire format compat test
- Update docs for multi-provider feat
- Remove ambigious provider type accessors
- Change evidence/token backcompat approach
- Refactor evidence wire format and cert verifier/config
- Refactor multi-provider layer
- ohttp: Fix unexpected unreachable panic in ChunkWriter flush handling
- refactor(error): remove redundant source placeholders from error messages
- Add multi-provider layer
- feat(ohttp): add error logging for OHTTP server request failures
- test(coco): update integration tests to use concrete converter/verifier types
- ohttp: Fix intermittent Aead(Error) caused by truncated varint-encoded chunk length
- refactor(ra): remove VerifyContext::Builtin variant and simplify converter instantiation
- refactor(tunnel): convert RaArgs to Arc<RaContext> at entry points
- refactor(config): restructure builtin provider with explicit type tags
- fix(ci): use nohup with output redirection to prevent Broken pipe in background services
- fix(Makefile): consolidate test-dep-as into a single shell to prevent zombie crane process
- refactor(ohttp): use AttestContext from ra_context instead of constructing RA components directly
- ci(clippy): add missing build dependencies
- docs: add rv_name field documentation for ReferenceValueListItem
- fix(makefile): remove --all-features from clippy to fix compilation errors
- ci: improve trustee service startup reliability in GitHub Actions
- docs: add Builtin mode documentation to English configuration guide
- fix(build): fix RPM and container build issues
- build: preserve uncommitted changes when creating source tarball
- fix(test): align SLSA test configurations with Makefile test environment
- refactor(rats-cert): replace custom TeeType/AaTeeType with kbs_types::Tee
- refactor(rats-cert): restructure error types with thiserror and source chains
- feat(builtin-as): refactor reference value configuration to use typed payload structures
- feat: add builtin attestation service (AS) support for local evidence verification

* Thu Mar 19 2026 Kun Lai <laikun@linux.alibaba.com> - 2.5.0-1
- ci: add GitHub Release notes generation with robust tag detection
- ci: upgrade GitHub Actions to v6/v8 for Node.js 24 compatibility
- build(makefile): add automated version bump targets
- chore: unify dependency versions and migrate to workspace-level management
- feat: migrate rats-cert into workspace with SGX/TDX features removed
- docs(configuration): fix typo in field name from r#in to in
- fix(verifier): fix missing headers when fetching JWT verification certs in Passport mode
- refactor(verifier): handle AS certificate fetch errors gracefully and validate HTTP status
- ohttp(peer_shared): add support for peers_file in peer_shared key mode
- feat(ohttp, utils): add robust file watcher with close-write detection for key reload
- feat(attestation): enable multi-submod EAR verification and additional evidence support
- ci: add reproducible build and SLSA provenance support for RPM build workflow
- docs: add missing attest, verify, and no_ra fields to peer_shared mode configuration
- fix(rpm): specify AnolisOS 23.3 release version in Dockerfile

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
