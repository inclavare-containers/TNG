%global debug_package %{nil}

Name: trusted-network-gateway
Version: 2.2.1
Release: 1%{?dist}
Summary: Trusted Network Gateway
Group: Applications/System
License: ASL 2.0
URL: www.alibaba.com
Source0: https://github.com/inclavare-containers/tng/releases/download/v{version}/trusted-network-gateway-%{version}.tar.gz

Requires: curl iptables openssl iproute
Recommends: attestation-agent

BuildRequires: make
BuildRequires: git
BuildRequires: gcc
BuildRequires: pkg-config
BuildRequires: protobuf-compiler
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
BuildRequires: cargo
BuildRequires: rust

ExclusiveArch: x86_64


%description
A tool for establishing secure communication tunnels in confidential computing.


%prep
%setup -q -n %{name}-%{version}


%build
# Build tng
pushd src/
cargo install --locked --path . --root %{_builddir}/%{name}-%{version}/install/tng/
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
