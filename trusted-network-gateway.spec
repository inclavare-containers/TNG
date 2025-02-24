%global debug_package %{nil}

Name: trusted-network-gateway
Version: 1.0.4
Release: 1%{?dist}
Summary: Trusted Network Gateway
Group: Applications/System
License: ASL 2.0
URL: www.alibaba.com
Source0: https://github.com/inclavare-containers/tng/archive/refs/tags/%{name}-%{version}.tar.gz
Source1: config

Requires: curl iptables openssl
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
# Add cargo source replacement configs
mkdir -p ~/.cargo/
cp %{SOURCE1} ~/.cargo/config


%build
ln -s `realpath %{_builddir}/%{name}-%{version}/vendor` ~/vendor
# Build tng
pushd src/
cargo install --locked --path . --root %{_builddir}/%{name}-%{version}/install/tng/
strip %{_builddir}/%{name}-%{version}/install/tng/bin/tng
popd
# Remove vendor
rm -f ~/vendor


%install
# Install tng
mkdir -p %{buildroot}/usr/bin/
install -p -m 755 %{_builddir}/%{name}-%{version}/install/tng/bin/tng %{buildroot}/usr/bin/tng


%define __requires_exclude librats_rs.so

%files
%license src/LICENSE
/usr/bin/tng

%changelog
* Mon Feb 24 2025 Kun Lai <laikun@linux.alibaba.com> - 1.0.4
- Nothing but some adjust on build script

* Wed Jan 22 2025 Kun Lai <laikun@linux.alibaba.com> - 1.0.3-2
- Rename package name from tng to trusted-network-gateway.

* Tue Dec 17 2024 Kun Lai <laikun@linux.alibaba.com> - 1.0.3-1
- Initial package release.
