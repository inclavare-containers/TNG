%global debug_package %{nil}

Name: trusted-network-gateway
Version: 1.0.3
Release: 2%{?dist}
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
BuildRequires: chrpath

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
# Build rats-rs
pushd src/deps/rats-rs
cmake -Hc-api -Bbuild -DCOCO_ONLY=ON
make -Cbuild install DESTDIR=%{_builddir}/%{name}-%{version}/install/rats-rs/
popd
# Build tng
pushd src/
cargo install --locked --path . --root %{_builddir}/%{name}-%{version}/install/tng/
strip %{_builddir}/%{name}-%{version}/install/tng/bin/tng
popd
# Patch tng-envoy
chrpath --replace '$ORIGIN' %{_builddir}/%{name}-%{version}/overlay/usr/local/bin/envoy-static
# Remove vendor
rm -f ~/vendor


%install
# Install rats-rs
mkdir -p %{buildroot}/usr/lib64/tng/
install -p -m 644 %{_builddir}/%{name}-%{version}/install/rats-rs/usr/local/lib/rats-rs/librats_rs.so %{buildroot}/usr/lib64/tng/
# Install tng
mkdir -p %{buildroot}/usr/bin/
install -p -m 755 %{_builddir}/%{name}-%{version}/install/tng/bin/tng %{buildroot}/usr/bin/tng
# Install tng-envoy
install -p -m 755 %{_builddir}/%{name}-%{version}/overlay/usr/local/bin/envoy-static %{buildroot}/usr/lib64/tng/envoy-static


%define __requires_exclude librats_rs.so

%files
%license src/LICENSE
/usr/bin/tng
/usr/lib64/tng/envoy-static
/usr/lib64/tng/librats_rs.so


%changelog
* Wed Jan 22 2025 Kun Lai <laikun@linux.alibaba.com> - 1.0.3-2
- Rename package name from tng to trusted-network-gateway.

* Tue Dec 17 2024 Kun Lai <laikun@linux.alibaba.com> - 1.0.3-1
- Initial package release.
