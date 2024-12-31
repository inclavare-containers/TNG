%global debug_package %{nil}

Name: tng
Version: 1.0.3
Release: 1%{?dist}
Summary: TEE Network Gateway
Group: Applications/System
License: Alibaba
URL: www.alibaba.com
Requires: curl iptables openssl
Provides: librats_rs.so()(64bit)
Recommends: Attestation-Agent

Source0: https://github.com/inclavare-containers/tng/archive/refs/tags/%{name}-%{version}.tar.gz

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
BuildRequires: patchelf

ExclusiveArch: x86_64


%description
A tool for establishing secure communication tunnels in confidential computing.


%prep
%setup -q -n %{name}-%{version}
# Add cargo source replacement configs
mkdir -p ~/.cargo/
cat > ~/.cargo/config <<EOF
[source.crates-io]
replace-with = "vendored-sources"
[source."git+https://github.com/intel/SGXDataCenterAttestationPrimitives?tag=DCAP_1.20"]
git = "https://github.com/intel/SGXDataCenterAttestationPrimitives"
tag = "DCAP_1.20"
replace-with = "vendored-sources"
[source."git+https://github.com/occlum/occlum?tag=v0.29.7"]
git = "https://github.com/occlum/occlum"
tag = "v0.29.7"
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "%{_builddir}/%{name}-%{version}/vendor"
EOF


%build
# Build rats-rs
pushd %{_builddir}/%{name}-%{version}/src/deps/rats-rs
cmake -Hc-api -Bbuild -DCOCO_ONLY=ON
make -Cbuild install DESTDIR=%{_builddir}/%{name}-%{version}/install/rats-rs/
popd
# Build tng
pushd %{_builddir}/%{name}-%{version}/src/
cargo install --path . --root %{_builddir}/%{name}-%{version}/install/tng/
strip %{_builddir}/%{name}-%{version}/install/tng/bin/tng
popd
# Patch tng-envoy
patchelf --set-rpath '$ORIGIN' %{_builddir}/%{name}-%{version}/overlay/usr/local/bin/envoy-static


%install
# Install rats-rs
mkdir -p %{buildroot}/usr/local/lib/tng/
install -p -m 644 %{_builddir}/%{name}-%{version}/install/rats-rs/usr/local/lib/rats-rs/librats_rs.so %{buildroot}/usr/local/lib/tng/
# Install tng
mkdir -p %{buildroot}/usr/local/bin/
install -p -m 755 %{_builddir}/%{name}-%{version}/install/tng/bin/tng %{buildroot}/usr/local/bin/tng
# Install tng-envoy
install -p -m 755 %{_builddir}/%{name}-%{version}/overlay/usr/local/bin/envoy-static %{buildroot}/usr/local/lib/tng/envoy-static


%clean
rm -f ~/.cargo/config
rm -rf %{buildroot}

%files
/usr/local/bin/tng
/usr/local/lib/tng/envoy-static
/usr/local/lib/tng/librats_rs.so


%changelog
* Tue Dec 17 2024 Kun Lai <laikun@linux.alibaba.com> - 1.0.3-1
- Initial package release.
