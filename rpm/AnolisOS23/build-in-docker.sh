#!/bin/bash
# build-in-docker.sh

# Exit on any error
set -euxo pipefail

# Function to print status messages
print_status() {
    echo "==== $1 ===="
}

# Parse command line arguments
TARBALL="$1"
if [[ -z "$TARBALL" ]]; then
  echo "Usage: $0 <rpmbuild-tarball.tar.gz>"
  exit 1
fi

# Set up RPM build environment
print_status "Setting up RPM build environment"
rpmdev-setuptree

# Prepare build artifacts
print_status "Preparing build artifacts"

tar -xzf "/input/$TARBALL" -C /tmp/

# copy SOURCES and SPECS
cp -r /tmp/SOURCES/* ~/rpmbuild/SOURCES/
cp -r /tmp/SPECS/*   ~/rpmbuild/SPECS/

# Prepare rust-1.91.0 toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain none
source $HOME/.cargo/env

# Build RPM packages
print_status "Building RPM packages"

# Install  BuildRequires dependencies
dnf builddep -y --skip-unavailable ~/rpmbuild/SPECS/trusted-network-gateway.spec

# Build RPM packages using only the artifacts we downloaded
rpmbuild -ba ~/rpmbuild/SPECS/trusted-network-gateway.spec --define 'with_rustup 1'

# Create output directory and move build artifacts
print_status "Moving build artifacts to /output"
mkdir -p /output/SRPMS /output/RPMS
cp -r ~/rpmbuild/SRPMS/* /output/SRPMS/
cp -r ~/rpmbuild/RPMS/* /output/RPMS/

print_status "RPM build completed successfully"
