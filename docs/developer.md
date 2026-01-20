# Developer Guide

This guide is intended for developers who need to modify the TNG source code or debug/run integration tests locally. It introduces the project structure and how to set up a source code development environment for TNG from scratch.

## Project Structure Overview

- **tng/**: Core service implementation, including command-line entry, configuration parsing, tunnel (Ingress/Egress), remote attestation, observability, and other main logic.
- **tng-testsuite/**: Integration test suite, providing orchestratable "scenario tasks" covering typical usage such as HTTP proxy, transparent proxy, Socks5, and unidirectional/bidirectional remote attestation.
- **tng-wasm/**: Browser-side JavaScript SDK, providing interfaces like `tng_fetch`, used in conjunction with OHTTP and remote attestation. For specific usage, see `tng-wasm/README.md`.
- **docs/**: User and development documentation, including the configuration manual (`configuration.md`) and this developer guide.
- **rpm/**: RPM packaging scripts and Dockerfiles used for building distribution packages.

If you only want to compile and run TNG locally, you can focus on the `tng/` directory. If you need to debug a complete end-to-end scenario (e.g., "HTTP proxy + unidirectional remote attestation"), it is recommended to prioritize running the corresponding `tng-testsuite` case for reproduction.

## Minimum Supported Rust Version (MSRV)

This project requires two versions of the Rust toolchain:

- `1.89.0`: This is the minimum supported Rust version required to build TNG binaries or RPM packages (whether from source or the released source tarball).
- `nightly-2025-07-07`: This is the Rust toolchain required for the following scenarios:
    - Building the TNG JavaScript SDK. For details, see [tng-wasm/README.md](../tng-wasm/README.md).
    - Creating the source code tarball using the `make create-tarball` command. This is because some of our crate dependencies require a newer Rust toolchain to resolve.

## Setting Up the Development Environment

## Obtaining the Source Code

To avoid dependency differences, we recommend using Docker to set up the development environment and compile TNG. The following steps will introduce the complete process:

1. Docker Environment Preparation

```sh
docker run -it --name tng-dev --privileged --network=host registry.openanolis.cn/openanolis/anolisos:23 bash
```
The above command will create a container named tng-dev based on the Anolis23 distribution, which will serve as the development environment for TNG. We will continue with the subsequent steps inside this container.

If you accidentally exit the container, use the following commands to re-enter:
```sh
docker start tng-dev
docker exec -it tng-dev bash
```

2. Clone the Source Code

```sh
cd /
git clone https://github.com/inclavare-containers/tng.git --branch <tag-name>
cd tng
```
Now, you have the TNG repository source code in the `/tng` directory.

## Compiling Components

### tng Compilation

1. Switch to the tng directory

```sh
cd /tng
```

2. Install Rust

```sh
cat <<EOF >> ~/.bashrc
export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
EOF

. ~/.bashrc

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

mkdir -p ~/.cargo/
cat <<EOF > ~/.cargo/config.toml
[source.crates-io]
replace-with = 'ustc'

[source.ustc]
registry = "git://mirrors.ustc.edu.cn/crates.io-index"
EOF

. "$HOME/.cargo/env"

```

3. Compile and Install tng
```sh
cargo install --locked --path ./tng/ --root /usr/local/
```

Now, you can directly use the `tng` command to start a TNG instance.

## Packaging RPM from the Development Environment

Generally, we recommend using the automated build process triggered by git, as described in [build-rpm.yml](/.github/workflows/build-rpm.yml), to package. If you have temporary packaging needs during development, you can use the following process.

1. Install Packaging Dependencies

```sh
apt install chrpath
```

2. Build RPM Package

```sh
cat <<EOF > /tmp/trusted-network-gateway.spec
%global debug_package %{nil}

Name: trusted-network-gateway
Version: 1.0.0
Release: 1
Summary: Trusted Network Gateway
Group: Applications/System
License: ASL 2.0
URL: www.alibaba.com

Requires: curl iptables openssl

ExclusiveArch: x86_64

%description
A tool for establishing secure communication tunnels in confidential computing.

%install
mkdir -p %{buildroot}/usr/bin/
install -p -m 755 /usr/local/bin/tng %{buildroot}/usr/bin/tng

%files
/usr/bin/tng
EOF

rpmbuild -ba /tmp/trusted-network-gateway.spec
```

The output will be located in the `~/rpmbuild/RPMS/x86_64/` directory. Please copy it to the target environment.

2. On the target environment, install the RPM package

First, uninstall the old version of TNG

```sh
yum remove trusted-network-gateway -y
```
Then, install the new version
```sh
yum install -y <path-to-rpm-package-on-target-environment>
```

Now, you can directly use the `tng` command to start a TNG instance.

## Running Tests

Some tests depend on attestation-agent and attestation-service instances. The following steps will introduce how to set them up.

In this repository, integration tests are mainly concentrated in the `tng-testsuite` crate, covering common scenarios through different test files, such as:

- **`tcp_two_way_ra.rs`**: Verifies TCP scenarios where both the client and server have remote attestation enabled (mutual RA).
- **`http_encapulation_with_ingress_httpproxy.rs`**: Verifies encrypted HTTP scenarios where the client accesses via HTTP proxy and the server uses netfilter.
- **`js_sdk_http.rs`**: Verifies scenarios using the browser-side JavaScript SDK (`tng-wasm`) with OHTTP and remote attestation.

### Running attestation-agent

1. Obtain the latest attestation-agent RPM package from [here](https://github.com/inclavare-containers/guest-components/releases) and install it using yum.

> [!TIP]
> If you are using the Alibaba Cloud Linux distribution, you can directly install our provided version from the yum repository:
> ```sh
> yum install -y attestation-agent
> ```

2. Run

```sh
RUST_LOG=debug attestation-agent --attestation_sock unix:///run/confidential-containers/attestation-agent/attestation-agent.sock
```

This will run an attestation-agent instance and create a ttrpc listener at `/run/confidential-containers/attestation-agent/attestation-agent.sock`.

### Running attestation-service

1. Obtain the latest trustee RPM package from [here](https://github.com/openanolis/trustee/releases) and install it using yum.

> [!TIP]
> If you are using the Alibaba Cloud Linux distribution, you can directly install our provided version from the yum repository:
> ```sh
> yum install -y trustee
> ```

2. Prepare Certificates

```sh
openssl ecparam -genkey -name prime256v1 -out /tmp/as-ca.key
openssl req -x509 -sha256 -nodes -days 365 -key /tmp/as-ca.key -out /tmp/as-ca.pem -subj "/O=Trustee CA" \
      -addext keyUsage=critical,cRLSign,keyCertSign,digitalSignature
openssl ecparam -genkey -name prime256v1 -out /tmp/as.key
openssl req -new -key /tmp/as.key -out /tmp/as.csr -subj "/CN=Trustee/O=Trustee CA"
openssl x509 -req -in /tmp/as.csr -CA /tmp/as-ca.pem -CAkey /tmp/as-ca.key -CAcreateserial -out /tmp/as.pem -days 365 -extensions v3_req -extfile <(echo -e "[v3_req]\nsubjectKeyIdentifier = hash") -sha256

cat /tmp/as.pem /tmp/as-ca.pem > /tmp/as-full.pem

cat config.json | jq '.attestation_token_broker.signer.cert_path="/tmp/as-full.pem" | .attestation_token_broker.signer.key_path="/tmp/as.key" | .rvps_config={"type":"BuiltIn","storage":{"type":"LocalFs"}}' > config_with_cert.json
```

3. Configure Debug Policy (Optional)

If you want to skip strict Attestation checks during development or testing, you can configure a default-allow OPA policy. **Note: This should absolutely not be used in production.**

```sh
mkdir -p /opt/trustee/attestation-service/policies/opa
cat <<EOF > /opt/trustee/attestation-service/policies/opa/default.rego
package policy

default executables := 3
default hardware := 2
default configuration := 2
default file_system := 2
EOF
```

4. Run

```sh
RUST_LOG=debug restful-as --socket 0.0.0.0:8080 --config-file /trustee/attestation-service/config_with_cert.json
```

This will run an attestation-service instance and create an HTTP RESTful listener at `0.0.0.0:8080`.

### Run TNG Tests

1. Install Dependencies

```sh
apt-get update && apt-get install -y curl iptables && update-alternatives --set iptables /usr/sbin/iptables-nft
```

2. Run Tests

```sh
make run-test
```

## Build and Deployment

TNG has two common running forms: it can be deployed as a container image or by building an RPM package. The following recommended build process is suitable for release or installation in a target environment.

### Build and Deploy TNG as a Container Image

1. Pull the Code

```sh
git clone git@github.com:inclavare-containers/tng.git --branch <tag-name>
cd tng
git submodule update --init
```

2. Build with Docker

This will completely recompile TNG and its dependencies from source:

```sh
docker build -t tng:latest --target release -f Dockerfile .
```

3. Run TNG as a Container

```sh
docker run -it --rm --privileged --network host --cgroupns=host tng:latest tng launch --config-content='<your config json string>'
```

### Build and Deploy TNG as an RPM Package

The following steps describe how to build an RPM package from source and install it in a target environment (applicable to distributions using yum as a package manager).

1. Pull the Code

```sh
git clone git@github.com:inclavare-containers/tng.git --branch <tag-name>
cd tng
git submodule update --init
```

2. Install Dependencies

Please install the [Rust toolchain](https://rustup.rs/) and Docker (or Podman) first.

3. Create the source tarball required for RPM building

```sh
make create-tarball
```

4. Build the RPM Package

You can choose to build the RPM package in a fresh Anolis8 distribution Docker container. This RPM package is compatible with both [Anolis8](https://openanolis.cn/anolisos) and [ALinux3](https://help.aliyun.com/zh/alinux/product-overview/alibaba-cloud-linux-overview) distributions:

```sh
make rpm-build-in-docker
```

Alternatively, you can build directly in your current distribution environment:

```sh
make rpm-build
```

The build artifacts will be located in the `~/rpmbuild/RPMS/x86_64/` directory.

5. Install the RPM Package

```sh
rpm -ivh ~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm
```

After installation, you can directly use the `tng` command to start a TNG instance.
