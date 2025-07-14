# Developer Guide

This guide will introduce the composition of this project and how to set up a source code development environment for TNG from scratch.

## Project Composition

The TNG source code consists of two parts: this repository, and another component, [rats-rs](https://github.com/inclavare-containers/rats-rs).

To better track the version dependencies between each TNG version and the other component, we use [git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules) to manage dependencies, making [rats-rs](https://github.com/inclavare-containers/rats-rs) a submodule of this project repository, as shown in the following diagram:

You can view the current commit ID of the submodule in this repository using the following command:

```sh
git submodule
```

Example output:
```txt
[root@0180caefdbb9 tng]# git submodule
 8f4e6e5f421c96b4840367085dc20c7519e5e425 deps/rats-rs (master)
```

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
git submodule update --init
```
Now, you have the TNG repository source code in the `/tng` directory.

The directory `deps/rats-rs` contains the source code of rats-rs as a submodule. You can directly modify it as if it were a regular git repository.

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

### Compile and Run attestation-agent

1. Clone the Code

```sh
cd /
git clone https://github.com/inclavare-containers/guest-components.git
```

2. Compile

```sh
cd guest-components/attestation-agent
make ATTESTER=none ttrpc=true
```

Here, we will build an attestation-agent that can generate fake evidence materials, which is convenient for testing in a development environment without TEE hardware.

3. Install

```sh
make install
```

4. Run

```sh
RUST_LOG=debug attestation-agent --attestation_sock unix:///run/confidential-containers/attestation-agent/attestation-agent.sock
```

This will run an attestation-agent instance and create a ttrpc listener at `/run/confidential-containers/attestation-agent/attestation-agent.sock`.

### Compile and Run attestation-service

1. Install Dependencies

```sh
# Update apt sources
KUBIC_REPO_URL="https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable/xUbuntu_20.04"
echo "deb ${KUBIC_REPO_URL} /" \
    | tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
curl -fsSL "${KUBIC_REPO_URL}/Release.key" \
    | gpg --dearmor \
    | tee /etc/apt/trusted.gpg.d/devel_kubic_libcontainers_stable.gpg \
            > /dev/null

# Install dependencies
apt update && apt install -y gcc perl wget make gnupg openssl curl protobuf-compiler git clang libtss2-dev libudev-dev pkg-config && \
    curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install -y libsgx-dcap-default-qpl libsgx-dcap-quote-verify libsgx-dcap-quote-verify-dev
```

2. Clone the Code

```sh
cd /
git clone https://github.com/openanolis/trustee.git
```

3. Compile and Install

```sh
cd trustee/attestation-service
cargo install --path . --bin restful-as --features restful-bin --locked
```

4. Prepare Certificates

```sh
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout /tmp/as-ca.key -out /tmp/as-ca.pem -nodes -subj "/O=Trustee CA" \
      -addext keyUsage=critical,cRLSign,keyCertSign,digitalSignature
openssl genrsa -out /tmp/as.key 2048
openssl req -new -key /tmp/as.key -out /tmp/as.csr -subj "/CN=Trustee/O=Trustee CA"
openssl x509 -req -in /tmp/as.csr -CA /tmp/as-ca.pem -CAkey /tmp/as-ca.key -CAcreateserial -out /tmp/as.pem -days 365 -extensions v3_req -extfile <(echo -e "[v3_req]\nsubjectKeyIdentifier = hash") -sha256

cat config.json | jq '.attestation_token_config.signer.cert_path="/tmp/as.pem" | .attestation_token_config.signer.key_path="/tmp/as.key"' > config_with_cert.json
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
