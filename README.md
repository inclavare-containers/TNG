# TNG

[![Docker](/../../actions/workflows/build-docker.yml/badge.svg)](/../../actions/workflows/build-docker.yml)
[![RPM](/../../actions/workflows/build-rpm.yml/badge.svg)](/../../actions/workflows/build-rpm.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![rust version](https://img.shields.io/badge/rustc-1.75+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![codecov](https://codecov.io/gh/inclavare-containers/TNG/graph/badge.svg?token=7CUZW26SH6)](https://codecov.io/gh/inclavare-containers/TNG)

[中文文档](README_zh.md)

## What is TNG?

TNG (Trusted Network Gateway) is a tool for establishing secure communication tunnels, supporting various inbound and outbound traffic methods. It also provides secure session capabilities based on remote attestation (Remote Attestation). By configuring different ingress (Ingress) and egress (Egress) endpoints, users can flexibly control the encryption and decryption of traffic without modifying existing applications.

## Usage

The main part of TNG is the `launch` subcommand. Here is the usage:

```txt
Usage: tng launch [OPTIONS]

Options:
  -c, --config-file <CONFIG_FILE>
      --config-content <CONFIG_CONTENT>
  -h, --help                             Print help
```

You have to provide a JSON config file, or provide configuration content in JSON directly from the command line arguments, which will be used to configure the TNG instance.

The simplest way to launch a TNG instance is using our pre-built Docker image:

```sh
docker run -it --rm --privileged --network host --cgroupns=host ghcr.io/inclavare-containers/tng:latest tng launch --config-content='<your config json string>'
```

Check the [reference document](docs/configuration.md) for the configuration. 

## Build

TNG has two common deployment forms: you can deploy and run TNG as a container, or you can build and deploy TNG as an RPM package. If you need to modify and compile TNG, please refer to the [developer documentation](docs/developer.md).

### Build and run as a container image

It is recommended to build TNG using Docker. Here are the steps:

1. Clone the code

```sh
git clone git@github.com:inclavare-containers/tng.git --branch <tag-name>
cd tng
git submodule update --init
```

2. Build with Docker

This will completely recompile TNG and its dependencies from the source code.

```sh
docker build -t tng:latest --target release -f Dockerfile .
```

Now we have got the Docker image `tng:latest`, which you can directly deploy and run.

3. Run TNG as a container

```sh
docker run -it --rm --privileged --network host --cgroupns=host tng:latest tng launch --config-content='<your config json string>'
```

### Build and run as an RPM package

This section describes how to build an RPM package from the source code and install it. This is only applicable to distributions that use yum as the package manager.

1. Clone the code

```sh
git clone git@github.com:inclavare-containers/tng.git --branch <tag-name>
cd tng
git submodule update --init
```

2. Install the Rust toolchain and Docker (or Podman)

3. Create the source tarball required for RPM building

```sh
make create-tarball
```

4. Build the RPM package

You can choose to build the RPM package in a fresh Anolis8 Docker container, which is compatible with both [Anolis8](https://openanolis.cn/anolisos) and [ALinux3](https://help.aliyun.com/zh/alinux/product-overview/alibaba-cloud-linux-overview) distributions.

```sh
make rpm-build-in-docker
```

Or, you can build the RPM package directly in your current distribution environment:

```sh
make rpm-build
```

The build artifacts will be located in the `~/rpmbuild/RPMS/x86_64/` directory.

5. Install the RPM package

First, uninstall the old version of TNG:

```sh
yum remove trusted-network-gateway -y
```

Then, install the new version:

```sh
yum install -y <path-to-rpm-package-on-target-environment>
```

Now, you can directly use the `tng` command to start a TNG instance.

## Example

You can get some examples from the [integration test cases](./tests/).

## Minimal Supported Rust Version (MSRV)

There are two versions of Rust toolchain required by this project:

- `1.75.0`: This is the minimal supported Rust version for building TNG binary or RPM package (from the source code or the released source code tar ball).
- `nightly-2025-07-07`: This is the requiestd Rust toolchain for:
    - Build the TNG Javascript SDK. See [./tng-wasm/README_zh.md](./tng-wasm/README_zh.md) for details.
    - Create the source code tar ball with `make create-tarball` command. That is because Some of our crate dependencies require a newer Rust toolchain to resolve.


## Contribution

We welcome community contributions to make TNG a better tool for confidential computing scenarios! If you have any questions or suggestions, feel free to submit an Issue or Pull Request.

## License

Apache-2.0
