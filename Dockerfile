#
# rats-rs
#
FROM ubuntu:20.04 as rats-rs-builder

ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
ENV DEBIAN_FRONTEND noninteractive

ENV SGX_SDK_VERSION 2.23
ENV SGX_SDK_RELEASE_NUMBER 2.23.100.2
ENV SGX_DCAP_VERSION 1.20

# install some necessary packages
RUN apt-get update && apt-get install -y make git vim clang-format gcc \
        pkg-config protobuf-compiler debhelper cmake \
        wget net-tools curl file gnupg tree libcurl4-openssl-dev \
        libbinutils libseccomp-dev libssl-dev binutils-dev libprotoc-dev libprotobuf-dev \
        clang jq

# install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
ENV PATH         /root/.cargo/bin:$PATH

# install tools for code-coverage
RUN rustup component add llvm-tools-preview

# install "just"
RUN cargo install just

# add repository to package manager
RUN echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | tee /etc/apt/sources.list.d/intel-sgx.list && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -


FROM rats-rs-builder as rats-rs-builder-c-api-coco-only

WORKDIR /root/rats-rs
COPY ./deps/rats-rs/. .

# build headers and librarys (with CoCo attester and CoCo verifier only)
RUN just prepare-repo && \
    cmake -Hc-api -Bbuild -DCOCO_ONLY=ON && make -Cbuild install

# build cert-app for testing
RUN cd ./examples/cert-app/ && \
    cmake -H. -Bbuild && \
    make -Cbuild all

#
# tng-envoy
#
FROM envoyproxy/envoy-build-ubuntu:26c6bcc3af3d6ad166c42b550de672d40209bc1c as tng-envoy-builder

ENV DEBIAN_FRONTEND noninteractive

# Copy rats-rs products as dependency
COPY --from=rats-rs:builder-c-api /usr/local/include/rats-rs /usr/local/include/rats-rs
COPY --from=rats-rs:builder-c-api /usr/local/lib/rats-rs/ /usr/local/lib/rats-rs/

# prepare envoy source code
RUN useradd -m -s /bin/bash newuser
WORKDIR /home/newuser/envoy
COPY ./deps/tng-envoy/. .
RUN chown -R newuser:newuser .
USER newuser

# build envoy
RUN bazel/setup_clang.sh /opt/llvm/
RUN echo "build --config=clang" >> user.bazelrc
RUN bazel build -c opt envoy
RUN chmod 0777 bazel-bin/source/exe/envoy-static && \
    strip bazel-bin/source/exe/envoy-static


#
# tng
#
FROM rust:bullseye as tng-builder

RUN apt update && apt install -y musl-tools

WORKDIR /root/tng/
COPY ./rust-toolchain.toml .
RUN rustup target add x86_64-unknown-linux-musl

COPY --exclude=./deps/rats-rs/ --exclude=./deps/tng-envoy/ . .

RUN cargo install --path . --target=x86_64-unknown-linux-musl

RUN strip /usr/local/cargo/bin/tng

FROM tng-envoy:latest as release

RUN apt-get update && apt-get install -y curl iptables && rm -rf /var/lib/apt/lists/* && update-alternatives --set iptables /usr/sbin/iptables-nft

COPY --from=tng-builder /usr/local/cargo/bin/tng /usr/local/bin/tng

CMD ["tng"]
