FROM alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest AS builder

# replace mirrors
RUN sed -i -E 's|https?://mirrors.cloud.aliyuncs.com/|https://mirrors.aliyun.com/|g' /etc/yum.repos.d/*.repo

# install build dependencies
RUN yum install -y git protobuf-devel gcc

# install remaining build dependencies
RUN yum install -y curl clang perl openssl-devel tpm2-tss tpm2-tss-devel

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path --default-toolchain none

WORKDIR /code/

COPY rust-toolchain.toml .

# install toolchain and cache it
RUN . "$HOME/.cargo/env" && rustup show

COPY . .

RUN . "$HOME/.cargo/env" && env RUSTFLAGS="--cfg tokio_unstable" cargo install --locked --features 'builtin-as-tdx-rust' --path ./tng/ --root /usr/local/cargo/

# Build libtng_hook.so (LD_PRELOAD hook for tng exec)
RUN . "$HOME/.cargo/env" && cargo build --release -p tng-hook-cdylib


FROM alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest AS release

# replace mirrors
RUN sed -i -E 's|https?://mirrors.cloud.aliyuncs.com/|https://mirrors.aliyun.com/|g' /etc/yum.repos.d/*.repo

RUN yum install -y curl iptables iproute && yum clean all
# install remaining runtime dependencies
RUN yum install -y tpm2-tss tpm2-tss-devel curl openssl
RUN yum reinstall -y ca-certificates

COPY --from=builder /usr/local/cargo/bin/tng /usr/local/bin/tng

# Install libtng_hook.so (LD_PRELOAD hook for tng exec transparent port interception)
RUN mkdir -p /usr/lib/tng/
COPY --from=builder /code/target/release/libtng_hook.so /usr/lib/tng/libtng_hook.so

RUN yum install -y jq

CMD ["tng"]
